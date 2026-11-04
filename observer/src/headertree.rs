use common::tokio::time::Instant;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use common::{
    anyhow::{Context, Result},
    bitcoin::{
        BlockHash, BlockHeader as Header, CompactTarget,
        blockdata::{block::HeaderExt, constants::genesis_block},
        consensus::encode::{deserialize, serialize},
        pow::{CompactTargetExt, Target, Work},
    },
    tokio::time::{Duration, interval},
    tracing,
};

use crate::TARGET_HEADERTREE as TARGET;

/// Minimum gap between two rounds of requests for the same missing block.
///
/// A new block reaches us from every connection within a second or two, and
/// when the tree is behind every one of those announcements is an orphan. A
/// few getheaders are enough to catch up; one per connection would be a
/// hundred replies of up to two thousand headers each, all saying the same
/// thing.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(10);

/// Connections asked about the same missing block within one interval.
///
/// One is not enough: the peer that announced first may never answer, or
/// answer with headers of another chain, and waiting out the interval on it
/// would cost a block interval of being behind. Three is what Bitcoin Core
/// settled on for block downloads, for the same reason.
const RECOVERY_PEERS: u8 = 3;

/// Headers the tree has rejected that it keeps the reason for.
///
/// A rejected header's descendants are rejected for the same reason without
/// being asked for: another chain on this network's magic announces a block
/// every few minutes from hundreds of peers, and without this every one of
/// those was an orphan the tree asked three peers to explain, and the reply
/// -- two thousand headers off a fork below the checkpoint -- was rejected
/// and forgotten in time for the next block. Bounded because the hashes come
/// from peers; at a few hundred a day this is weeks of such a chain.
///
/// Least recently used, not arrival order. A refusal something has just
/// inherited from goes to the back, because the root of a refused branch is
/// the entry every header on that branch is recognised by, and in arrival
/// order it is the first to be forgotten. That cost nothing while the branch
/// was a chain -- each header inherits from its parent, refused a moment ago
/// -- and it cost the classification of a peer that sent this many *direct
/// children* of one refused header: once the root was gone they read as
/// headers with no parent, which is a tree that is behind rather than a peer
/// on another chain. See `test_the_refusals_the_tree_remembers_are_bounded`.
const REJECTED_REMEMBERED: usize = 8192;

/// How much easier than our own tip's target an unplaceable header's target
/// may be before the chain it belongs to is read as weaker than ours.
///
/// A retarget can legitimately ease the target fourfold, which is the most a
/// peer a little ahead of us can show, so anything inside that is left as an
/// ordinary orphan. The fork this exists for is three orders of magnitude
/// easier: on mainnet its blocks have sixteen leading zero digits where the
/// chain has nineteen to twenty-one.
///
/// Only consulted on networks that do not allow minimum-difficulty blocks.
/// On testnet an honest header really can be difficulty 1, and nothing can be
/// told from its target at all.
///
/// The comparison is against our own tip, so it assumes the tip is roughly
/// current, which the header sync at startup and the recovery requests after
/// it are there to keep true. A tree left many retarget periods behind would
/// be comparing against a difficulty the network has moved away from -- and
/// one still at genesis simply never finds anything weaker, since nothing is
/// easier than difficulty 1, so a fresh observer under-detects rather than
/// dropping honest peers.
const WEAKER_CHAIN_FACTOR: f64 = 4.0;

/// The requests out for one block the tree does not have.
struct Recovery {
    started: Instant,
    requests: u8,
}

const HEADER_SIZE: usize = 80;

/// A block hash the chain must have at a height.
///
/// One per network is built in, at a recent height, and the config can add
/// more. A header at that height with another hash is rejected, and once the
/// tree holds a checkpoint block nothing new is accepted below it: the tree is
/// contiguous, so a new header down there can only be a fork. That keeps out
/// what proof of work alone cannot: a branch off the early chain, where
/// difficulty 1 is valid and two thousand headers cost nothing to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    pub(crate) height: u32,
    pub(crate) hash: BlockHash,
}

/// The built-in checkpoint of a network: one recent block, verified against
/// two sources when it was added. Networks without one get none.
pub(crate) fn builtin_checkpoints(network: common::bitcoin::Network) -> Vec<Checkpoint> {
    use common::bitcoin::{Network, network::TestnetVersion};
    let (height, hash) = match network {
        Network::Bitcoin => (
            970_000,
            "000000000000000000014e6a9bad5f954f266cfb3e8f63f8c2fb7967f29b5a07",
        ),
        Network::Signet => (
            320_000,
            "0000000740ae66b284da84387dcfa14d7b1385b0bad482005ba4e770ea6c4b95",
        ),
        Network::Testnet(TestnetVersion::V4) => (
            150_000,
            "0000000000d9877342754dea8ec1eb24631517d38e3443c370465ee53a8b7434",
        ),
        Network::Testnet(TestnetVersion::V3) => (
            5_200_000,
            "0000000000e79b4cd86775e9455066e392952f35cf16b702e07312cd33424dd2",
        ),
        _ => return Vec::new(),
    };
    vec![Checkpoint {
        height,
        hash: hash.parse().expect("built-in checkpoint hash"),
    }]
}

/// Built-in and configured checkpoints together, sorted by height. A
/// configured one replaces a built-in one at the same height, so the config
/// can correct as well as extend.
pub(crate) fn merge_checkpoints(
    builtin: Vec<Checkpoint>,
    configured: Vec<Checkpoint>,
) -> Vec<Checkpoint> {
    let mut by_height: BTreeMap<u32, Checkpoint> =
        builtin.into_iter().map(|c| (c.height, c)).collect();
    for c in configured {
        by_height.insert(c.height, c);
    }
    by_height.into_values().collect()
}

struct HeaderEntry {
    header: Header,
    height: u32,
    chain_work: Work,
}

pub struct HeaderTree {
    headers: HashMap<BlockHash, HeaderEntry>,
    /// best_chain[height] = block hash on the current best chain.
    best_chain: Vec<BlockHash>,
    tip: BlockHash,
    tip_height: u32,
    tip_work: Work,
    params: common::bitcoin::network::Params,
    dirty: bool,
    /// Sorted by height.
    checkpoints: Vec<Checkpoint>,
    /// Height of the highest checkpoint whose block the tree holds. Nothing
    /// new is accepted at or below it.
    reached_checkpoint: Option<u32>,
    /// Headers removed below a reached checkpoint since the tree was made.
    pruned: usize,
    /// Blocks announced but absent from the tree, with the requests sent for
    /// each. Per block, so a peer that never answers for one block does not
    /// hold up the next; shared across connections, which is what makes it a
    /// throttle rather than a per-peer courtesy.
    recovery: HashMap<BlockHash, Recovery>,
    /// Headers rejected by validation, or descended from one that was, with
    /// why and the sequence number that orders them. See
    /// [`REJECTED_REMEMBERED`].
    rejected: HashMap<BlockHash, (HeaderError, u64)>,
    /// The refusals in the order they will be forgotten, oldest first. One
    /// entry per refusal, so exactly as long as `rejected` is.
    rejected_order: BTreeMap<u64, BlockHash>,
    /// Hands out the next sequence number.
    rejected_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    OrphanHeader,
    /// The parent is unknown and the header's own target is far easier than
    /// our chain's, so whatever chain it belongs to is weaker than ours.
    WeakerChain,
    InvalidPow,
    TargetTooEasy,
    /// A header at a checkpoint height with another hash.
    CheckpointMismatch,
    /// A header at or below a checkpoint the tree has reached.
    ForkBelowCheckpoint,
}

impl HeaderError {
    /// Whether this says the peer follows a chain we will never accept,
    /// rather than that we are behind.
    ///
    /// A fork at or below a checkpoint we hold, a different block at a
    /// checkpoint height, or work that does not meet this network's rules:
    /// each means the peer built on history we have already rejected, and our
    /// own chain carries the work to that point. An orphan is the opposite --
    /// the tree is behind and the peer is ahead of it -- and a valid header on
    /// a side branch is not here at all, because the tree accepts it: a fork
    /// with less work than our tip is an ordinary race that resolves in
    /// minutes, and a peer on one is still a peer on our chain.
    pub(crate) fn is_other_chain(&self) -> bool {
        match self {
            HeaderError::OrphanHeader => false,
            HeaderError::WeakerChain
            | HeaderError::InvalidPow
            | HeaderError::TargetTooEasy
            | HeaderError::CheckpointMismatch
            | HeaderError::ForkBelowCheckpoint => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainTipStatus {
    /// The current best chain.
    Active,
    /// Headers are valid but we have not validated block bodies (SPV node).
    HeadersOnly,
}

#[derive(Debug, Clone)]
pub(crate) struct ChainTip {
    pub hash: BlockHash,
    pub height: u32,
    /// Number of headers on this branch since it forked from the active chain
    /// (0 for the active tip itself).
    pub branch_len: u32,
    pub status: ChainTipStatus,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::OrphanHeader => write!(f, "parent header not in tree"),
            HeaderError::WeakerChain => write!(f, "unplaceable header of a weaker chain"),
            HeaderError::InvalidPow => write!(f, "invalid proof of work"),
            HeaderError::TargetTooEasy => write!(f, "target exceeds maximum"),
            HeaderError::CheckpointMismatch => write!(f, "hash differs from the checkpoint"),
            HeaderError::ForkBelowCheckpoint => write!(f, "fork below a reached checkpoint"),
        }
    }
}

impl HeaderTree {
    pub fn new(params: common::bitcoin::network::Params) -> Self {
        let genesis = *genesis_block(&params).header();
        let hash = genesis.block_hash();
        let work = genesis.work();

        let mut headers = HashMap::new();
        headers.insert(
            hash,
            HeaderEntry {
                header: genesis,
                height: 0,
                chain_work: work,
            },
        );

        Self {
            headers,
            best_chain: vec![hash],
            tip: hash,
            tip_height: 0,
            tip_work: work,
            params,
            dirty: false,
            checkpoints: Vec::new(),
            reached_checkpoint: None,
            pruned: 0,
            recovery: HashMap::new(),
            rejected: HashMap::new(),
            rejected_order: BTreeMap::new(),
            rejected_seq: 0,
        }
    }

    /// A tree that enforces `checkpoints` (see [`Checkpoint`]).
    pub(crate) fn with_checkpoints(
        params: common::bitcoin::network::Params,
        mut checkpoints: Vec<Checkpoint>,
    ) -> Self {
        checkpoints.sort_by_key(|c| c.height);
        let mut tree = Self::new(params);
        tree.checkpoints = checkpoints;
        tree.note_checkpoint(tree.tip, 0);
        tree
    }

    pub(crate) fn reached_checkpoint(&self) -> Option<u32> {
        self.reached_checkpoint
    }

    /// Records that the block at `height` is a checkpoint, if it is one, and
    /// drops whatever the tree holds below it that is not on its chain.
    fn note_checkpoint(&mut self, hash: BlockHash, height: u32) {
        let is_checkpoint = self
            .checkpoints
            .iter()
            .any(|c| c.height == height && c.hash == hash);
        if !is_checkpoint || self.reached_checkpoint.is_some_and(|r| height <= r) {
            return;
        }
        self.reached_checkpoint = Some(height);
        let pruned = self.prune_below_checkpoint();
        tracing::info!(target: TARGET, height, pruned, "checkpoint reached");
    }

    /// Removes every header at or below the reached checkpoint that is not
    /// an ancestor of it, and whatever was built on those. Returns how many.
    ///
    /// Needed on top of the insert-time rule because a load inserts headers
    /// in height order: a branch off the early chain is in before the
    /// checkpoint block is, and nothing stops it until then.
    fn prune_below_checkpoint(&mut self) -> usize {
        let Some(reached) = self.reached_checkpoint else {
            return 0;
        };
        let Some(checkpoint) = self.checkpoints.iter().find(|c| c.height == reached) else {
            return 0;
        };
        let mut keep = HashSet::new();
        let mut hash = checkpoint.hash;
        while let Some(entry) = self.headers.get(&hash) {
            keep.insert(hash);
            if entry.height == 0 {
                break;
            }
            hash = entry.header.prev_blockhash;
        }
        let before = self.headers.len();
        self.headers
            .retain(|hash, entry| entry.height > reached || keep.contains(hash));
        // What was built on a pruned header would now be an orphan; walked in
        // height order so a parent is settled before its children.
        //
        // Nothing reaches this today. A branch cannot cross a checkpoint
        // height -- the header at that height is refused by hash and its
        // descendants inherit the refusal -- and `note_checkpoint` only fires
        // on the insert of the checkpoint block itself, so nothing taller is
        // in the tree when this runs. See
        // `test_a_stray_branch_stops_at_the_checkpoint_height`. It stays
        // because a header with no parent panics `chain_tips`, and this is
        // where that is prevented rather than where it is discovered.
        let mut above: Vec<(u32, BlockHash)> = self
            .headers
            .iter()
            .filter(|(_, e)| e.height > reached)
            .map(|(h, e)| (e.height, *h))
            .collect();
        above.sort_unstable();
        for (_, hash) in above {
            let parent = self.headers[&hash].header.prev_blockhash;
            if !self.headers.contains_key(&parent) {
                self.headers.remove(&hash);
            }
        }
        let pruned = before - self.headers.len();
        if pruned > 0 {
            self.pruned += pruned;
            self.dirty = true;
            if !self.headers.contains_key(&self.tip) {
                let (hash, entry) = self
                    .headers
                    .iter()
                    .max_by_key(|(_, e)| e.chain_work)
                    .expect("the checkpoint chain remains");
                self.tip = *hash;
                self.tip_height = entry.height;
                self.tip_work = entry.chain_work;
            }
            self.rebuild_best_chain();
        }
        pruned
    }

    /// Insert a single header. Returns `Ok(true)` if new, `Ok(false)` if
    /// already known.
    ///
    /// Does not rebuild the best chain: both callers insert a run of headers
    /// and rebuild once at the end, which is the only way either of them is
    /// cheap.
    fn insert_inner(&mut self, header: Header) -> std::result::Result<bool, HeaderError> {
        let hash = header.block_hash();
        if self.headers.contains_key(&hash) {
            return Ok(false);
        }

        let parent = match self.headers.get(&header.prev_blockhash) {
            Some(parent) => parent,
            // The parent is not in the tree. When that is because the tree
            // threw it out, this header goes the same way, for the same
            // reason, and nobody is asked for headers to explain it.
            None => {
                let inherited = self
                    .rejected
                    .get(&header.prev_blockhash)
                    .map(|(reason, _)| *reason);
                return Err(match inherited {
                    Some(reason) => {
                        // The parent first, so that remembering the child
                        // cannot be what forgets the parent.
                        self.touch_rejected(header.prev_blockhash);
                        self.remember_rejected(hash, reason);
                        reason
                    }
                    // Nothing says where this header sits, but its own target
                    // says how much work its chain puts into a block. Far
                    // below ours is not a chain we are behind on.
                    None if self.weaker_than_our_tip(&header) => {
                        self.remember_rejected(hash, HeaderError::WeakerChain);
                        HeaderError::WeakerChain
                    }
                    None => HeaderError::OrphanHeader,
                });
            }
        };
        let height = parent.height + 1;
        let parent_work = parent.chain_work;

        if let Err(e) = self.validate_header(&header, height, parent) {
            self.remember_rejected(hash, e);
            return Err(e);
        }

        let chain_work = parent_work + header.work();
        self.headers.insert(
            hash,
            HeaderEntry {
                header,
                height,
                chain_work,
            },
        );
        // Whatever was asked for this block has been answered.
        self.recovery.remove(&hash);
        self.note_checkpoint(hash, height);

        if chain_work > self.tip_work {
            let old_tip = self.tip;
            self.tip = hash;
            self.tip_height = height;
            self.tip_work = chain_work;

            // Check for reorg: old tip should be an ancestor of new tip
            if old_tip != header.prev_blockhash {
                tracing::warn!(target: TARGET,
                    old_tip = %old_tip,
                    new_tip = %hash,
                    height,
                    "chain reorg detected"
                );
            }
        }

        self.dirty = true;
        Ok(true)
    }

    /// Insert a batch of headers. Returns count of accepted headers and first error if any.
    pub fn insert_batch(&mut self, headers: &[Header]) -> (usize, Option<HeaderError>) {
        let old_tip = self.tip;
        let mut accepted = 0;
        let mut err = None;

        // Carries on past a rejected header rather than stopping at it, so
        // that the headers built on it in the same message are recorded as
        // rejected too. The first error is the one reported: it is the one
        // that explains the rest.
        for header in headers {
            match self.insert_inner(*header) {
                Ok(true) => accepted += 1,
                Ok(false) => {} // already known, skip
                Err(e) => err = err.or(Some(e)),
            }
        }

        // Rebuild best_chain once if tip changed
        if self.tip != old_tip {
            self.rebuild_best_chain();
        }

        (accepted, err)
    }

    fn validate_header(
        &self,
        header: &Header,
        height: u32,
        parent: &HeaderEntry,
    ) -> std::result::Result<(), HeaderError> {
        if header.target() > self.params.max_attainable_target {
            return Err(HeaderError::TargetTooEasy);
        }

        if let Some(checkpoint) = self.checkpoints.iter().find(|c| c.height == height)
            && checkpoint.hash != header.block_hash()
        {
            return Err(HeaderError::CheckpointMismatch);
        }
        // The checkpoint block and all its ancestors are already in the
        // tree, so a new header at or below it can only be a fork.
        if self
            .reached_checkpoint
            .is_some_and(|reached| height <= reached)
        {
            return Err(HeaderError::ForkBelowCheckpoint);
        }

        let expected_bits = if height.is_multiple_of(2016) && height > 0 {
            // Retarget: we need the first block of the epoch (height - 2016) to
            // compute the new difficulty. We can't use best_chain[height - 2016]
            // because on test networks deep reorgs spanning a retarget boundary
            // are realistic, meaning the fork's epoch-start block may differ from
            // the one on our best chain. Walking back via prev_blockhash always
            // gives the correct epoch-start for whichever chain this header is on.
            // We start at the parent (the last block of the epoch) and walk back
            // 2015 more steps to land on the epoch-start block (2016 behind us).
            let epoch_start = self
                .walk_back(header.prev_blockhash, 2015)
                .ok_or(HeaderError::OrphanHeader)?;
            CompactTarget::from_header_difficulty_adjustment(
                epoch_start.header,
                parent.header,
                &self.params,
            )
        } else {
            parent.header.bits
        };

        header
            .validate_pow(Target::from(expected_bits))
            .map_err(|_| HeaderError::InvalidPow)?;

        Ok(())
    }

    /// Walk back `steps` blocks from `start_hash` via prev_blockhash.
    fn walk_back(&self, start_hash: BlockHash, steps: u32) -> Option<&HeaderEntry> {
        let mut hash = start_hash;
        for _ in 0..steps {
            let entry = self.headers.get(&hash)?;
            hash = entry.header.prev_blockhash;
        }
        self.headers.get(&hash)
    }

    fn rebuild_best_chain(&mut self) {
        let mut chain = Vec::with_capacity(self.tip_height as usize + 1);
        let mut hash = self.tip;
        loop {
            chain.push(hash);
            let entry = &self.headers[&hash];
            if entry.height == 0 {
                break;
            }
            hash = entry.header.prev_blockhash;
        }
        chain.reverse();
        self.best_chain = chain;
    }

    pub fn tip(&self) -> (BlockHash, u32) {
        (self.tip, self.tip_height)
    }

    /// The height of a header the tree holds.
    pub(crate) fn height_of(&self, hash: &BlockHash) -> Option<u32> {
        self.headers.get(hash).map(|e| e.height)
    }

    /// Why the tree rejected a header, if it did and still remembers.
    pub(crate) fn rejection_of(&self, hash: &BlockHash) -> Option<HeaderError> {
        self.rejected.get(hash).map(|(reason, _)| *reason)
    }

    /// Whether an unplaceable header's own target is so much easier than our
    /// tip's that its chain cannot be the one we are behind on.
    ///
    /// The header's target is the one thing it carries that can be read
    /// without its parent: it is what that chain's own retarget rules asked
    /// of this block. See [`WEAKER_CHAIN_FACTOR`].
    fn weaker_than_our_tip(&self, header: &Header) -> bool {
        if self.params.allow_min_difficulty_blocks {
            return false;
        }
        let Some(tip) = self.headers.get(&self.tip) else {
            return false;
        };
        let ours = tip.header.target().difficulty_float(&self.params);
        let theirs = header.target().difficulty_float(&self.params);
        theirs * WEAKER_CHAIN_FACTOR < ours
    }

    /// Whether this block has reached the tree at all, accepted or rejected.
    ///
    /// What "new to us" is judged by, and the reason it is not
    /// [`Self::contains`]: a block the tree refuses is never held, so every
    /// announcement of it looked like the first. Two peers on another chain
    /// announcing the same block counted as two blocks, and on signet that
    /// turned thirty of their blocks into sixty first sightings.
    pub(crate) fn seen(&self, hash: &BlockHash) -> bool {
        self.headers.contains_key(hash) || self.rejected.contains_key(hash)
    }

    /// Remember that `hash` was refused, and why.
    ///
    /// A refusal already held keeps the place it has: this is about when we
    /// first learned of it, and learning of it twice is not news.
    fn remember_rejected(&mut self, hash: BlockHash, reason: HeaderError) {
        if self.rejected.contains_key(&hash) {
            return;
        }
        let seq = self.next_rejected_seq();
        self.rejected.insert(hash, (reason, seq));
        self.rejected_order.insert(seq, hash);
        while self.rejected.len() > REJECTED_REMEMBERED {
            let Some((&oldest, &hash)) = self.rejected_order.iter().next() else {
                break;
            };
            self.rejected_order.remove(&oldest);
            self.rejected.remove(&hash);
        }
    }

    /// Move a refusal to the back of the queue, because something has just
    /// been refused for inheriting it.
    ///
    /// The root of a refused branch is the entry every header on that branch
    /// is recognised by, which makes it the last one worth forgetting -- and
    /// in arrival order it is the first to go. A peer feeding us direct
    /// children of one refused header used to reach a cliff at
    /// [`REJECTED_REMEMBERED`] of them: the root fell out, and from then on
    /// the rest of the branch arrived as headers with no parent, which
    /// `accept_headers` reads as the tree being behind. It asked the peer for
    /// headers and stopped recording it as a peer on another chain, which for
    /// a tool whose output is what each peer is doing is the part that matters.
    ///
    /// So a refusal still being built on is a refusal still in use, and stays.
    /// Nothing grows: this moves an entry rather than adding one, and the map
    /// is capped either way.
    fn touch_rejected(&mut self, hash: BlockHash) {
        let seq = self.next_rejected_seq();
        if let Some((_, old)) = self.rejected.get_mut(&hash) {
            let previous = std::mem::replace(old, seq);
            self.rejected_order.remove(&previous);
            self.rejected_order.insert(seq, hash);
        }
    }

    fn next_rejected_seq(&mut self) -> u64 {
        self.rejected_seq = self.rejected_seq.wrapping_add(1);
        self.rejected_seq
    }

    /// Whether a connection that has just found `missing` absent from the tree
    /// should ask its peer for headers now, or leave it to the requests out.
    ///
    /// Up to [`RECOVERY_PEERS`] connections ask within one interval. `proven`
    /// says the announcement carried the header, so the peer has the block. A
    /// bare inv proves nothing -- the peer may not have validated the block
    /// yet, which is how a download stalls -- so an inv is acted on only when
    /// no request for the block is out at all.
    ///
    /// Takes the time rather than reading the clock so the throttle can be
    /// tested without waiting it out.
    pub(crate) fn recovery_due(&mut self, missing: BlockHash, proven: bool, now: Instant) -> bool {
        self.recovery
            .retain(|_, r| now.duration_since(r.started) < RECOVERY_INTERVAL);
        match self.recovery.get_mut(&missing) {
            None => {
                self.recovery.insert(
                    missing,
                    Recovery {
                        started: now,
                        requests: 1,
                    },
                );
                true
            }
            Some(r) if proven && r.requests < RECOVERY_PEERS => {
                r.requests += 1;
                true
            }
            Some(_) => false,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.headers.len()
    }

    /// Build a block locator: exponential backoff from tip.
    pub fn build_locator(&self) -> Vec<BlockHash> {
        let mut locator = Vec::new();
        let mut height = self.tip_height as i64;
        let mut step: i64 = 1;

        while height >= 0 {
            if (height as usize) < self.best_chain.len() {
                locator.push(self.best_chain[height as usize]);
            }
            if height == 0 {
                break;
            }
            height -= step;
            if height < 0 {
                height = 0;
            }
            if step < 16 {
                step += 1;
            } else {
                step *= 2;
            }
        }

        // Always include genesis if not already there
        if locator.last() != Some(&self.best_chain[0]) {
            locator.push(self.best_chain[0]);
        }

        locator
    }

    /// Respond to a getheaders request: find first locator on best chain,
    /// return up to 2000 headers from the next block.
    pub fn get_headers_from_locator(
        &self,
        locator: &[BlockHash],
        stop_hash: BlockHash,
    ) -> Vec<Header> {
        let zero_hash = BlockHash::from_byte_array([0; 32]);

        // Find the first locator hash that is on our best chain.
        let start_height = locator
            .iter()
            .find_map(|hash| {
                let entry = self.headers.get(hash)?;
                let h = entry.height as usize;
                if h < self.best_chain.len() && self.best_chain[h] == *hash {
                    Some(h + 1)
                } else {
                    None
                }
            })
            .unwrap_or(1); // If no locator matches, start after genesis.

        let end = std::cmp::min(start_height + 2000, self.best_chain.len());
        let mut headers = Vec::with_capacity(end - start_height);

        for h in start_height..end {
            let hash = self.best_chain[h];
            headers.push(self.headers[&hash].header);
            if stop_hash != zero_hash && hash == stop_hash {
                break;
            }
        }

        headers
    }

    /// Return all chain tips (analogous to Bitcoin Core's `getchaintips`).
    ///
    /// A tip is any header that is not referenced as the parent of another
    /// known header. The active tip has `branch_len = 0`; all others report
    /// how many headers since they last shared a block with the active chain.
    pub(crate) fn chain_tips(&self) -> Vec<ChainTip> {
        // Set of all hashes that are someone's parent.
        let parents: std::collections::HashSet<BlockHash> = self
            .headers
            .values()
            .filter(|e| e.height > 0)
            .map(|e| e.header.prev_blockhash)
            .collect();

        // Tips = headers whose own hash does not appear in `parents`.
        self.headers
            .iter()
            .filter(|(hash, _)| !parents.contains(*hash))
            .map(|(hash, entry)| {
                let status = if *hash == self.tip {
                    ChainTipStatus::Active
                } else {
                    ChainTipStatus::HeadersOnly
                };

                // Walk back from this tip until we hit a block on best_chain.
                let branch_len = {
                    let mut len = 0u32;
                    let mut h = entry.height as usize;
                    let mut cur = *hash;
                    loop {
                        if h < self.best_chain.len() && self.best_chain[h] == cur {
                            break;
                        }
                        let e = &self.headers[&cur];
                        cur = e.header.prev_blockhash;
                        h = h.saturating_sub(1);
                        len += 1;
                    }
                    len
                };

                ChainTip {
                    hash: *hash,
                    height: entry.height,
                    branch_len,
                    status,
                }
            })
            .collect()
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    pub(crate) fn save(&mut self, path: &Path) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }

        // Height first, so a parent is always written before its child, which
        // is what lets `load` replay the file straight back into a tree.
        //
        // Within one height, the block on the best chain first and the rest in
        // hash order. Both halves are about the reload. The tree keeps the
        // first tip it sees of a given amount of work, so writing the active
        // chain ahead of its equals is what makes it the active chain again --
        // otherwise a restart with two branches tied at the tip comes back on
        // whichever one happened to be written first. And that was the
        // iteration order of a HashMap, so it was not even the same twice: the
        // same tree saved again could come back as the other chain.
        let on_best: std::collections::HashSet<&BlockHash> = self.best_chain.iter().collect();
        let mut entries: Vec<_> = self
            .headers
            .iter()
            .map(|(hash, e)| (e.height, !on_best.contains(hash), *hash, &e.header))
            .collect();
        entries.sort_unstable_by_key(|(height, off_best, hash, _)| (*height, *off_best, *hash));

        let mut buf = Vec::with_capacity(entries.len() * HEADER_SIZE);
        for (_, _, _, header) in &entries {
            buf.extend_from_slice(&serialize(*header));
        }

        std::fs::write(path, &buf).context("write header tree")?;
        self.dirty = false;
        tracing::info!(target: TARGET,
            headers = self.headers.len(),
            tip_height = self.tip_height,
            "header tree saved"
        );
        Ok(())
    }

    pub(crate) fn load(
        path: &Path,
        params: common::bitcoin::network::Params,
        checkpoints: Vec<Checkpoint>,
    ) -> Result<Self> {
        let mut tree = Self::with_checkpoints(params.clone(), checkpoints);

        tracing::info!(target: TARGET, path=format!("{:?}", path), "loading header tree");

        match std::fs::read(path) {
            Ok(data) => {
                if data.len() % HEADER_SIZE != 0 {
                    common::anyhow::bail!(
                        "header file size {} is not a multiple of {HEADER_SIZE}",
                        data.len()
                    );
                }
                let count = data.len() / HEADER_SIZE;
                // One line per reason rather than one per header: a pruned
                // branch is thousands of them.
                let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
                for i in 0..count {
                    let offset = i * HEADER_SIZE;
                    let header: Header = deserialize(&data[offset..offset + HEADER_SIZE])
                        .context("deserialize header")?;
                    if let Err(e) = tree.insert_inner(header) {
                        *skipped.entry(e.to_string()).or_default() += 1;
                    }
                }
                for (reason, n) in &skipped {
                    tracing::warn!(target: TARGET, count = n, "skipped headers during load: {reason}");
                }
                tree.rebuild_best_chain();
                tracing::info!(target: TARGET,
                    headers = tree.headers.len(),
                    tip_height = tree.tip_height,
                    pruned = tree.pruned,
                    "header tree loaded"
                );
                // Pruned anything: the file still has it, so the next save
                // must write.
                tree.dirty = tree.pruned > 0;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(target: TARGET, "no header file found, starting fresh");
            }
            Err(e) => return Err(e).context("read header tree"),
        }

        Ok(tree)
    }
}

/// Background task: periodically saves the header tree to disk.
pub(crate) async fn persist_task(
    tree: std::sync::Arc<std::sync::RwLock<HeaderTree>>,
    path: PathBuf,
) {
    let mut timer = interval(Duration::from_secs(60));
    timer.tick().await; // skip immediate first tick

    loop {
        timer.tick().await;
        let mut tree = tree.write().unwrap();
        if let Err(e) = tree.save(&path) {
            tracing::warn!(target: TARGET, "failed to persist header tree: {e:#}");
        }
    }
}

#[cfg(any(test, feature = "bench"))]
pub mod testing {
    use super::*;
    use common::bitcoin::{Network, network::Params};

    pub fn regtest_params() -> Params {
        Params::new(Network::Regtest)
    }

    /// Mine a valid regtest header. Regtest uses bits=0x207fffff which gives a
    /// target so easy that nonce=0 always satisfies PoW. A unique `seed` byte in
    /// the merkle root lets callers produce different blocks at the same height.
    pub fn mine_header(prev_hash: BlockHash, time: u32, seed: u8) -> Header {
        use common::bitcoin::{
            CompactTarget, TxMerkleNode, blockdata::block::Version, time::BlockTime,
        };
        let bits = CompactTarget::from_consensus(0x207fffff);
        let merkle_root = TxMerkleNode::from_byte_array([seed; 32]);
        for nonce in 0..=u32::MAX {
            let h = Header {
                version: Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root,
                time: BlockTime::from(time),
                bits,
                nonce,
            };
            if h.validate_pow(h.bits.into()).is_ok() {
                return h;
            }
        }
        panic!("failed to mine regtest header — this should never happen");
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{mine_header, regtest_params};
    use super::*;
    use crate::protocol::MAX_LOCATOR_SZ;
    use bitcoind::client::bitcoin::Address;
    use testsupport::TempDir;

    // A random regtest address we can mine to.
    fn regtest_address() -> Address {
        const REGTEST_ADDR: &str = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw";
        REGTEST_ADDR
            .parse::<bitcoind::client::bitcoin::Address<_>>()
            .unwrap()
            .assume_checked()
    }

    fn regtest_tree() -> HeaderTree {
        HeaderTree::new(regtest_params())
    }

    #[test]
    fn test_new_starts_at_genesis() {
        let tree = regtest_tree();
        let (_, height) = tree.tip();
        assert_eq!(height, 0);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_locator_genesis_only() {
        let tree = regtest_tree();
        let locator = tree.build_locator();
        assert_eq!(locator.len(), 1);
        let (tip, _) = tree.tip();
        assert_eq!(locator[0], tip);
    }

    #[test]
    fn test_duplicate_insert_returns_false() {
        let mut tree = regtest_tree();
        let genesis =
            *common::bitcoin::blockdata::constants::genesis_block(regtest_params()).header();
        let (accepted, err) = tree.insert_batch(&[genesis]);
        assert_eq!(accepted, 0);
        assert!(err.is_none());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_orphan_rejected() {
        let mut tree = regtest_tree();
        let mut header =
            *common::bitcoin::blockdata::constants::genesis_block(regtest_params()).header();
        header.prev_blockhash = BlockHash::from_byte_array([0xab; 32]);
        let (_, err) = tree.insert_batch(&[header]);
        assert!(matches!(err, Some(HeaderError::OrphanHeader)));
    }

    #[test]
    fn test_recovery_requests_are_per_block_and_capped() {
        let mut tree = regtest_tree();
        let t0 = Instant::now();
        let a = BlockHash::from_byte_array([1; 32]);
        let b = BlockHash::from_byte_array([2; 32]);
        let c = BlockHash::from_byte_array([3; 32]);
        // Three connections that saw the header ask; the next hundred, within
        // the same second or two, do not.
        assert!(tree.recovery_due(a, true, t0));
        assert!(tree.recovery_due(a, true, t0));
        assert!(tree.recovery_due(a, true, t0));
        assert!(!tree.recovery_due(a, true, t0 + RECOVERY_INTERVAL / 2));
        // Another missing block is its own matter, however the first is going.
        assert!(tree.recovery_due(b, true, t0));
        // An inv proves nothing about the peer: it asks only when nobody has.
        assert!(!tree.recovery_due(a, false, t0));
        assert!(tree.recovery_due(c, false, t0));
        assert!(!tree.recovery_due(c, false, t0));
        // Once the interval has passed the block may still be missing -- a reply
        // carries at most two thousand headers -- so a new round is right.
        assert!(tree.recovery_due(a, true, t0 + RECOVERY_INTERVAL));
        assert!(!tree.recovery_due(a, false, t0 + RECOVERY_INTERVAL));
    }

    #[test]
    fn test_an_accepted_header_ends_its_recovery() {
        let mut tree = regtest_tree();
        let h1 = mine_header(tree.tip().0, 1296688602, 0);
        let t0 = Instant::now();
        assert!(tree.recovery_due(h1.block_hash(), false, t0));
        assert!(!tree.recovery_due(h1.block_hash(), false, t0));
        tree.insert_batch(&[h1]);
        // The block arrived, so nothing is out for it any more.
        assert!(!tree.recovery.contains_key(&h1.block_hash()));
    }

    #[test]
    fn test_save_load_roundtrip() {
        let mut tree = regtest_tree();
        let genesis_hash = tree.tip().0;

        // Mine chain A: 5 headers
        let mut chain_a = Vec::new();
        let mut prev = genesis_hash;
        for i in 0..5u32 {
            let h = mine_header(prev, 1296688602 + i, 0);
            chain_a.push(h);
            prev = h.block_hash();
        }
        tree.insert_batch(&chain_a);

        // Mine chain B: 7 headers (longer, causes reorg)
        let mut chain_b = Vec::new();
        prev = genesis_hash;
        for i in 0..7u32 {
            let h = mine_header(prev, 1296688602 + i, 1);
            chain_b.push(h);
            prev = h.block_hash();
        }
        tree.insert_batch(&chain_b);

        // Tree should have: genesis + 5 (chain A) + 7 (chain B) = 13 headers, tip at 7
        assert_eq!(tree.len(), 13);
        assert_eq!(tree.tip().1, 7);
        let tip_before = tree.tip().0;

        let dir = TempDir::new("headertree-roundtrip");
        let path = dir.path().join("headers.bin");

        let mut tips_before = tree.chain_tips();
        tips_before.sort_by_key(|t| t.hash);
        tree.save(&path).unwrap();

        let loaded = HeaderTree::load(&path, regtest_params(), Vec::new()).unwrap();
        let mut tips_after = loaded.chain_tips();
        tips_after.sort_by_key(|t| t.hash);

        assert_eq!(loaded.tip(), tree.tip());
        assert_eq!(loaded.tip().0, tip_before);
        assert_eq!(loaded.len(), tree.len());
        assert_eq!(loaded.len(), 13);

        // Chain tips should be preserved across save/load
        assert_eq!(tips_before.len(), tips_after.len());
        for (before, after) in tips_before.iter().zip(tips_after.iter()) {
            assert_eq!(before.hash, after.hash);
            assert_eq!(before.height, after.height);
            assert_eq!(before.branch_len, after.branch_len);
            assert_eq!(before.status, after.status);
        }

        // Both forks should be preserved
        for header in &chain_a {
            assert!(loaded.height_of(&header.block_hash()).is_some());
        }
        for header in &chain_b {
            assert!(loaded.height_of(&header.block_hash()).is_some());
        }
    }

    #[test]
    fn test_load_missing_file_starts_fresh() {
        let tree = HeaderTree::load(
            Path::new("/tmp/nonexistent-headertree-test-6336395673c0dceda7e525edb3ffbb6607e4.bin"),
            regtest_params(),
            Vec::new(),
        )
        .unwrap();

        let (hash, height) = tree.tip();
        assert_eq!(height, 0);
        assert_eq!(
            hash.to_string(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_get_headers_from_locator_empty_tree() {
        let tree = regtest_tree();
        let (genesis_hash, _) = tree.tip();
        let headers =
            tree.get_headers_from_locator(&[genesis_hash], BlockHash::from_byte_array([0; 32]));
        // No headers after genesis
        assert!(headers.is_empty());
    }

    /// Decode a hex-encoded header string from the bitcoind RPC.
    fn header_from_hex(hex: &str) -> Header {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        deserialize(&bytes).unwrap()
    }

    /// Fetch headers at heights 1..=count from a bitcoind node.
    fn fetch_headers(node: &bitcoind::Node, count: u64) -> Vec<Header> {
        use bitcoind::client::bitcoin::BlockHash as RpcBlockHash;

        let mut headers = Vec::new();
        for h in 1..=count {
            let hash_hex = &node.client.get_block_hash(h).unwrap().0;
            let block_hash: RpcBlockHash = hash_hex.parse().unwrap();
            let header_hex = &node.client.get_block_header(&block_hash).unwrap().0;
            headers.push(header_from_hex(header_hex));
        }
        headers
    }

    /// Generate blocks with a real bitcoind, fetch headers via RPC, insert into
    /// the tree, and verify tip height, locator, save/load, and getheaders response.
    #[test]
    fn test_insert_regtest_headers() {
        let exe = bitcoind::exe_path().unwrap();
        let conf = bitcoind::Conf::default();
        let node = bitcoind::Node::with_conf(exe, &conf).unwrap();

        node.client
            .generate_to_address(10, &regtest_address())
            .unwrap();

        let headers = fetch_headers(&node, 10);
        let mut tree = regtest_tree();
        let (accepted, err) = tree.insert_batch(&headers);
        assert_eq!(accepted, 10);
        assert!(err.is_none());

        assert_eq!(tree.tip().1, 10);
        assert_eq!(tree.len(), 11);

        // Locator starts at tip, ends at genesis
        let locator = tree.build_locator();
        assert_eq!(locator[0], tree.tip().0);
        assert_eq!(*locator.last().unwrap(), tree.best_chain[0]);

        // get_headers_from_locator: asking from genesis should return all 10
        let genesis_hash = tree.best_chain[0];
        let resp =
            tree.get_headers_from_locator(&[genesis_hash], BlockHash::from_byte_array([0; 32]));
        assert_eq!(resp.len(), 10);

        // get_headers_from_locator: asking from tip should return empty
        let resp =
            tree.get_headers_from_locator(&[tree.tip().0], BlockHash::from_byte_array([0; 32]));
        assert!(resp.is_empty());

        // Save and reload
        let dir = TempDir::new("headertree-regtest");
        let path = dir.path().join("headers.bin");

        tree.dirty = true;
        tree.save(&path).unwrap();

        let loaded = HeaderTree::load(&path, regtest_params(), Vec::new()).unwrap();
        assert_eq!(loaded.tip(), tree.tip());
        assert_eq!(loaded.len(), tree.len());
        assert_eq!(loaded.build_locator(), tree.build_locator());
    }

    /// Insert the same batch twice — second time should accept 0 new headers.
    #[test]
    fn test_insert_batch_dedup() {
        let exe = bitcoind::exe_path().unwrap();
        let conf = bitcoind::Conf::default();
        let node = bitcoind::Node::with_conf(exe, &conf).unwrap();

        node.client
            .generate_to_address(5, &regtest_address())
            .unwrap();

        let headers = fetch_headers(&node, 5);

        let mut tree = regtest_tree();
        let (accepted, err) = tree.insert_batch(&headers);
        assert_eq!(accepted, 5);
        assert!(err.is_none());

        let (accepted, err) = tree.insert_batch(&headers);
        assert_eq!(accepted, 0);
        assert!(err.is_none());
    }

    /// Mine a valid regtest header. Regtest uses bits=0x207fffff which gives a
    /// target so easy that nonce=0 always satisfies PoW. A unique `seed` byte in
    /// the merkle root lets callers produce different blocks at the same height.
    /// Simulate a reorg by self-mining two diverging chains without bitcoind.
    /// Chain A has 10 blocks; chain B diverges at height 1 and has 12 blocks.
    /// The tree should follow chain B after both are inserted.
    #[test]
    fn test_reorg() {
        let mut tree = regtest_tree();
        let genesis_hash = tree.tip().0;

        // Chain A: 10 headers, seed=0
        let mut chain_a = Vec::new();
        let mut prev = genesis_hash;
        for i in 0..10u32 {
            let h = mine_header(prev, 1296688602 + i, 0);
            chain_a.push(h);
            prev = h.block_hash();
        }

        // Chain B: 12 headers from same genesis, seed=1 so height-1 block differs
        let mut chain_b = Vec::new();
        prev = genesis_hash;
        for i in 0..12u32 {
            let h = mine_header(prev, 1296688602 + i, 1);
            chain_b.push(h);
            prev = h.block_hash();
        }

        // Sanity: chains diverge immediately at height 1
        assert_ne!(chain_a[0].block_hash(), chain_b[0].block_hash());

        // Insert chain A — tip at height 10
        let (accepted, err) = tree.insert_batch(&chain_a);
        assert_eq!(accepted, 10);
        assert!(err.is_none());
        assert_eq!(tree.tip().1, 10);
        let tip_a = tree.tip().0;

        // Insert chain B — all 12 are new (different chain), tip should switch to height 12
        let (accepted, err) = tree.insert_batch(&chain_b);
        assert_eq!(accepted, 12);
        assert!(err.is_none());
        assert_eq!(tree.tip().1, 12);

        // Tip changed to chain B
        let tip_b = tree.tip().0;
        assert_ne!(tip_a, tip_b);

        // best_chain should follow chain B (13 entries: genesis + 12)
        assert_eq!(tree.best_chain.len(), 13);
        assert_eq!(tree.best_chain[12], tip_b);

        // Chain A headers are still in the tree
        for header in &chain_a {
            assert!(tree.height_of(&header.block_hash()).is_some());
        }

        // Total headers: genesis + 10 (chain A) + 12 (chain B) = 23
        assert_eq!(tree.len(), 23);
    }

    /// A reorg that crosses a retarget boundary (height 2016). Both chains share
    /// 2010 blocks, then diverge. Both cross the retarget, exercising the
    /// walk_back path in validate_header. Chain B (15 blocks) beats chain A (10).
    #[test]
    fn test_reorg_across_retarget() {
        const SHARED: u32 = 2010;
        const CHAIN_A_LEN: u32 = 10; // tip at 2020
        const CHAIN_B_LEN: u32 = 15; // tip at 2025

        let mut tree = regtest_tree();

        // Build shared base
        let mut shared = Vec::new();
        let mut prev = tree.tip().0;
        for i in 0..SHARED {
            let h = mine_header(prev, 1296688602 + i, 0);
            shared.push(h);
            prev = h.block_hash();
        }
        let (accepted, err) = tree.insert_batch(&shared);
        assert_eq!(accepted, SHARED as usize);
        assert!(err.is_none());

        let fork_point = prev;

        // Chain A: 10 blocks crossing retarget at 2016, seed=0
        let mut chain_a = Vec::new();
        prev = fork_point;
        for i in 0..CHAIN_A_LEN {
            let h = mine_header(prev, 1296688602 + SHARED + i, 0);
            chain_a.push(h);
            prev = h.block_hash();
        }
        let (accepted, err) = tree.insert_batch(&chain_a);
        assert_eq!(accepted, CHAIN_A_LEN as usize);
        assert!(err.is_none());
        assert_eq!(tree.tip().1, SHARED + CHAIN_A_LEN);

        // Chain B: 15 blocks crossing retarget at 2016, seed=1
        let mut chain_b = Vec::new();
        prev = fork_point;
        for i in 0..CHAIN_B_LEN {
            let h = mine_header(prev, 1296688602 + SHARED + i, 1);
            chain_b.push(h);
            prev = h.block_hash();
        }
        let (accepted, err) = tree.insert_batch(&chain_b);
        assert_eq!(accepted, CHAIN_B_LEN as usize);
        assert!(err.is_none());

        // Chain B wins
        assert_eq!(tree.tip().1, SHARED + CHAIN_B_LEN);
        assert_eq!(tree.tip().0, chain_b.last().unwrap().block_hash());

        // Both fork branches are in the tree
        assert_eq!(
            tree.len(),
            1 + SHARED as usize + CHAIN_A_LEN as usize + CHAIN_B_LEN as usize
        );

        // Two tips: chain A (stale) and chain B (active)
        let mut tips = tree.chain_tips();
        tips.sort_by_key(|t| t.height);
        assert_eq!(tips.len(), 2);

        let stale = &tips[0];
        assert_eq!(stale.height, SHARED + CHAIN_A_LEN);
        assert_eq!(stale.branch_len, CHAIN_A_LEN);
        assert_eq!(stale.status, ChainTipStatus::HeadersOnly);

        let active = &tips[1];
        assert_eq!(active.height, SHARED + CHAIN_B_LEN);
        assert_eq!(active.branch_len, 0);
        assert_eq!(active.status, ChainTipStatus::Active);
    }

    #[test]
    fn test_chain_tips() {
        let mut tree = regtest_tree();
        let genesis_hash = tree.tip().0;

        // Only genesis: one tip, active, branch_len=0
        let tips = tree.chain_tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].hash, genesis_hash);
        assert_eq!(tips[0].branch_len, 0);
        assert_eq!(tips[0].status, ChainTipStatus::Active);

        // Mine chain A (10 blocks) and chain B (12 blocks) from genesis
        let mut chain_a = Vec::new();
        let mut prev = genesis_hash;
        for i in 0..10u32 {
            let h = mine_header(prev, 1296688602 + i, 0);
            chain_a.push(h);
            prev = h.block_hash();
        }
        let mut chain_b = Vec::new();
        prev = genesis_hash;
        for i in 0..12u32 {
            let h = mine_header(prev, 1296688602 + i, 1);
            chain_b.push(h);
            prev = h.block_hash();
        }

        tree.insert_batch(&chain_a);
        tree.insert_batch(&chain_b);

        // Two tips: chain A (stale) and chain B (active)
        let mut tips = tree.chain_tips();
        tips.sort_by_key(|t| t.height);

        assert_eq!(tips.len(), 2);

        let stale = &tips[0];
        assert_eq!(stale.hash, chain_a.last().unwrap().block_hash());
        assert_eq!(stale.height, 10);
        assert_eq!(stale.branch_len, 10); // all 10 blocks are off the active chain
        assert_eq!(stale.status, ChainTipStatus::HeadersOnly);

        let active = &tips[1];
        assert_eq!(active.hash, chain_b.last().unwrap().block_hash());
        assert_eq!(active.height, 12);
        assert_eq!(active.branch_len, 0);
        assert_eq!(active.status, ChainTipStatus::Active);
    }

    /// Sync 4321 headers from Node A, then serve them to Node B. Both
    /// connections use real Connection instances sharing a single HeaderTree.
    #[tokio::test]
    async fn test_sync_and_serve_headers() {
        use crate::addresses;
        use crate::addresses::peer_addr::PeerAddr;
        use crate::connection;
        use crate::protocol;
        use common::p2p::Magic;
        use common::tokio::sync::mpsc;
        use std::sync::{Arc, RwLock};

        const TOTAL: usize = 4321;

        let exe = bitcoind::exe_path().unwrap();

        let header_tree = Arc::new(RwLock::new(regtest_tree()));
        let (event_tx, _) = mpsc::channel(1024);
        // Only the handle is needed: nothing in this test dials through the
        // manager, and the lifecycle reports go nowhere.
        let (addrman, _gossip_rx, _life_rx, _cmd_rx) = addresses::channels();

        let make_cfg = |sync_headers: bool| protocol::Config {
            connections: crate::connections::Registry::new(),
            magic: Magic::REGTEST,
            ping_interval: common::tokio::time::Duration::from_secs(120),
            user_agent: protocol::USER_AGENT.to_owned(),
            event_tx: event_tx.clone(),
            header_tree: header_tree.clone(),
            sync_headers,
            probe_compact_blocks: false,
            networks: crate::settings::NetworksConfig::default(),
        };

        let make_addr = |port: u16| PeerAddr::Ipv4([127, 0, 0, 1], port);

        let node_conf = |p2p| {
            let mut conf = bitcoind::Conf::default();
            conf.p2p = p2p;
            conf.args.push("-nowallet");
            conf
        };

        // Node A: generate blocks
        let node_a = bitcoind::Node::with_conf(&exe, &node_conf(bitcoind::P2P::Yes)).unwrap();

        println!("generating {TOTAL} blocks on node A...");
        node_a
            .client
            .generate_to_address(TOTAL, &regtest_address())
            .unwrap();
        println!(
            "node A at height {}",
            node_a.client.get_blockchain_info().unwrap().headers
        );

        // Sync from Node A
        println!("syncing headers from node A...");
        let port_a = node_a.params.p2p_socket.unwrap().port();
        connection::bootstrap_attempt(make_addr(port_a), &make_cfg(true), &addrman)
            .await
            .unwrap();
        println!("tree at height {}", header_tree.read().unwrap().tip().1);
        assert_eq!(header_tree.read().unwrap().tip().1, TOTAL as u32);

        // Node B: serve headers to it
        let node_b = bitcoind::Node::with_conf(&exe, &node_conf(bitcoind::P2P::Yes)).unwrap();
        let port_b = node_b.params.p2p_socket.unwrap().port();
        println!("serving headers to node B...");
        let serve_cfg = make_cfg(false);
        let serve_addrman = addrman.clone();
        let handle = common::tokio::spawn(async move {
            let _ =
                connection::bootstrap_attempt(make_addr(port_b), &serve_cfg, &serve_addrman).await;
        });

        // Wait for Node B to sync
        loop {
            common::tokio::time::sleep(common::tokio::time::Duration::from_millis(200)).await;
            let headers = node_b.client.get_blockchain_info().unwrap().headers;
            println!("node B headers: {headers}");
            if headers >= TOTAL as i64 {
                break;
            }
        }
        handle.abort();

        let tips_a = node_a.client.get_chain_tips().unwrap().0;
        let tips_b = node_b.client.get_chain_tips().unwrap().0;
        let tip_a = tips_a.iter().max_by_key(|t| t.height).unwrap();
        let tip_b = tips_b.iter().max_by_key(|t| t.height).unwrap();
        assert_eq!(tip_a.height, TOTAL as i64);
        assert_eq!(tip_b.height, TOTAL as i64);
        assert_eq!(
            tip_a.hash, tip_b.hash,
            "both nodes should have the same tip hash"
        );
        println!("both nodes at height {} tip {}", tip_b.height, tip_b.hash);
    }

    /// `n` headers on `prev`, each passing regtest proof of work.
    fn mine_chain(prev: BlockHash, n: u32, seed: u8) -> Vec<Header> {
        let mut chain = Vec::new();
        let mut prev = prev;
        for i in 0..n {
            let h = mine_header(prev, 1296688602 + i, seed);
            chain.push(h);
            prev = h.block_hash();
        }
        chain
    }

    fn checkpoint_at(chain: &[Header], height: u32) -> Checkpoint {
        Checkpoint {
            height,
            hash: chain[height as usize - 1].block_hash(),
        }
    }

    #[test]
    fn test_checkpoint_mismatch_rejected() {
        let genesis = regtest_tree().tip().0;
        let chain_a = mine_chain(genesis, 4, 0);
        let chain_b = mine_chain(genesis, 4, 1);
        let mut tree =
            HeaderTree::with_checkpoints(regtest_params(), vec![checkpoint_at(&chain_a, 3)]);

        // Chain B is fine up to the checkpoint height, where its hash differs.
        let (accepted, err) = tree.insert_batch(&chain_b);
        assert_eq!(accepted, 2);
        assert!(
            matches!(err, Some(HeaderError::CheckpointMismatch)),
            "{err:?}"
        );
        assert_eq!(tree.reached_checkpoint(), None);

        let (accepted, err) = tree.insert_batch(&chain_a);
        assert_eq!(accepted, 4);
        assert!(err.is_none());
        assert_eq!(tree.reached_checkpoint(), Some(3));
        assert_eq!(tree.tip().1, 4);
        // Reaching the checkpoint pruned B's two headers below it.
        assert_eq!(tree.len(), 5);
        assert!(tree.height_of(&chain_b[0].block_hash()).is_none());
    }

    #[test]
    fn test_forks_only_above_a_reached_checkpoint() {
        let genesis = regtest_tree().tip().0;
        let chain_a = mine_chain(genesis, 5, 0);
        let mut tree =
            HeaderTree::with_checkpoints(regtest_params(), vec![checkpoint_at(&chain_a, 3)]);
        tree.insert_batch(&chain_a);

        // A fork off height 1 lands at height 2, below the checkpoint: rejected.
        let low = mine_header(chain_a[0].block_hash(), 1296688700, 7);
        let (_, err) = tree.insert_batch(&[low]);
        assert!(
            matches!(err, Some(HeaderError::ForkBelowCheckpoint)),
            "{err:?}"
        );
        // A fork off the checkpoint block itself lands at height 4: allowed.
        let high = mine_header(chain_a[2].block_hash(), 1296688700, 8);
        let (accepted, err) = tree.insert_batch(&[high]);
        assert_eq!((accepted, err.is_none()), (1, true));
        assert_eq!(tree.chain_tips().len(), 2);
    }

    /// An unplaceable header whose own target is far easier than our tip's
    /// belongs to a weaker chain, which is a different thing from the tree
    /// being behind. This is how the fork on mainnet is recognised: it never
    /// hands us a header we can place, only compact blocks of its own chain,
    /// and its blocks take a fraction of the work ours do.
    #[test]
    fn test_an_unplaceable_header_of_a_weaker_chain_is_not_an_orphan() {
        use common::bitcoin::{
            CompactTarget, Network, TxMerkleNode, blockdata::block::Version, network::Params,
            time::BlockTime,
        };

        // Mainnet, so the tip is the genesis block at difficulty 1 and the
        // network does not allow minimum-difficulty blocks.
        let mut tree = HeaderTree::new(Params::new(Network::Bitcoin));
        let orphan = |bits: u32, seed: u8| Header {
            version: Version::ONE,
            // A parent the tree has never seen, so nothing can place it.
            prev_blockhash: BlockHash::from_byte_array([seed; 32]),
            merkle_root: TxMerkleNode::from_byte_array([seed; 32]),
            time: BlockTime::from(1_700_000_000),
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        };

        // Same difficulty as our tip: we are simply behind, and the tree says
        // so, which is what sends a getheaders rather than ending a session.
        let (_, err) = tree.insert_batch(&[orphan(0x1d00_ffff, 1)]);
        assert_eq!(err, Some(HeaderError::OrphanHeader));
        assert!(!HeaderError::OrphanHeader.is_other_chain());

        // Sixteen times easier. No chain that costs this little per block is
        // the chain we are behind on.
        let weak = orphan(0x1e00_ffff, 2);
        let (_, err) = tree.insert_batch(&[weak]);
        assert_eq!(err, Some(HeaderError::WeakerChain));
        assert!(HeaderError::WeakerChain.is_other_chain());
        // Remembered, so the next block of that chain needs no judging of its
        // own and no peer is asked to explain it.
        assert_eq!(
            tree.rejection_of(&weak.block_hash()),
            Some(HeaderError::WeakerChain)
        );
        let child = Header {
            prev_blockhash: weak.block_hash(),
            ..orphan(0x1e00_ffff, 3)
        };
        let (_, err) = tree.insert_batch(&[child]);
        assert_eq!(err, Some(HeaderError::WeakerChain));

        // On a network where an honest header can be difficulty 1, the target
        // says nothing and the same header is only an orphan.
        let mut testnet = HeaderTree::new(Params::new(Network::Testnet(
            common::bitcoin::network::TestnetVersion::V3,
        )));
        let (_, err) = testnet.insert_batch(&[orphan(0x1e00_ffff, 2)]);
        assert_eq!(err, Some(HeaderError::OrphanHeader));
    }

    /// A header built on a rejected one is rejected for the same reason, not
    /// reported as an orphan the tree should go and ask about.
    #[test]
    fn test_descendants_of_a_rejected_header_inherit_the_reason() {
        let genesis = regtest_tree().tip().0;
        let chain_a = mine_chain(genesis, 5, 0);
        let mut tree =
            HeaderTree::with_checkpoints(regtest_params(), vec![checkpoint_at(&chain_a, 3)]);
        tree.insert_batch(&chain_a);

        // Another chain forking below the checkpoint, announced block by
        // block as its peers would, then two at once.
        let fork = mine_chain(chain_a[0].block_hash(), 4, 7);
        let (_, err) = tree.insert_batch(&fork[..1]);
        assert_eq!(err, Some(HeaderError::ForkBelowCheckpoint));
        let (_, err) = tree.insert_batch(&fork[1..2]);
        assert_eq!(err, Some(HeaderError::ForkBelowCheckpoint), "inherited");
        let (accepted, err) = tree.insert_batch(&fork[2..]);
        assert_eq!((accepted, err), (0, Some(HeaderError::ForkBelowCheckpoint)));
        for h in &fork {
            assert_eq!(
                tree.rejection_of(&h.block_hash()),
                Some(HeaderError::ForkBelowCheckpoint)
            );
            assert!(tree.height_of(&h.block_hash()).is_none());
        }

        // A header whose parent the tree has simply never seen is still an
        // orphan, and nothing is remembered about it.
        let stray = mine_header(BlockHash::from_byte_array([0xab; 32]), 1296688700, 9);
        let (_, err) = tree.insert_batch(&[stray]);
        assert_eq!(err, Some(HeaderError::OrphanHeader));
        assert_eq!(tree.rejection_of(&stray.block_hash()), None);
    }

    /// The refusals the tree remembers are bounded, it forgets the oldest
    /// first, and what that costs.
    ///
    /// Remembering a refusal is what stops the tree asking its peers to
    /// explain a header it has already thrown out, and what stops a block
    /// announced by two peers on another chain from counting as two first
    /// sightings. It is also a map a peer gets to grow: every header built on
    /// a refused one is refused for the same reason and remembered under its
    /// own hash, and none of that costs the peer more than the headers
    /// themselves. [`REJECTED_REMEMBERED`] is the whole of what keeps it from
    /// being unbounded, and nothing asked whether it works.
    #[test]
    fn test_the_refusals_the_tree_remembers_are_bounded() {
        let genesis = regtest_tree().tip().0;
        let real = mine_chain(genesis, 1, 0);
        let mut tree =
            HeaderTree::with_checkpoints(regtest_params(), vec![checkpoint_at(&real, 1)]);

        // One refusal to build on: a header at the checkpoint height with
        // another hash.
        let root = mine_header(genesis, 1296688602, 1);
        tree.insert_batch(&[root]);
        assert_eq!(
            tree.rejection_of(&root.block_hash()),
            Some(HeaderError::CheckpointMismatch)
        );

        // And more children of it than fit, each refused for the same reason
        // and remembered under its own hash.
        let children: Vec<Header> = (0..REJECTED_REMEMBERED as u32 + 64)
            .map(|i| mine_header(root.block_hash(), 1296700000 + i, 2))
            .collect();
        tree.insert_batch(&children);

        assert_eq!(
            tree.rejected.len(),
            REJECTED_REMEMBERED,
            "the refusals are not bounded"
        );
        assert_eq!(tree.rejected_order.len(), REJECTED_REMEMBERED);
        // Nothing was accepted along the way: the tree is still genesis.
        assert_eq!(tree.len(), 1);
        // The root is still here, because it is still being used: every one
        // of those children was refused by inheriting it, and each inheriting
        // moved it to the back. In arrival order it was the oldest entry in
        // the map and would have been the first forgotten -- and it is the one
        // entry every header on that branch is recognised by.
        assert_eq!(
            tree.rejection_of(&root.block_hash()),
            Some(HeaderError::CheckpointMismatch),
            "the refusal everything inherited from was forgotten"
        );
        // So is the newest child, and so the branch is still being recognised
        // at both ends.
        assert_eq!(
            tree.rejection_of(&children.last().unwrap().block_hash()),
            Some(HeaderError::CheckpointMismatch),
            "the most recent refusal was forgotten"
        );
        // What went instead: the earliest children, which nothing has
        // inherited from and nothing has asked about since.
        assert_eq!(tree.rejection_of(&children[0].block_hash()), None);

        // Which is what keeps the recognition going for as long as the peer
        // keeps sending. Before this, a peer feeding direct children of one
        // refused header hit a cliff at REJECTED_REMEMBERED of them: the root
        // fell out, and from then on the rest arrived as headers with no
        // parent, which `accept_headers` reads as the tree being behind. It
        // asked the peer for headers and stopped recording it as a peer on
        // another chain. A thousand more children, and all of them are still
        // refused for the reason the root was.
        let more: Vec<Header> = (0..1_000u32)
            .map(|i| mine_header(root.block_hash(), 1_297_000_000 + i, 4))
            .collect();
        tree.insert_batch(&more);
        for header in &more {
            assert_eq!(
                tree.rejection_of(&header.block_hash()),
                Some(HeaderError::CheckpointMismatch),
                "a child of the refused root was not refused"
            );
        }

        // And a chain off a refused header, which was never the problem: each
        // header inherits from its parent, refused a moment ago.
        let remembered = *more.last().unwrap();
        let branch = mine_chain(remembered.block_hash(), 50, 3);
        tree.insert_batch(&branch);
        for header in &branch {
            assert_eq!(
                tree.rejection_of(&header.block_hash()),
                Some(HeaderError::CheckpointMismatch),
                "a header on a refused chain was not refused"
            );
        }

        // Still bounded, and the order is still exactly as long as the map:
        // moving an entry is not adding one.
        assert_eq!(tree.rejected.len(), REJECTED_REMEMBERED, "still bounded");
        assert_eq!(tree.rejected_order.len(), REJECTED_REMEMBERED);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_forks_allowed_before_the_checkpoint_is_reached() {
        let genesis = regtest_tree().tip().0;
        let chain_a = mine_chain(genesis, 5, 0);
        let chain_b = mine_chain(genesis, 2, 1);
        let mut tree =
            HeaderTree::with_checkpoints(regtest_params(), vec![checkpoint_at(&chain_a, 3)]);
        // Nothing has reached the checkpoint, so a low fork is as good as any
        // chain: a bad bootstrap peer must not be able to wedge the tree.
        let (accepted, err) = tree.insert_batch(&chain_b);
        assert_eq!((accepted, err.is_none()), (2, true));
        tree.insert_batch(&chain_a);
        // Reaching it cleans up.
        assert_eq!(tree.len(), 6);
        assert!(tree.height_of(&chain_b[1].block_hash()).is_none());
        assert_eq!(tree.tip().1, 5);
    }

    #[test]
    fn test_load_prunes_below_the_checkpoint() {
        // A tree saved without checkpoints, holding a stray branch off
        // genesis next to the real chain, like the mainnet tree did.
        let mut tree = regtest_tree();
        let genesis = tree.tip().0;
        let real = mine_chain(genesis, 6, 0);
        let stray = mine_chain(genesis, 4, 1);
        tree.insert_batch(&stray);
        tree.insert_batch(&real);
        assert_eq!(tree.len(), 11);
        let dir = TempDir::new("headertree-checkpoint-load");
        let path = dir.path().join("headers.bin");
        tree.save(&path).unwrap();

        let loaded =
            HeaderTree::load(&path, regtest_params(), vec![checkpoint_at(&real, 5)]).unwrap();
        assert_eq!(loaded.reached_checkpoint(), Some(5));
        assert_eq!(loaded.len(), 7);
        assert_eq!(loaded.tip().0, real[5].block_hash());
        assert_eq!(loaded.chain_tips().len(), 1);
        for h in &stray {
            assert!(loaded.height_of(&h.block_hash()).is_none());
        }
        // The load is dirty: the next save writes the pruned tree.
        assert!(loaded.dirty);
    }

    #[test]
    fn test_pruning_moves_the_tip_off_a_pruned_branch() {
        // The tip is on the stray branch when the checkpoint block arrives:
        // the real chain has not overtaken it yet at that moment, since the
        // checkpoint is noted before the tip is updated.
        let genesis = regtest_tree().tip().0;
        let real = mine_chain(genesis, 3, 0);
        let stray = mine_chain(genesis, 2, 1);
        let mut tree =
            HeaderTree::with_checkpoints(regtest_params(), vec![checkpoint_at(&real, 3)]);
        tree.insert_batch(&stray);
        assert_eq!(tree.tip().0, stray[1].block_hash());
        tree.insert_batch(&real);
        assert_eq!(tree.tip().0, real[2].block_hash());
        assert_eq!(tree.len(), 4);
        assert_eq!(tree.chain_tips().len(), 1);
    }

    /// A stray branch cannot cross the checkpoint height, and that is what
    /// keeps the tree's parents whole.
    ///
    /// Before a checkpoint is reached a fork below it is allowed in, so a peer
    /// can hand us a long branch off genesis while we are still syncing. The
    /// question this answers is how far it gets: the header at the checkpoint
    /// height is refused by hash, and every header built on that one inherits
    /// the refusal -- so the branch stops one short of the checkpoint, and the
    /// tree never holds a header *above* a checkpoint whose ancestry is about
    /// to be pruned.
    ///
    /// Which is why the second pass of `prune_below_checkpoint` -- the one
    /// that drops what was built on a pruned header -- has nothing to do, on
    /// this path or any other: `note_checkpoint` only fires on the insert of
    /// the checkpoint block itself, and nothing taller than it is in the tree
    /// at that moment. Worth knowing rather than worth removing. A header
    /// left with no parent would not merely be stale: `chain_tips` walks
    /// parents by indexing into the map, so the next `headertree.tips` RPC
    /// would panic on it. This test is what says the guard is a guard.
    #[test]
    fn test_a_stray_branch_stops_at_the_checkpoint_height() {
        let genesis = regtest_tree().tip().0;
        let real = mine_chain(genesis, 100, 0);
        let stray = mine_chain(genesis, 150, 1);

        let mut tree =
            HeaderTree::with_checkpoints(regtest_params(), vec![checkpoint_at(&real, 100)]);
        let (accepted, _) = tree.insert_batch(&stray);

        // Ninety-nine of the hundred and fifty, and the tip is the last one
        // below the checkpoint height.
        assert_eq!(accepted, 99);
        assert_eq!(tree.tip().1, 99);
        assert_eq!(
            tree.rejection_of(&stray[99].block_hash()),
            Some(HeaderError::CheckpointMismatch),
            "the header at the checkpoint height was not refused by hash"
        );
        assert_eq!(
            tree.rejection_of(&stray[149].block_hash()),
            Some(HeaderError::CheckpointMismatch),
            "a header fifty blocks above it did not inherit the refusal"
        );
        assert_eq!(tree.reached_checkpoint(), None);

        // The real chain arrives and takes the whole stray branch with it.
        tree.insert_batch(&real);
        assert_eq!(tree.reached_checkpoint(), Some(100));
        assert_eq!(tree.len(), 101, "genesis and the hundred real headers");
        assert_eq!(tree.tip().0, real[99].block_hash());
        for header in &stray {
            assert!(
                tree.height_of(&header.block_hash()).is_none(),
                "a stray header survived the checkpoint"
            );
        }

        // The invariant the rest of the tree reads as given.
        for (hash, entry) in &tree.headers {
            if entry.height == 0 {
                continue;
            }
            assert!(
                tree.headers.contains_key(&entry.header.prev_blockhash),
                "{hash} at height {} has no parent",
                entry.height
            );
        }
        // And the RPC that walks those parents answers.
        let tips = tree.chain_tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].branch_len, 0);
        assert_eq!(tips[0].status, ChainTipStatus::Active);
    }

    #[test]
    fn test_builtin_checkpoints() {
        use common::bitcoin::{Network, network::TestnetVersion};
        for network in [
            Network::Bitcoin,
            Network::Signet,
            Network::Testnet(TestnetVersion::V4),
            Network::Testnet(TestnetVersion::V3),
        ] {
            assert_eq!(builtin_checkpoints(network).len(), 1, "{network}");
        }
        assert!(builtin_checkpoints(Network::Regtest).is_empty());

        let built_in = builtin_checkpoints(Network::Bitcoin);
        let other: BlockHash = "0000000000000000000172bed57d59e3e4b79d44296a17a298e378d9f6040395"
            .parse()
            .unwrap();
        let merged = merge_checkpoints(
            built_in.clone(),
            vec![
                Checkpoint {
                    height: 973_364,
                    hash: other,
                },
                Checkpoint {
                    height: 970_000,
                    hash: other,
                },
            ],
        );
        // Sorted, and the configured entry at 970000 replaced the built-in one.
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].height, 970_000);
        assert_eq!(merged[0].hash, other);
        assert_eq!(merged[1].height, 973_364);
    }

    // ── Random shapes ────────────────────────────────────────────────────────
    //
    // The hand-written cases above each fix one shape and one order. What they
    // cannot cover is the interaction: a reorg onto a branch that was itself
    // reorged away, a header arriving between two others that depend on it.
    // The tree's job over all of that is one sentence -- the tip is the
    // deepest block it holds, and the best chain is that block's ancestry --
    // and these check that sentence over shapes nobody chose.

    /// Deterministic, so a failure names the case that produced it rather than
    /// happening once in a thousand runs.
    struct Rng(u64);

    impl Rng {
        /// splitmix64, which is short enough to read and good enough to pick
        /// a parent with.
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// `count` headers, each built on a block already in the shape, so that
    /// branches, forks and reorgs arise rather than being arranged. Returned
    /// in creation order, which is one valid topological order.
    fn random_shape(rng: &mut Rng, count: usize, genesis: BlockHash) -> Vec<Header> {
        let mut hashes = vec![genesis];
        let mut headers = Vec::with_capacity(count);
        for i in 0..count {
            let parent = hashes[rng.below(hashes.len())];
            let header = mine_header(parent, 1_700_000_000 + i as u32, (i % 251) as u8 + 1);
            hashes.push(header.block_hash());
            headers.push(header);
        }
        headers
    }

    /// Heights of every header in a shape, worked out independently of the
    /// tree: this is the reference the tree is checked against.
    fn heights(headers: &[Header], genesis: BlockHash) -> HashMap<BlockHash, u32> {
        let mut heights = HashMap::from([(genesis, 0)]);
        // Creation order is topological, so one pass places everything.
        for header in headers {
            let height = heights[&header.prev_blockhash] + 1;
            heights.insert(header.block_hash(), height);
        }
        heights
    }

    /// An order in which every parent still comes before its children, but
    /// which branch is extended next is random.
    fn topological_shuffle(rng: &mut Rng, headers: &[Header], genesis: BlockHash) -> Vec<Header> {
        let mut placed: HashSet<BlockHash> = HashSet::from([genesis]);
        let mut left: Vec<Header> = headers.to_vec();
        let mut order = Vec::with_capacity(headers.len());
        while !left.is_empty() {
            let ready: Vec<usize> = left
                .iter()
                .enumerate()
                .filter(|(_, h)| placed.contains(&h.prev_blockhash))
                .map(|(i, _)| i)
                .collect();
            let header = left.remove(ready[rng.below(ready.len())]);
            placed.insert(header.block_hash());
            order.push(header);
        }
        order
    }

    /// However the headers arrive, as long as each parent comes before its
    /// children, the tree ends at the deepest block it holds and holds all of
    /// them.
    #[test]
    fn test_any_topological_order_ends_at_the_deepest_block() {
        for seed in 0..40u64 {
            let mut rng = Rng(seed);
            let genesis = regtest_tree().tip().0;
            let shape = random_shape(&mut rng, 30, genesis);
            let heights = heights(&shape, genesis);
            let deepest = *heights.values().max().unwrap();

            let order = topological_shuffle(&mut rng, &shape, genesis);
            let mut tree = regtest_tree();
            for header in &order {
                let (accepted, err) = tree.insert_batch(&[*header]);
                assert_eq!(
                    accepted, 1,
                    "seed {seed}: refused a placeable header: {err:?}"
                );
            }

            assert_eq!(tree.len(), shape.len() + 1, "seed {seed}");
            let (tip, height) = tree.tip();
            assert_eq!(height, deepest, "seed {seed}: the tip is not the deepest");
            assert_eq!(heights[&tip], deepest, "seed {seed}");

            // Where the deepest block is the only one at that height, the tip
            // is that block and not merely one of its depth.
            let at_the_top: Vec<_> = heights
                .iter()
                .filter(|(_, h)| **h == deepest)
                .map(|(hash, _)| *hash)
                .collect();
            if at_the_top.len() == 1 {
                assert_eq!(tip, at_the_top[0], "seed {seed}");
            }
        }
    }

    /// The best chain is the tip's ancestry, every time.
    ///
    /// A reorg rebuilds this list, and a reorg that got it wrong -- a stale
    /// entry, a missing link, the wrong length -- would still leave the tip
    /// right, so the tip alone does not check it.
    #[test]
    fn test_the_best_chain_is_the_tips_ancestry() {
        for seed in 100..130u64 {
            let mut rng = Rng(seed);
            let genesis = regtest_tree().tip().0;
            let shape = random_shape(&mut rng, 25, genesis);
            let order = topological_shuffle(&mut rng, &shape, genesis);

            let mut tree = regtest_tree();
            for header in &order {
                tree.insert_batch(&[*header]);
            }

            let (tip, height) = tree.tip();
            assert_eq!(tree.best_chain.len(), height as usize + 1, "seed {seed}");
            assert_eq!(tree.best_chain[0], genesis, "seed {seed}");
            assert_eq!(*tree.best_chain.last().unwrap(), tip, "seed {seed}");

            let by_hash: HashMap<BlockHash, Header> =
                shape.iter().map(|h| (h.block_hash(), *h)).collect();
            for pair in tree.best_chain.windows(2) {
                assert_eq!(
                    by_hash[&pair[1]].prev_blockhash, pair[0],
                    "seed {seed}: the best chain is not a chain"
                );
            }
        }
    }

    /// Headers that arrive before their parents are refused, and the tree says
    /// so rather than remembering them as wrong: offered again once the gap is
    /// filled, they are taken.
    ///
    /// This is what the recovery requests are for, and the property they rely
    /// on. An orphan rejection that stuck would leave the tree permanently
    /// short of a branch it had been told about, with nothing asking again.
    #[test]
    fn test_a_tree_fed_out_of_order_catches_up_when_fed_again() {
        for seed in 200..230u64 {
            let mut rng = Rng(seed);
            let genesis = regtest_tree().tip().0;
            let shape = random_shape(&mut rng, 25, genesis);
            let heights = heights(&shape, genesis);
            let deepest = *heights.values().max().unwrap();

            // A plain shuffle, so parents and children arrive in any order.
            let mut scrambled = shape.clone();
            for i in (1..scrambled.len()).rev() {
                scrambled.swap(i, rng.below(i + 1));
            }

            let mut tree = regtest_tree();
            // One pass can place at most one more generation, so the bound is
            // the depth; failing to converge inside it is the bug.
            let mut passes = 0;
            while tree.len() < shape.len() + 1 {
                passes += 1;
                assert!(
                    passes <= deepest + 1,
                    "seed {seed}: {} of {} headers after {passes} passes",
                    tree.len() - 1,
                    shape.len()
                );
                for header in &scrambled {
                    tree.insert_batch(&[*header]);
                }
            }
            assert_eq!(tree.tip().1, deepest, "seed {seed}");
        }
    }

    /// The same tree, built twice, saves to the same bytes.
    ///
    /// It did not: the order within a height was the iteration order of a
    /// HashMap, which differs between two maps holding the same keys. So the
    /// file written every minute could differ from the last for no reason, and
    /// -- because the tree keeps the first tip it sees of a given amount of
    /// work -- a restart with two branches tied at the tip came back on
    /// whichever one that order happened to put first.
    #[test]
    fn test_the_same_tree_saves_to_the_same_bytes() {
        let dir = TempDir::new("headertree-stable");
        for seed in 400..410u64 {
            let genesis = regtest_tree().tip().0;
            let shape = random_shape(&mut Rng(seed), 20, genesis);

            let written = |n: u8| {
                let mut tree = regtest_tree();
                for header in &shape {
                    tree.insert_batch(&[*header]);
                }
                let path = dir.path().join(format!("{seed}-{n}.bin"));
                tree.dirty = true;
                tree.save(&path).unwrap();
                std::fs::read(&path).unwrap()
            };
            assert_eq!(written(0), written(1), "seed {seed}");
        }
    }

    /// A random tree survives the round trip to disk.
    #[test]
    fn test_save_and_load_agree_on_a_random_tree() {
        let dir = TempDir::new("headertree-random");
        for seed in 300..310u64 {
            let mut rng = Rng(seed);
            let genesis = regtest_tree().tip().0;
            let shape = random_shape(&mut rng, 20, genesis);
            let order = topological_shuffle(&mut rng, &shape, genesis);

            let mut tree = regtest_tree();
            for header in &order {
                tree.insert_batch(&[*header]);
            }

            let path = dir.path().join(format!("{seed}.bin"));
            tree.dirty = true;
            tree.save(&path).unwrap();
            let loaded = HeaderTree::load(&path, regtest_params(), Vec::new()).unwrap();

            assert_eq!(loaded.tip(), tree.tip(), "seed {seed}");
            assert_eq!(loaded.len(), tree.len(), "seed {seed}");
            assert_eq!(loaded.best_chain, tree.best_chain, "seed {seed}");
            assert_eq!(loaded.build_locator(), tree.build_locator(), "seed {seed}");
        }
    }

    /// What a locator has to get right, and what it is free to choose.
    ///
    /// A peer answers from the first hash in the locator that is on the
    /// peer's own chain, so only two entries matter by their presence: the
    /// tip, which is what makes a peer that agrees with us send nothing, and
    /// genesis, which is what keeps a peer that agrees with us about nothing
    /// from having to guess. Everything in between is a trade -- denser means
    /// fewer headers re-sent after a fork, longer means a bigger message --
    /// so the step pattern is deliberately not pinned here. What is pinned is
    /// that every entry is a block on our chain, in descending order, and
    /// that there are not too many of them.
    #[test]
    fn test_a_locator_names_our_tip_first_and_genesis_last() {
        let mut tree = regtest_tree();
        let genesis = tree.tip().0;
        let chain = mine_chain(genesis, 400, 0);
        tree.insert_batch(&chain);

        let locator = tree.build_locator();
        assert_eq!(locator.first(), Some(&tree.tip().0), "the tip comes first");
        assert_eq!(locator.last(), Some(&genesis), "genesis comes last");

        let mut last_height = None;
        for hash in &locator {
            let height = tree
                .height_of(hash)
                .unwrap_or_else(|| panic!("a locator hash we do not know: {hash}"));
            assert_eq!(
                tree.best_chain[height as usize], *hash,
                "a locator hash that is not on our best chain: {hash}"
            );
            if let Some(last) = last_height {
                assert!(height < last, "the locator is not descending: {locator:?}");
            }
            last_height = Some(height);
        }
        assert!(
            locator.len() <= MAX_LOCATOR_SZ,
            "a peer disconnects us for a locator this long: {}",
            locator.len()
        );
    }

    /// And still not too many at a height no test can mine to.
    ///
    /// The entries grow with the logarithm of the height once the step starts
    /// doubling, so the limit is never close -- but "never close" is the kind
    /// of claim that stops being true when someone changes the step. The tree
    /// is handed a chain rather than mining one: all `build_locator` reads is
    /// the best chain and the tip height, and mining a million regtest headers
    /// to test an index walk would take minutes.
    #[test]
    fn test_a_locator_stays_short_at_mainnet_scale() {
        let mut tree = regtest_tree();
        let genesis = tree.tip().0;
        tree.best_chain = (0..5_000_000u32)
            .map(|i| {
                if i == 0 {
                    genesis
                } else {
                    let mut bytes = [0u8; 32];
                    bytes[..4].copy_from_slice(&i.to_le_bytes());
                    BlockHash::from_byte_array(bytes)
                }
            })
            .collect();
        tree.tip_height = tree.best_chain.len() as u32 - 1;

        let locator = tree.build_locator();
        assert_eq!(
            locator.first(),
            Some(&tree.best_chain[tree.tip_height as usize])
        );
        assert_eq!(locator.last(), Some(&genesis));
        assert!(
            locator.len() <= MAX_LOCATOR_SZ,
            "a locator of {} at height {}",
            locator.len(),
            tree.tip_height
        );
    }

    /// The locator and the answer to it, together, against a peer on another
    /// chain.
    ///
    /// Each half is only as useful as the other: a locator that named nothing
    /// the peer had would be answered from height 1, and an answer that
    /// started above our fork would not connect to anything we hold. So this
    /// takes our locator, has a peer's tree answer it, and feeds the answer
    /// back -- which is the whole exchange, and the only thing that proves
    /// the two agree.
    #[test]
    fn test_a_peer_answers_our_locator_with_headers_that_connect() {
        let genesis = regtest_tree().tip().0;
        let common = mine_chain(genesis, 280, 0);
        let ours = mine_chain(common[279].block_hash(), 20, 1);
        let theirs = mine_chain(common[279].block_hash(), 70, 2);

        let mut us = regtest_tree();
        us.insert_batch(&common);
        us.insert_batch(&ours);
        assert_eq!(us.tip().1, 300);

        let mut peer = regtest_tree();
        peer.insert_batch(&common);
        peer.insert_batch(&theirs);
        assert_eq!(peer.tip().1, 350);

        let answer =
            peer.get_headers_from_locator(&us.build_locator(), BlockHash::from_byte_array([0; 32]));
        assert!(!answer.is_empty(), "the peer answered nothing");
        assert!(
            us.height_of(&answer[0].prev_blockhash).is_some(),
            "the answer starts at a block whose parent we do not have"
        );
        assert_eq!(
            answer.last().unwrap().block_hash(),
            peer.tip().0,
            "the answer stops short of the peer's tip"
        );

        // And it does not start far below the fork. This is what the dense
        // run of entries nearest the tip is for, and it is the only
        // measurable thing about the step pattern: a locator of just the tip
        // and genesis is a valid locator, and a peer would answer it by
        // re-sending our whole chain. Twenty blocks past the fork, a peer
        // should be re-sending us a handful of headers, not hundreds.
        let already_had = answer
            .iter()
            .filter(|h| us.height_of(&h.block_hash()).is_some())
            .count();
        assert!(
            already_had < 32,
            "the peer re-sent {already_had} headers we already had"
        );

        // Every one of them places, and we end up on the peer's chain: that
        // is what the exchange was for.
        us.insert_batch(&answer);
        assert_eq!(us.tip().0, peer.tip().0);
        assert_eq!(us.tip().1, 350);
        // Our own fork is still there, as a stale tip rather than a gap.
        assert_eq!(us.chain_tips().len(), 2);

        // And now that we agree, our locator asks for nothing.
        assert!(
            peer.get_headers_from_locator(&us.build_locator(), BlockHash::from_byte_array([0; 32]))
                .is_empty(),
            "the peer re-sent headers we already have"
        );
    }

    /// Any locator at all gets an answer that is a piece of our best chain.
    ///
    /// The locator is a peer's to compose: any hashes, in any order, including
    /// ones from a branch we know but are not on. The walk takes the first
    /// hash that is on the best chain, starts after it, and copies up to two
    /// thousand headers -- and the length it reserves for them is a
    /// subtraction between two heights, which is the shape that underflows if
    /// the two ever get out of order.
    ///
    /// What has to hold: no more than the cap, every header actually ours, and
    /// each one built on the last -- an answer that is not a run of the chain
    /// is one the peer cannot use.
    #[test]
    fn test_any_locator_is_answered_with_a_run_of_our_chain() {
        // A chain with side branches, so a locator can hold a hash we know at
        // a height we are not on -- the case a flat chain cannot produce.
        let mut tree = regtest_tree();
        let (genesis, _) = tree.tip();
        let mut known = vec![genesis];
        let mut rng = testsupport::Rng::new(7);
        for i in 0..120u32 {
            let parent = known[rng.below(known.len())];
            let header = mine_header(parent, 1_700_000_000 + i, (i % 251) as u8 + 1);
            tree.insert_batch(&[header]);
            known.push(header.block_hash());
        }
        let (tip, tip_height) = tree.tip();
        assert!(tip_height > 1, "the shape is not a chain");

        let zero = BlockHash::from_byte_array([0; 32]);
        for seed in 0..20_000u64 {
            let mut rng = testsupport::Rng::new(seed);
            let locator: Vec<BlockHash> = (0..rng.below(8))
                .map(|_| match rng.below(4) {
                    // A hash we know, on or off the best chain.
                    0 | 1 => known[rng.below(known.len())],
                    2 => tip,
                    // One we have never seen.
                    _ => {
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&rng.bytes(32));
                        BlockHash::from_byte_array(bytes)
                    }
                })
                .collect();
            let stop = if rng.one_in(4) {
                known[rng.below(known.len())]
            } else {
                zero
            };

            let answer = tree.get_headers_from_locator(&locator, stop);
            assert!(
                answer.len() <= 2000,
                "seed {seed}: {} headers",
                answer.len()
            );

            for pair in answer.windows(2) {
                assert_eq!(
                    pair[1].prev_blockhash,
                    pair[0].block_hash(),
                    "seed {seed}: the answer is not a run of one chain"
                );
            }
            for header in &answer {
                let hash = header.block_hash();
                let height = tree.height_of(&hash).unwrap_or_else(|| {
                    panic!("seed {seed}: answered with a header we do not hold")
                });
                assert_eq!(
                    tree.best_chain[height as usize], hash,
                    "seed {seed}: answered with a header off our best chain"
                );
            }
        }

        // And the one case worth naming: a peer already at our tip is told
        // nothing, which is the answer that costs nothing to give.
        assert!(tree.get_headers_from_locator(&[tip], zero).is_empty());
    }
}
