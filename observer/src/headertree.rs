use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

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

struct HeaderEntry {
    header: Header,
    height: u32,
    chain_work: Work,
}

pub(crate) struct HeaderTree {
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
}

#[derive(Debug)]
pub(crate) enum HeaderError {
    OrphanHeader,
    InvalidPow,
    TargetTooEasy,
    /// A header at a checkpoint height with another hash.
    CheckpointMismatch,
    /// A header at or below a checkpoint the tree has reached.
    ForkBelowCheckpoint,
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
            HeaderError::InvalidPow => write!(f, "invalid proof of work"),
            HeaderError::TargetTooEasy => write!(f, "target exceeds maximum"),
            HeaderError::CheckpointMismatch => write!(f, "hash differs from the checkpoint"),
            HeaderError::ForkBelowCheckpoint => write!(f, "fork below a reached checkpoint"),
        }
    }
}

impl HeaderTree {
    pub(crate) fn new(params: common::bitcoin::network::Params) -> Self {
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
        // What was built on a pruned header is now an orphan; in height order
        // so a parent is settled before its children.
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

    // Insert a single header. Returns `Ok(true)` if new, `Ok(false)` if already known.
    // In batch mode, the caller has to take care of calling rebuild_best_chain().
    fn insert_inner(
        &mut self,
        header: Header,
        batch: bool,
    ) -> std::result::Result<bool, HeaderError> {
        let hash = header.block_hash();
        if self.headers.contains_key(&hash) {
            return Ok(false);
        }

        let parent = self
            .headers
            .get(&header.prev_blockhash)
            .ok_or(HeaderError::OrphanHeader)?;
        let height = parent.height + 1;

        self.validate_header(&header, height, parent)?;

        let chain_work = parent.chain_work + header.work();
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

            // On batch inserts, don't rebuild the bast chain here.
            // The caller has to take care of it.
            if !batch {
                self.rebuild_best_chain();
            }
        }

        self.dirty = true;
        Ok(true)
    }

    /// Insert a batch of headers. Returns count of accepted headers and first error if any.
    pub(crate) fn insert_batch(&mut self, headers: &[Header]) -> (usize, Option<HeaderError>) {
        let old_tip = self.tip;
        let mut accepted = 0;
        let mut err = None;

        for header in headers {
            match self.insert_inner(*header, true) {
                Ok(true) => accepted += 1,
                Ok(false) => {} // already known, skip
                Err(e) => {
                    err = Some(e);
                    break;
                }
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

    pub(crate) fn tip(&self) -> (BlockHash, u32) {
        (self.tip, self.tip_height)
    }

    pub(crate) fn contains(&self, hash: &BlockHash) -> bool {
        self.headers.contains_key(hash)
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
    pub(crate) fn build_locator(&self) -> Vec<BlockHash> {
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
    pub(crate) fn get_headers_from_locator(
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

        let mut entries: Vec<_> = self
            .headers
            .values()
            .map(|e| (e.height, &e.header))
            .collect();
        entries.sort_by_key(|(h, _)| *h);

        let mut buf = Vec::with_capacity(entries.len() * HEADER_SIZE);
        for (_, header) in &entries {
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
                    if let Err(e) = tree.insert_inner(header, true) {
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

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use common::bitcoin::{Network, network::Params};

    pub(crate) fn regtest_params() -> Params {
        Params::new(Network::Regtest)
    }

    /// Mine a valid regtest header. Regtest uses bits=0x207fffff which gives a
    /// target so easy that nonce=0 always satisfies PoW. A unique `seed` byte in
    /// the merkle root lets callers produce different blocks at the same height.
    pub(crate) fn mine_header(prev_hash: BlockHash, time: u32, seed: u8) -> Header {
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
    use bitcoind::client::bitcoin::Address;

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

        let dir = std::env::temp_dir().join("headertree-test-roundtrip");
        let path = dir.join("headers.bin");
        let _ = std::fs::create_dir_all(&dir);

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
            assert!(loaded.contains(&header.block_hash()));
        }
        for header in &chain_b {
            assert!(loaded.contains(&header.block_hash()));
        }

        let _ = std::fs::remove_dir_all(&dir);
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
        let dir = std::env::temp_dir().join("headertree-test-regtest");
        let path = dir.join("headers.bin");
        let _ = std::fs::create_dir_all(&dir);

        tree.dirty = true;
        tree.save(&path).unwrap();

        let loaded = HeaderTree::load(&path, regtest_params(), Vec::new()).unwrap();
        assert_eq!(loaded.tip(), tree.tip());
        assert_eq!(loaded.len(), tree.len());
        assert_eq!(loaded.build_locator(), tree.build_locator());

        let _ = std::fs::remove_dir_all(&dir);
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
            assert!(tree.contains(&header.block_hash()));
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
            magic: Magic::REGTEST,
            ping_interval: common::tokio::time::Duration::from_secs(120),
            user_agent: protocol::USER_AGENT.to_owned(),
            event_tx: event_tx.clone(),
            header_tree: header_tree.clone(),
            sync_headers,
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
        assert!(!tree.contains(&chain_b[0].block_hash()));
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
        assert!(!tree.contains(&chain_b[1].block_hash()));
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
        let dir = std::env::temp_dir().join("headertree-test-checkpoint-load");
        let path = dir.join("headers.bin");
        let _ = std::fs::create_dir_all(&dir);
        tree.save(&path).unwrap();

        let loaded =
            HeaderTree::load(&path, regtest_params(), vec![checkpoint_at(&real, 5)]).unwrap();
        assert_eq!(loaded.reached_checkpoint(), Some(5));
        assert_eq!(loaded.len(), 7);
        assert_eq!(loaded.tip().0, real[5].block_hash());
        assert_eq!(loaded.chain_tips().len(), 1);
        for h in &stray {
            assert!(!loaded.contains(&h.block_hash()));
        }
        // The load is dirty: the next save writes the pruned tree.
        assert!(loaded.dirty);
        let _ = std::fs::remove_dir_all(&dir);
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
    }
}
