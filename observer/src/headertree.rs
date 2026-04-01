use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use common::{
    anyhow::{Context, Result, anyhow, bail},
    bitcoin::{
        BlockHash, Network,
        block::Header,
        blockdata::constants::genesis_block,
        consensus,
        network::Params,
        pow::{CompactTarget, CompactTargetExt, Target, Work},
    },
    tracing,
};

use crate::TARGET_HEADERS as TARGET;

const RECORD_SIZE: usize = 84; // 4 (height u32 LE) + 80 (consensus-encoded header)

pub struct HeaderNode {
    pub header: Header,
    pub height: u32,
    pub total_work: Work,
}

pub struct Reorg {
    pub disconnected: Vec<BlockHash>, // removed from best chain, tip-first
    pub connected: Vec<BlockHash>,    // added to best chain, tip-first
}

pub struct HeaderTree {
    nodes: HashMap<BlockHash, HeaderNode>,
    tip: BlockHash,
    /// Hashes of the best chain, indexed by height.
    height_index: HashMap<u32, BlockHash>,
    params: Params,
    file: File,
}

impl HeaderTree {
    pub fn load(path: &Path, network: Network) -> Result<Self> {
        let params = Params::new(network);
        let genesis = genesis_block(network);
        let genesis_header = *genesis.header();
        let genesis_hash = genesis_header.block_hash();
        let genesis_work = Target::from_compact(genesis_header.bits).to_work();

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open headers file {path:?}"))?;

        // Read existing records before doing anything else.
        let mut records: Vec<(u32, Header)> = Vec::new();
        {
            file.seek(SeekFrom::Start(0)).context("seek headers file")?;
            let mut buf = [0u8; RECORD_SIZE];
            loop {
                match file.read_exact(&mut buf) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e).context("read header record"),
                }
                let height = u32::from_le_bytes(buf[..4].try_into().unwrap());
                match consensus::deserialize::<Header>(&buf[4..]) {
                    Ok(h) => records.push((height, h)),
                    Err(e) => tracing::warn!(target: TARGET, "skipping corrupt record: {e}"),
                }
            }
            records.sort_by_key(|(h, _)| *h);
            // Seek to end so subsequent writes append.
            file.seek(SeekFrom::End(0)).context("seek to end")?;
        }

        let mut nodes = HashMap::new();
        let mut height_index = HashMap::new();
        nodes.insert(
            genesis_hash,
            HeaderNode {
                header: genesis_header,
                height: 0,
                total_work: genesis_work,
            },
        );
        height_index.insert(0, genesis_hash);

        let mut tree = HeaderTree {
            nodes,
            tip: genesis_hash,
            height_index,
            params,
            file,
        };

        let count = records.len();
        let mut loaded = 0usize;
        for (_, header) in records {
            match tree.insert_inner(header, false) {
                Ok(_) => loaded += 1,
                Err(e) => tracing::debug!(target: TARGET, "skipping header on load: {e}"),
            }
        }
        tracing::info!(target: TARGET, loaded, count, height = tree.tip().height, "headers loaded");
        Ok(tree)
    }

    /// Insert a header received from the network. Returns a `Reorg` if the best chain changed.
    pub fn insert(&mut self, header: Header) -> Result<Option<Reorg>> {
        self.insert_inner(header, true)
    }

    fn insert_inner(&mut self, header: Header, validate: bool) -> Result<Option<Reorg>> {
        let hash = header.block_hash();
        if self.nodes.contains_key(&hash) {
            return Ok(None);
        }

        let parent_hash = header.prev_blockhash;
        let (parent_height, parent_total_work) = {
            let p = self
                .nodes
                .get(&parent_hash)
                .ok_or_else(|| anyhow!("orphan: unknown parent {parent_hash}"))?;
            (p.height, p.total_work)
        };
        let height = parent_height + 1;

        if validate {
            self.validate_pow(&header)?;
            self.validate_difficulty(&header, parent_hash, height)?;
        }

        let work = Target::from_compact(header.bits).to_work();
        let total_work = parent_total_work + work;

        if validate {
            self.append_record(height, &header)?;
        }

        self.nodes.insert(
            hash,
            HeaderNode {
                header,
                height,
                total_work,
            },
        );

        let current_tip_work = self.nodes[&self.tip].total_work;
        if total_work > current_tip_work {
            if parent_hash == self.tip {
                // Simple chain extension — no reorg.
                self.tip = hash;
                self.height_index.insert(height, hash);
                Ok(None)
            } else {
                // New tip is on a fork — reorg needed.
                let reorg = self.apply_reorg(hash);
                tracing::warn!(target: TARGET,
                    disconnected = reorg.disconnected.len(),
                    connected = reorg.connected.len(),
                    height,
                    "reorg"
                );
                Ok(Some(reorg))
            }
        } else {
            Ok(None)
        }
    }

    fn validate_pow(&self, header: &Header) -> Result<()> {
        let hash = header.block_hash();
        if !Target::from_compact(header.bits).is_met_by(hash) {
            bail!("proof of work not met for {hash}");
        }
        Ok(())
    }

    fn validate_difficulty(
        &self,
        header: &Header,
        parent_hash: BlockHash,
        height: u32,
    ) -> Result<()> {
        let interval = self.params.miner_confirmation_window.to_u32();
        let parent = &self.nodes[&parent_hash];

        // Testnet: a block whose timestamp exceeds parent + 2×target_spacing may
        // use the minimum-difficulty target. We allow it and skip further checks.
        if self.params.allow_min_difficulty_blocks {
            let threshold = parent
                .header
                .time
                .to_u32()
                .saturating_add(self.params.pow_target_spacing as u32 * 2);
            if header.time.to_u32() > threshold {
                return Ok(());
            }
        }

        let is_retarget = height % interval == 0;
        let expected_bits: CompactTarget = if is_retarget {
            // Walk back (interval - 1) steps from parent to find epoch-start header.
            let steps = interval - 1;
            let epoch_start = self
                .walk_back(parent_hash, steps)
                .ok_or_else(|| anyhow!("missing epoch start for retarget at height {height}"))?;
            // `from_header_difficulty_adjustment(epoch_start, epoch_end, params)` where
            // epoch_end is the last header of the epoch (our parent).
            <CompactTarget as CompactTargetExt>::from_header_difficulty_adjustment(
                epoch_start.header,
                parent.header,
                &self.params,
            )
        } else {
            parent.header.bits
        };

        if header.bits != expected_bits {
            bail!(
                "invalid difficulty at height {height}: expected {:?}, got {:?}",
                expected_bits,
                header.bits,
            );
        }
        Ok(())
    }

    fn walk_back(&self, from: BlockHash, steps: u32) -> Option<&HeaderNode> {
        let mut hash = from;
        for _ in 0..steps {
            let node = self.nodes.get(&hash)?;
            hash = node.header.prev_blockhash;
        }
        self.nodes.get(&hash)
    }

    fn walk_back_hash(&self, from: BlockHash, steps: u32) -> Option<BlockHash> {
        let mut hash = from;
        for _ in 0..steps {
            hash = self.nodes.get(&hash)?.header.prev_blockhash;
        }
        Some(hash)
    }

    fn append_record(&mut self, height: u32, header: &Header) -> Result<()> {
        self.file.seek(SeekFrom::End(0)).context("seek to end")?;
        let mut buf = [0u8; RECORD_SIZE];
        buf[..4].copy_from_slice(&height.to_le_bytes());
        let encoded = consensus::serialize(header);
        debug_assert_eq!(encoded.len(), 80);
        buf[4..].copy_from_slice(&encoded);
        self.file.write_all(&buf).context("write header record")
    }

    /// Switches the best chain to `new_tip`, updating `height_index` and returning
    /// the set of disconnected/connected hashes.
    fn apply_reorg(&mut self, new_tip: BlockHash) -> Reorg {
        let mut disconnected = Vec::new();
        let mut connected = Vec::new();

        let mut old = self.tip;
        let mut new = new_tip;

        // Walk both chains to the same height.
        while self.nodes[&old].height > self.nodes[&new].height {
            disconnected.push(old);
            old = self.nodes[&old].header.prev_blockhash;
        }
        while self.nodes[&new].height > self.nodes[&old].height {
            connected.push(new);
            new = self.nodes[&new].header.prev_blockhash;
        }

        // Walk both back until they share a common ancestor.
        while old != new {
            disconnected.push(old);
            connected.push(new);
            old = self.nodes[&old].header.prev_blockhash;
            new = self.nodes[&new].header.prev_blockhash;
        }
        // `old == new` is the common ancestor; do not include it in either list.

        for &hash in &disconnected {
            self.height_index.remove(&self.nodes[&hash].height);
        }
        for &hash in &connected {
            self.height_index.insert(self.nodes[&hash].height, hash);
        }

        self.tip = new_tip;
        Reorg {
            disconnected,
            connected,
        }
    }

    /// Generates a block locator for a `getheaders` request, starting from the current tip.
    pub fn locator(&self) -> Vec<BlockHash> {
        let mut locator = Vec::new();
        let mut hash = self.tip;
        let mut step = 1u32;
        let mut count = 0u32;

        loop {
            locator.push(hash);
            let node = match self.nodes.get(&hash) {
                Some(n) => n,
                None => break,
            };
            if node.height == 0 {
                break;
            }
            let back = step.min(node.height);
            match self.walk_back_hash(hash, back) {
                Some(h) => hash = h,
                None => break,
            }
            count += 1;
            if count >= 10 {
                step = step.saturating_mul(2);
            }
        }

        // Ensure genesis is included.
        if let Some(&genesis_hash) = self.height_index.get(&0) {
            if locator.last() != Some(&genesis_hash) {
                locator.push(genesis_hash);
            }
        }

        locator
    }

    pub fn tip(&self) -> &HeaderNode {
        &self.nodes[&self.tip]
    }

    #[allow(dead_code)]
    pub fn tip_hash(&self) -> BlockHash {
        self.tip
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
}
