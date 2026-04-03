use std::collections::HashMap;
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

const HEADER_SIZE: usize = 80;

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
}

#[derive(Debug)]
pub(crate) enum HeaderError {
    OrphanHeader,
    InvalidPow,
    TargetTooEasy,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::OrphanHeader => write!(f, "parent header not in tree"),
            HeaderError::InvalidPow => write!(f, "invalid proof of work"),
            HeaderError::TargetTooEasy => write!(f, "target exceeds maximum"),
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
        }
    }

    /// Insert a single header. Returns `Ok(true)` if new, `Ok(false)` if already known.
    pub(crate) fn insert(&mut self, header: Header) -> std::result::Result<bool, HeaderError> {
        self.insert_inner(header, false)
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

        let expected_bits = if height % 2016 == 0 && height > 0 {
            // Retarget: walk back 2016 blocks from the parent to find epoch start
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

    #[allow(dead_code)]
    pub(crate) fn contains(&self, hash: &BlockHash) -> bool {
        self.headers.contains_key(hash)
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

    pub(crate) fn load(path: &Path, params: common::bitcoin::network::Params) -> Result<Self> {
        let mut tree = Self::new(params.clone());

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
                for i in 0..count {
                    let offset = i * HEADER_SIZE;
                    let header: Header = deserialize(&data[offset..offset + HEADER_SIZE])
                        .context("deserialize header")?;
                    match tree.insert(header) {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(target: TARGET, "skipping header during load: {e}");
                        }
                    }
                }
                tracing::info!(target: TARGET,
                    headers = tree.headers.len(),
                    tip_height = tree.tip_height,
                    "header tree loaded"
                );
                tree.dirty = false;
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
            tracing::warn!(target: TARGET, "failed to persist header tree: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoind::client::bitcoin::Address;
    use common::bitcoin::{Network, network::Params};

    // A random regtest address we can mine to.
    fn regtest_address() -> Address {
        const REGTEST_ADDR: &str = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw";
        REGTEST_ADDR
            .parse::<bitcoind::client::bitcoin::Address<_>>()
            .unwrap()
            .assume_checked()
    }

    fn regtest_params() -> Params {
        Params::new(Network::Regtest)
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
            *common::bitcoin::blockdata::constants::genesis_block(&regtest_params()).header();
        let (accepted, err) = tree.insert_batch(&[genesis]);
        assert_eq!(accepted, 0);
        assert!(err.is_none());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_orphan_rejected() {
        let mut tree = regtest_tree();
        let mut header =
            *common::bitcoin::blockdata::constants::genesis_block(&regtest_params()).header();
        header.prev_blockhash = BlockHash::from_byte_array([0xab; 32]);
        let (_, err) = tree.insert_batch(&[header]);
        assert!(matches!(err, Some(HeaderError::OrphanHeader)));
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

        let tips_before = tree.chain_tips();
        tree.save(&path).unwrap();

        let loaded = HeaderTree::load(&path, regtest_params()).unwrap();
        let tips_after = loaded.chain_tips();

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

        let loaded = HeaderTree::load(&path, regtest_params()).unwrap();
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
}
