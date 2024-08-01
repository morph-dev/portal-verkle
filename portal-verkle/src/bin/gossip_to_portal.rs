use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use clap::Parser;
use ethportal_api::{
    types::content_key::verkle::LeafFragmentKey, VerkleContentKey, VerkleContentValue,
    VerkleNetworkApiClient,
};
use futures::future;
use itertools::{zip_eq, Itertools};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use portal_verkle::{
    beacon_block_fetcher::BeaconBlockFetcher, evm::VerkleEvm, utils::read_genesis,
};
use portal_verkle_primitives::{
    constants::PORTAL_NETWORK_NODE_WIDTH,
    portal::PortalVerkleNodeWithProof,
    ssz::TriePath,
    verkle::{
        genesis_config::GenesisConfig,
        nodes::{
            portal_branch_node_builder::PortalBranchNodeBuilder,
            portal_leaf_node_builder::PortalLeafNodeBuilder,
        },
        StateWrites,
    },
    Stem,
};

const LOCALHOST_BEACON_RPC_URL: &str = "http://localhost:9596/";
const LOCALHOST_PORTAL_RPC_URL: &str = "http://localhost:8545/";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub slots: u64,
    #[arg(long, default_value_t = String::from(LOCALHOST_BEACON_RPC_URL))]
    pub beacon_rpc_url: String,
    #[arg(long, default_value_t = String::from(LOCALHOST_PORTAL_RPC_URL))]
    pub portal_rpc_url: String,
}

struct BranchNodeBuilderWithFragments<'a> {
    builder: PortalBranchNodeBuilder<'a>,
    fragment_indices: HashSet<u8>,
}

struct LeafNodeBuilderWithFragments<'a> {
    stem: Stem,
    builder: PortalLeafNodeBuilder<'a>,
    fragment_indices: HashSet<u8>,
}

struct TriePathWrapper(TriePath);

impl Eq for TriePathWrapper {}

impl PartialEq for TriePathWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl PartialOrd for TriePathWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TriePathWrapper {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.len().cmp(&other.0.len()).then_with(|| {
            zip_eq(&self.0, &other.0)
                .find_map(|(a, b)| if a == b { None } else { Some(a.cmp(b)) })
                .unwrap_or(Ordering::Equal)
        })
    }
}

struct Gossiper {
    block_fetcher: BeaconBlockFetcher,
    portal_client: HttpClient,
    evm: VerkleEvm,
}

impl Gossiper {
    fn new(args: &Args) -> anyhow::Result<Self> {
        let block_fetcher =
            BeaconBlockFetcher::new(&args.beacon_rpc_url, /* save_locally = */ false);
        let portal_client = HttpClientBuilder::new()
            .request_timeout(Duration::from_secs(60))
            .build(&args.portal_rpc_url)?;
        let evm = VerkleEvm::new(read_genesis()?)?;

        Ok(Self {
            block_fetcher,
            portal_client,
            evm,
        })
    }

    async fn gossip_genesis(&mut self) -> anyhow::Result<()> {
        let state_writes = read_genesis()?.into_state_writes();
        println!("Gossiping genesis...");
        self.gossip_state_writes(
            GenesisConfig::DEVNET6_BLOCK_HASH,
            state_writes,
            HashSet::new(),
        )
        .await?;
        Ok(())
    }

    async fn gossip_slot(&mut self, slot: u64) -> anyhow::Result<()> {
        let Ok(Some(beacon_block)) = self.block_fetcher.fetch_beacon_block(slot).await else {
            println!("Beacon block for slot {slot} not found!");
            return Ok(());
        };
        let execution_payload = &beacon_block.message.body.execution_payload;
        let process_block_result = self.evm.process_block(execution_payload)?;
        println!(
            "Gossiping slot {slot:04} (block - number={:04} hash={} root={})",
            execution_payload.block_number,
            execution_payload.block_hash,
            execution_payload.state_root
        );
        self.gossip_state_writes(
            execution_payload.block_hash,
            process_block_result.state_writes,
            process_block_result.new_branch_nodes,
        )
        .await?;
        Ok(())
    }

    async fn gossip_state_writes(
        &self,
        block_hash: B256,
        state_writes: StateWrites,
        new_branch_nodes: HashSet<TriePath>,
    ) -> anyhow::Result<()> {
        let timer = Instant::now();

        let mut branches_to_gossip: BTreeMap<TriePathWrapper, BranchNodeBuilderWithFragments> =
            BTreeMap::new();
        let mut leaves_to_gossip: BTreeMap<Stem, LeafNodeBuilderWithFragments> = BTreeMap::new();

        for stem_state_write in state_writes.iter() {
            let stem = &stem_state_write.stem;
            let path_to_leaf = self.evm.state_trie().traverse_to_leaf(stem)?;

            for depth in 0..path_to_leaf.trie_path.len() {
                let trie_path = TriePath::from(stem[..depth].to_vec());
                let (branch, child_index) = path_to_leaf.trie_path[depth];

                branches_to_gossip
                    .entry(TriePathWrapper(trie_path))
                    .or_insert_with_key(|trie_path| {
                        let builder =
                            PortalBranchNodeBuilder::new(branch, &path_to_leaf.trie_path[..depth])
                                .expect("creating PortalBranchNodeBuilder should succeed");
                        let fragment_indices = if new_branch_nodes.contains(&trie_path.0) {
                            HashSet::from_iter((0..PORTAL_NETWORK_NODE_WIDTH as u8).filter(
                                |fragment_index| {
                                    !builder.fragment_commitment(*fragment_index).is_zero()
                                },
                            ))
                        } else {
                            HashSet::new()
                        };
                        BranchNodeBuilderWithFragments {
                            builder,
                            fragment_indices,
                        }
                    })
                    .fragment_indices
                    .insert(child_index / PORTAL_NETWORK_NODE_WIDTH as u8);
            }

            leaves_to_gossip
                .entry(*stem)
                .or_insert_with(|| {
                    let builder = PortalLeafNodeBuilder::new(&path_to_leaf);
                    LeafNodeBuilderWithFragments {
                        stem: *stem,
                        builder,
                        fragment_indices: HashSet::new(),
                    }
                })
                .fragment_indices
                .extend(
                    stem_state_write
                        .writes
                        .keys()
                        .map(|child_index| child_index / PORTAL_NETWORK_NODE_WIDTH as u8)
                        .dedup(),
                );
        }

        for (trie_path, builder_with_fragments) in branches_to_gossip.into_iter() {
            self.gossip_branch_node(trie_path.0, builder_with_fragments, block_hash)
                .await?;
        }

        for builder_with_fragments in leaves_to_gossip.into_values() {
            self.gossip_leaf_node(builder_with_fragments, block_hash)
                .await?;
        }

        println!("Elapsed: {:?}", timer.elapsed());
        Ok(())
    }

    async fn gossip_branch_node(
        &self,
        trie_path: TriePath,
        builder_with_fragments: BranchNodeBuilderWithFragments<'_>,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let BranchNodeBuilderWithFragments {
            builder,
            fragment_indices,
        } = builder_with_fragments;
        println!(
            "  branch: {} {:x?}",
            trie_path.into_iter().map(|i| format!("{i:x}")).join(""),
            fragment_indices.iter().sorted().collect_vec()
        );

        let mut gossip_futures = vec![];

        // Gossip bundle
        let bundle_node = builder.bundle_node_with_proof(block_hash);
        let bundle_key = VerkleContentKey::Bundle(bundle_node.node.commitment().clone());
        let bundle_value =
            VerkleContentValue::NodeWithProof(PortalVerkleNodeWithProof::BranchBundle(bundle_node));
        gossip_futures.push(self.portal_client.gossip(bundle_key, bundle_value));

        // Gossip fragments
        for fragment_index in fragment_indices {
            let fragment_key = VerkleContentKey::BranchFragment(
                builder.fragment_commitment(fragment_index).clone(),
            );
            let fragment_value =
                VerkleContentValue::NodeWithProof(PortalVerkleNodeWithProof::BranchFragment(
                    builder.fragment_node_with_proof(fragment_index, block_hash),
                ));
            gossip_futures.push(self.portal_client.gossip(fragment_key, fragment_value));
        }

        future::try_join_all(gossip_futures).await?;

        Ok(())
    }

    async fn gossip_leaf_node(
        &self,
        builder_with_fragments: LeafNodeBuilderWithFragments<'_>,
        block_hash: B256,
    ) -> anyhow::Result<()> {
        let LeafNodeBuilderWithFragments {
            stem,
            builder,
            fragment_indices,
        } = builder_with_fragments;
        println!(
            "  leaf:   {stem} {:x?}",
            fragment_indices.iter().sorted().collect_vec()
        );

        let mut gossip_futures = vec![];

        // Gossip bundle
        let bundle_node = builder.bundle_node_with_proof(block_hash);
        let bundle_key = VerkleContentKey::Bundle(bundle_node.node.commitment().clone());
        let bundle_value =
            VerkleContentValue::NodeWithProof(PortalVerkleNodeWithProof::LeafBundle(bundle_node));
        gossip_futures.push(self.portal_client.gossip(bundle_key, bundle_value));

        // Gossip fragments
        for fragment_index in fragment_indices {
            let fragment_key = VerkleContentKey::LeafFragment(LeafFragmentKey {
                stem,
                commitment: builder.fragment_commitment(fragment_index).clone(),
            });
            let fragment_value =
                VerkleContentValue::NodeWithProof(PortalVerkleNodeWithProof::LeafFragment(
                    builder.fragment_node_with_proof(fragment_index, block_hash),
                ));
            gossip_futures.push(self.portal_client.gossip(fragment_key, fragment_value));
        }

        future::try_join_all(gossip_futures).await?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("Initializing...");
    let mut gossiper = Gossiper::new(&args)?;

    println!("Starting gossiping");
    let timer = Instant::now();
    gossiper.gossip_genesis().await?;
    for slot in 1..=args.slots {
        gossiper.gossip_slot(slot).await?;
    }
    println!("Finished gossiping in {:?}", timer.elapsed());

    Ok(())
}
