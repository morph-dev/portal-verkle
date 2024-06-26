use alloy_primitives::B256;
use ssz_derive::{Decode, Encode};
use verkle_core::{constants::PORTAL_NETWORK_NODE_WIDTH, Point, Stem, TrieValue};

use super::{sparse_vector::SparseVector, BundleProof, TriePath, TrieProof};

#[derive(Debug, Clone, Encode, Decode)]
pub struct BranchBundleNode {
    pub fragments: SparseVector<Point, PORTAL_NETWORK_NODE_WIDTH>,
    pub proof: BundleProof,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct BranchBundleNodeWithProof {
    pub node: BranchBundleNode,
    pub block_hash: B256,
    pub path: TriePath,
    pub proof: TrieProof,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct BranchFragmentNode {
    pub fragment_index: u8,
    pub children: SparseVector<Point, PORTAL_NETWORK_NODE_WIDTH>,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct BranchFragmentNodeWithProof {
    pub node: BranchFragmentNode,
    pub block_hash: B256,
    pub path: TriePath,
    pub proof: TrieProof,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct LeafBundleNode {
    pub marker: u64,
    pub stem: Stem,
    pub fragments: SparseVector<Point, PORTAL_NETWORK_NODE_WIDTH>,
    pub proof: BundleProof,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct LeafBundleNodeWithProof {
    pub node: LeafBundleNode,
    pub block_hash: B256,
    pub proof: TrieProof,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct LeafFragmentNode {
    pub fragment_index: u8,
    pub children: SparseVector<TrieValue, PORTAL_NETWORK_NODE_WIDTH>,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct LeafFragmentNodeWithProof {
    pub node: LeafFragmentNode,
    pub block_hash: B256,
    pub proof: TrieProof,
}
