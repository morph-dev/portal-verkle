use std::{array, mem};

use portal_verkle_primitives::{
    constants::{PORTAL_NETWORK_NODE_WIDTH, VERKLE_NODE_WIDTH},
    portal::{BranchBundleNode, BranchFragmentNode},
    ssz::{SparseVector, TriePath},
    Point, ScalarField, Stem, TrieKey, TrieValue, CRS,
};

use crate::{
    types::state_write::StemStateWrite, utils::bundle_proof, verkle_trie::error::VerkleTrieError,
};

use super::{commitment::Commitment, leaf::LeafNode, Node};

pub struct BranchNode {
    depth: usize,
    commitment: Commitment,
    children: [Node; VERKLE_NODE_WIDTH],
}

impl BranchNode {
    pub fn new(depth: usize) -> Self {
        if depth >= Stem::len_bytes() {
            panic!("Invalid branch depth!")
        }
        Self {
            depth,
            commitment: Commitment::zero(),
            children: array::from_fn(|_| Node::Empty),
        }
    }

    pub fn commitment(&self) -> &Point {
        self.commitment.commitment()
    }

    pub fn commitment_hash(&mut self) -> ScalarField {
        self.commitment.commitment_hash()
    }

    pub fn get(&self, key: &TrieKey) -> Option<&TrieValue> {
        let index = key[self.depth] as usize;
        match &self.children[index] {
            Node::Empty => None,
            Node::Branch(branch_node) => branch_node.get(key),
            Node::Leaf(leaf_node) => {
                if key.starts_with_stem(leaf_node.stem()) {
                    leaf_node.get(key.suffix() as usize)
                } else {
                    None
                }
            }
        }
    }

    pub fn insert(&mut self, key: &TrieKey, value: TrieValue) {
        let index = key[self.depth] as usize;
        let child = &mut self.children[index];
        let old_commitment_hash = child.commitment_hash();
        match child {
            Node::Empty => {
                let mut leaf_node = Box::new(LeafNode::new(key.stem()));
                leaf_node.set(key.suffix() as usize, value);
                *child = Node::Leaf(leaf_node);
            }
            Node::Branch(branch_node) => branch_node.insert(key, value),
            Node::Leaf(leaf_node) => {
                if leaf_node.stem() == &key.stem() {
                    leaf_node.set(key.suffix() as usize, value);
                } else {
                    let old_child_index_in_new_branch = leaf_node.stem()[self.depth + 1] as usize;
                    let old_child = mem::replace(child, Node::Empty);

                    let mut branch_node = Box::new(Self::new(self.depth + 1));
                    branch_node.set_child(old_child_index_in_new_branch, old_child);
                    branch_node.insert(key, value);

                    *child = Node::Branch(branch_node);
                }
            }
        }
        self.commitment += CRS::commit_single(
            index as u8,
            &(child.commitment_hash() - old_commitment_hash),
        );
    }

    pub fn get_child(&self, index: usize) -> &Node {
        &self.children[index]
    }

    fn set_child(&mut self, index: usize, mut child: Node) {
        self.commitment += CRS::commit_single(
            index as u8,
            &(child.commitment_hash() - self.children[index].commitment_hash()),
        );
        self.children[index] = child;
    }

    /// Returns the path to the new branch node if one was created.
    pub fn update(
        &mut self,
        state_write: &StemStateWrite,
    ) -> Result<Option<TriePath>, VerkleTrieError> {
        let index = state_write.stem[self.depth] as usize;
        let child = &mut self.children[index];
        let old_commitment_hash = child.commitment_hash();
        let mut path_to_created_branch = None;
        match child {
            Node::Empty => {
                let mut leaf_node = Box::new(LeafNode::new(state_write.stem));
                leaf_node.update(state_write)?;
                *child = Node::Leaf(leaf_node);
            }
            Node::Branch(branch_node) => {
                path_to_created_branch = branch_node.update(state_write)?;
            }
            Node::Leaf(leaf_node) => {
                if leaf_node.stem() == &state_write.stem {
                    leaf_node.update(state_write)?;
                } else {
                    let old_child_index_in_new_branch = leaf_node.stem()[self.depth + 1] as usize;
                    let old_child = mem::replace(child, Node::Empty);

                    let mut branch_node = Box::new(Self::new(self.depth + 1));
                    branch_node.set_child(old_child_index_in_new_branch, old_child);
                    branch_node.update(state_write)?;

                    path_to_created_branch = Some(TriePath::from(
                        state_write.stem[..branch_node.depth].to_vec(),
                    ));
                    *child = Node::Branch(branch_node);
                }
            }
        };
        self.commitment += CRS::commit_single(
            index as u8,
            &(child.commitment_hash() - old_commitment_hash),
        );
        Ok(path_to_created_branch)
    }

    fn get_fragment_commitment(&self, fragment_index: usize) -> Option<Point> {
        let start_index = fragment_index * PORTAL_NETWORK_NODE_WIDTH;
        let mut commitment = Point::zero();
        for fragment_child_index in 0..PORTAL_NETWORK_NODE_WIDTH {
            let index = start_index + fragment_child_index;
            let child_commitment = self.children[index].commitment();
            if !child_commitment.is_zero() {
                commitment +=
                    CRS::commit_single(index as u8, &child_commitment.map_to_scalar_field());
            }
        }
        if commitment.is_zero() {
            None
        } else {
            Some(commitment)
        }
    }

    pub fn extract_bundle_node(&self) -> BranchBundleNode {
        let fragment_commitments = SparseVector::new(array::from_fn(|fragment_index| {
            self.get_fragment_commitment(fragment_index)
        }));
        let bundle_proof = bundle_proof(&fragment_commitments);
        BranchBundleNode::new(fragment_commitments, bundle_proof)
    }

    pub fn extract_fragment_node(&self, fragment_index: usize) -> (Point, BranchFragmentNode) {
        let fragment_commitment = self
            .get_fragment_commitment(fragment_index)
            .unwrap_or_else(Point::zero);
        let children = SparseVector::new(array::from_fn(|fragment_child_index| {
            let child_index = fragment_index * PORTAL_NETWORK_NODE_WIDTH + fragment_child_index;
            let commitment = self.children[child_index].commitment();
            if commitment.is_zero() {
                None
            } else {
                Some(commitment)
            }
        }));
        let fragment_node = BranchFragmentNode::new(fragment_index as u8, children);
        (fragment_commitment, fragment_node)
    }
}
