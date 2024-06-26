use std::{array, mem};

use verkle_core::{
    constants::VERKLE_NODE_WIDTH,
    msm::{DefaultMsm, MultiScalarMultiplicator},
    Point, ScalarField, Stem, TrieKey, TrieValue,
};

use crate::{types::state_write::StemStateWrite, verkle_trie::error::VerkleTrieError};

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
        self.commitment +=
            DefaultMsm.scalar_mul(index, child.commitment_hash() - old_commitment_hash);
    }

    pub fn get_child(&self, index: usize) -> &Node {
        &self.children[index]
    }

    fn set_child(&mut self, index: usize, mut child: Node) {
        self.commitment += DefaultMsm.scalar_mul(
            index,
            child.commitment_hash() - self.children[index].commitment_hash(),
        );
        self.children[index] = child;
    }

    pub fn update(&mut self, state_write: &StemStateWrite) -> Result<(), VerkleTrieError> {
        let index = state_write.stem[self.depth] as usize;
        let child = &mut self.children[index];
        let old_commitment_hash = child.commitment_hash();
        match child {
            Node::Empty => {
                let mut leaf_node = Box::new(LeafNode::new(state_write.stem));
                leaf_node.update(state_write)?;
                *child = Node::Leaf(leaf_node);
            }
            Node::Branch(branch_node) => branch_node.update(state_write)?,
            Node::Leaf(leaf_node) => {
                if leaf_node.stem() == &state_write.stem {
                    leaf_node.update(state_write)?;
                } else {
                    let old_child_index_in_new_branch = leaf_node.stem()[self.depth + 1] as usize;
                    let old_child = mem::replace(child, Node::Empty);

                    let mut branch_node = Box::new(Self::new(self.depth + 1));
                    branch_node.set_child(old_child_index_in_new_branch, old_child);
                    branch_node.update(state_write)?;

                    *child = Node::Branch(branch_node);
                }
            }
        };
        self.commitment +=
            DefaultMsm.scalar_mul(index, child.commitment_hash() - old_commitment_hash);
        Ok(())
    }
}
