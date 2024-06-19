use std::array;

use banderwagon::{Element, Fr, PrimeField, Zero};
use verkle_core::{
    constants::{
        EXTENSION_C1_INDEX, EXTENSION_C2_INDEX, EXTENSION_MARKER_INDEX, EXTENSION_STEM_INDEX,
        VERKLE_NODE_WIDTH,
    },
    msm::{DefaultMsm, MultiScalarMultiplicator},
    Stem, TrieValue,
};

pub struct LeafNode {
    marker: u64,
    stem: Stem,
    commitment: Element,
    c1: Element,
    c2: Element,
    children: [Option<TrieValue>; VERKLE_NODE_WIDTH],
}

impl LeafNode {
    pub fn new(stem: Stem) -> Self {
        Self::new_with_childrent(stem, array::from_fn(|_| None))
    }

    pub fn new_with_childrent(
        stem: Stem,
        children: [Option<TrieValue>; VERKLE_NODE_WIDTH],
    ) -> Self {
        let (children_first_half, children_second_half) = children.split_at(VERKLE_NODE_WIDTH / 2);

        let suffix_commitment = |suffix_children: &[Option<TrieValue>]| {
            DefaultMsm.commit_sparse(
                suffix_children
                    .iter()
                    .enumerate()
                    .filter_map(|(suffix_index, child)| {
                        child.as_ref().map(|child| (suffix_index, child))
                    })
                    .flat_map(|(suffix_index, child)| {
                        let (low_value, high_value) = child.split();
                        [
                            (2 * suffix_index, low_value),
                            (2 * suffix_index + 1, high_value),
                        ]
                    })
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
        };

        let c1 = suffix_commitment(children_first_half);
        let c2 = suffix_commitment(children_second_half);

        let marker = 1; // Extension marker
        let commitment = DefaultMsm.commit_sparse(&[
            (EXTENSION_MARKER_INDEX, Fr::from(marker)),
            (
                EXTENSION_STEM_INDEX,
                Fr::from_le_bytes_mod_order(stem.as_slice()),
            ),
            (EXTENSION_C1_INDEX, c1.map_to_scalar_field()),
            (EXTENSION_C2_INDEX, c2.map_to_scalar_field()),
        ]);

        Self {
            marker,
            stem,
            commitment,
            c1,
            c2,
            children,
        }
    }

    pub fn version(&self) -> u64 {
        self.marker
    }

    pub fn stem(&self) -> &Stem {
        &self.stem
    }

    pub fn commitment(&self) -> Element {
        self.commitment
    }

    pub fn commitment_hash(&self) -> Fr {
        self.commitment.map_to_scalar_field()
    }

    pub fn set(&mut self, index: usize, child: TrieValue) {
        let (new_low_value, new_high_value) = child.split();
        let (old_low_value, old_high_value) = self.children[index]
            .replace(child)
            .map_or_else(|| (Fr::zero(), Fr::zero()), |old_child| old_child.split());

        let suffix_index = index % (VERKLE_NODE_WIDTH / 2);
        let suffix_commitment_diff = DefaultMsm
            .scalar_mul(2 * suffix_index, new_low_value - old_low_value)
            + DefaultMsm.scalar_mul(2 * suffix_index + 1, new_high_value - old_high_value);

        if index < VERKLE_NODE_WIDTH / 2 {
            self.c1 += suffix_commitment_diff;
            self.commitment +=
                DefaultMsm.scalar_mul(EXTENSION_C1_INDEX, self.c1.map_to_scalar_field());
        } else {
            self.c2 += suffix_commitment_diff;
            self.commitment +=
                DefaultMsm.scalar_mul(EXTENSION_C2_INDEX, self.c2.map_to_scalar_field());
        }
    }

    pub fn get(&self, index: usize) -> Option<&TrieValue> {
        self.children[index].as_ref()
    }
}
