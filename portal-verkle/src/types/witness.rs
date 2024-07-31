use std::collections::HashMap;

use alloy_primitives::{Bytes, U8};
use portal_verkle_primitives::{proof::IpaProof, verkle::StemStateWrite, Point, Stem, TrieValue};
use serde::{Deserialize, Serialize};
use serde_nested_with::serde_nested;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuffixStateDiff {
    pub suffix: U8,
    #[serde(alias = "currentValue")]
    pub current_value: Option<TrieValue>,
    #[serde(alias = "newValue")]
    pub new_value: Option<TrieValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StemStateDiff {
    pub stem: Stem,
    #[serde(alias = "suffixDiffs")]
    pub suffix_diffs: Vec<SuffixStateDiff>,
}

pub type StateDiff = Vec<StemStateDiff>;

#[serde_nested]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerkleProof {
    #[serde(alias = "otherStems")]
    pub other_stems: Vec<Stem>,
    #[serde(alias = "depthExtensionPresent")]
    pub depth_extension_present: Bytes,
    #[serde(alias = "commitmentsByPath")]
    pub commitments_by_path: Vec<Point>,
    pub d: Point,
    #[serde(alias = "ipaProof")]
    pub ipa_proof: IpaProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionWitness {
    #[serde(alias = "stateDiff")]
    pub state_diff: StateDiff,
    #[serde(alias = "verkleProof")]
    pub verkle_proof: VerkleProof,
}

impl StemStateDiff {
    pub fn into_stem_state_write(self) -> Option<StemStateWrite> {
        let writes = self
            .suffix_diffs
            .into_iter()
            .flat_map(|suffix_state_diff| {
                suffix_state_diff
                    .new_value
                    .map(|value| (suffix_state_diff.suffix.byte(0), value))
            })
            .collect::<HashMap<_, _>>();
        if writes.is_empty() {
            None
        } else {
            Some(StemStateWrite {
                stem: self.stem,
                writes,
            })
        }
    }
}
