use std::{fs::File, io::BufReader, path::Path};

use portal_verkle_primitives::{
    constants::PORTAL_NETWORK_NODE_WIDTH,
    proof::{BundleProof, IpaProof, MultiPointProof},
    ssz::SparseVector,
    Point, ScalarField,
};
use ssz_types::FixedVector;

use crate::{paths::genesis_path, types::genesis::GenesisConfig};

pub fn read_genesis() -> anyhow::Result<GenesisConfig> {
    read_genesis_from_file(genesis_path())
}

#[cfg(test)]
pub fn read_genesis_for_test() -> anyhow::Result<GenesisConfig> {
    use crate::paths::test_path;

    read_genesis_from_file(test_path(genesis_path()))
}

fn read_genesis_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<GenesisConfig> {
    let reader = BufReader::new(File::open(path)?);
    Ok(serde_json::from_reader(reader)?)
}

pub fn bundle_proof(
    _fragment_commitments: &SparseVector<Point, PORTAL_NETWORK_NODE_WIDTH>,
) -> BundleProof {
    // TODO: add implementation
    BundleProof::new(dummy_multiproof())
}

pub fn dummy_multiproof() -> MultiPointProof {
    // TODO: add implementation
    MultiPointProof {
        ipa_proof: IpaProof {
            cl: FixedVector::from_elem(Point::zero()),
            cr: FixedVector::from_elem(Point::zero()),
            final_evaluation: ScalarField::zero(),
        },
        g_x: Point::zero(),
    }
}
