use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use portal_verkle_primitives::verkle::genesis_config::GenesisConfig;

pub const TESTNET_DATA_PATH: &str = "data/verkle-devnet-6/";

#[cfg(test)]
pub fn test_path<P: AsRef<std::path::Path>>(path: P) -> PathBuf {
    PathBuf::from("..").join(path)
}

pub fn beacon_slot_path(slot: u64) -> PathBuf {
    PathBuf::from(TESTNET_DATA_PATH).join(format!("beacon/slot.{slot}.json"))
}

// Genesis

fn genesis_path() -> PathBuf {
    PathBuf::from(TESTNET_DATA_PATH).join("genesis.json")
}

fn read_genesis_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<GenesisConfig> {
    let reader = BufReader::new(File::open(path)?);
    Ok(serde_json::from_reader(reader)?)
}

pub fn read_genesis() -> anyhow::Result<GenesisConfig> {
    read_genesis_from_file(genesis_path())
}

#[cfg(test)]
pub fn read_genesis_for_test() -> anyhow::Result<GenesisConfig> {
    read_genesis_from_file(test_path(genesis_path()))
}
