use std::time::Duration;

use alloy_primitives::B256;
use anyhow::bail;
use ethportal_api::{
    types::{content_key::verkle::LeafFragmentKey, verkle::ContentInfo},
    ContentValue, OverlayContentKey, VerkleContentKey, VerkleContentValue, VerkleNetworkApiClient,
};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use portal_verkle_primitives::{
    constants::PORTAL_NETWORK_NODE_WIDTH,
    portal::PortalVerkleNode,
    verkle::{StateWrites, StemStateWrite, VerkleTrie},
    Point,
};

pub struct StateTrieFetcher {
    portal_client: HttpClient,
}

impl StateTrieFetcher {
    pub fn new(portal_rpc_url: &str) -> anyhow::Result<StateTrieFetcher> {
        let portal_client = HttpClientBuilder::new()
            .request_timeout(Duration::from_secs(60))
            .build(portal_rpc_url)?;
        Ok(Self { portal_client })
    }

    pub async fn fetch_state_trie(&self, state_root: B256) -> anyhow::Result<VerkleTrie> {
        let mut trie = VerkleTrie::new();
        let mut stack = vec![VerkleContentKey::Bundle(Point::from(&state_root))];

        while let Some(key) = stack.pop() {
            let value = self.fetch_content(&key).await?;
            match &value {
                VerkleContentValue::Node(PortalVerkleNode::BranchBundle(node)) => {
                    let VerkleContentKey::Bundle(key_commitment) = &key else {
                        bail!(
                            "Invalid BranchBundle value received! key: {}, value: {}",
                            key.to_hex(),
                            value.to_hex()
                        )
                    };
                    node.verify(key_commitment)?;

                    for commitment in node.fragments().iter_set_items() {
                        stack.push(VerkleContentKey::BranchFragment(commitment.clone()));
                    }
                }
                VerkleContentValue::Node(PortalVerkleNode::LeafBundle(node)) => {
                    let VerkleContentKey::Bundle(key_commitment) = &key else {
                        bail!(
                            "Invalid LeafBundle value received! key: {}, value: {}",
                            key.to_hex(),
                            value.to_hex()
                        )
                    };
                    node.verify(key_commitment)?;

                    for commitment in node.fragments().iter_set_items() {
                        stack.push(VerkleContentKey::LeafFragment(LeafFragmentKey {
                            stem: *node.stem(),
                            commitment: commitment.clone(),
                        }));
                    }
                }
                VerkleContentValue::Node(PortalVerkleNode::BranchFragment(node)) => {
                    let VerkleContentKey::BranchFragment(key_commitment) = &key else {
                        bail!(
                            "Invalid BranchFragment value received! key: {}, value: {}",
                            key.to_hex(),
                            value.to_hex()
                        )
                    };
                    node.verify(key_commitment)?;

                    for commitment in node.children().iter_set_items() {
                        stack.push(VerkleContentKey::Bundle(commitment.clone()));
                    }
                }
                VerkleContentValue::Node(PortalVerkleNode::LeafFragment(node)) => {
                    let VerkleContentKey::LeafFragment(leaf_fragment_key) = &key else {
                        bail!(
                            "Invalid LeafFragment value received! key: {}, value: {}",
                            key.to_hex(),
                            value.to_hex()
                        )
                    };
                    node.verify(&leaf_fragment_key.commitment)?;

                    let start_index = node.fragment_index() as usize * PORTAL_NETWORK_NODE_WIDTH;
                    let stem_state_write = StemStateWrite {
                        stem: leaf_fragment_key.stem,
                        writes: node
                            .children()
                            .iter_enumerated_set_items()
                            .map(|(child_index, value)| ((start_index + child_index) as u8, *value))
                            .collect(),
                    };
                    trie.update(&StateWrites::new(vec![stem_state_write]));
                }
                _ => bail!("Invalid content value received: {}", value.to_hex()),
            }
        }
        Ok(trie)
    }

    async fn fetch_content(&self, key: &VerkleContentKey) -> anyhow::Result<VerkleContentValue> {
        let content_info = self
            .portal_client
            .recursive_find_content(key.clone())
            .await?;
        let ContentInfo::Content { content, .. } = content_info else {
            bail!("Couldn't find content for key: {}", key.to_hex())
        };
        Ok(*content)
    }
}
