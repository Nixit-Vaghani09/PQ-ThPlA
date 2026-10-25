use crate::merkle_tree::hash::hash_pair;
use crate::merkle_tree::proof::{MerkleProof,ProofNode};
use std::collections::HashMap;
pub type Hash = [u8; 32];
pub struct MerkleTree {
    pub levels: Vec<Vec<Hash>>,
    pub server_positions: HashMap<u32, usize>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<(u32, Hash)>) -> Self {
        let mut positions = HashMap::new();
        let mut current_level = Vec::new();
        for (index, (server_id, hash)) in leaves.iter().enumerate() {
            positions.insert(*server_id, index);
            current_level.push(*hash);
        }

        let mut levels = vec![current_level.clone()];
        while current_level.len() > 1 {
            if current_level.len() % 2 == 1 {
                let last = *current_level.last().unwrap();
                current_level.push(last);
            }
            let mut next_level = Vec::new();
            for pair in current_level.chunks(2) {
                next_level.push(hash_pair(&pair[0], &pair[1]));
            }

            levels.push(next_level.clone());

            current_level = next_level;
        }
        Self {
            levels,
            server_positions: positions,
        }
    }

    pub fn generate_proof(&self, server_id: u32) -> Option<MerkleProof> {
        let mut index = *self.server_positions.get(&server_id)?;

        let mut nodes = Vec::new();

        for level in &self.levels[..self.levels.len() - 1] {
            let (sibling_index, is_left) = if index % 2 == 0 {
                (index + 1, true)
            } else {
                (index - 1, false) 
            };

            let sibling = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                level[index]
            };

            nodes.push(ProofNode { sibling, is_left });

            index /= 2;
        }

        Some(MerkleProof { nodes })
    }

    pub fn root(&self) -> Hash {
        let root_level = self.levels.last().unwrap();
        root_level[0]
    }
}
