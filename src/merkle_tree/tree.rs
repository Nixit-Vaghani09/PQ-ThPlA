use std::collections::HashMap;
use crate::merkle_tree::hash::{hash_pair};
pub type Hash = [u8;32];
pub struct MerkleTree {
    pub levels: Vec<Vec<Hash>>,
    pub server_positions: HashMap<u32,usize>,
}

impl MerkleTree {
    pub fn new(
        leaves: Vec<(u32,Hash)>
    ) -> Self {
        let mut positions = HashMap::new();
        let mut current_level = Vec::new();
        for (index, (server_id,hash)) in leaves.iter().enumerate()
        {
            positions.insert(*server_id,index);
            current_level.push(*hash);
        }

        let mut levels = vec![current_level.clone()];
        while current_level.len() > 1 {
            if current_level.len() % 2 == 1 {
                let last = *current_level.last().unwrap();
                current_level.push(last);
            }
            let mut next_level = Vec::new();
            for pair in current_level.chunks(2)
            {
                next_level.push(
                    hash_pair(
                        &pair[0],
                        &pair[1]
                    )
                );
            }

            levels.push(next_level.clone());

            current_level = next_level;
        }
        Self {
            levels,
            server_positions: positions,
        }
    }


}

