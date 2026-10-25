use crate::merkle_tree::hash::sha3_hash;
pub struct MerkltTree {
    pub leaves: Vec<Vec<u8>>,
    pub root: Vec<u8>,
}

pub fn build_merkle_root(mut leaves: Vec<Vec<u8>>) -> Vec<u8> {
    if leaves.is_empty() {
        return vec![];
    }

    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            let last = leaves.last().unwrap().clone();
            leaves.push(last);
        }

        let mut next_level = Vec::new();

        for chunk in leaves.chunks(2) {
            let mut combined = Vec::new();
            combined.extend(&chunk[0]);
            combined.extend(&chunk[1]);

            next_level.push(sha3_hash(&combined));
        }
        leaves = next_level;
    }
    leaves[0].clone()
}
