use crate::merkle_tree::tree::Hash;
use crate::merkle_tree::hash::hash_pair;

#[derive(Clone, Debug)]
pub struct ProofNode {
    pub sibling: Hash,
    pub is_left: bool,
}

#[derive(Clone,Debug)]
pub struct MerkleProof {
    pub nodes: Vec<ProofNode>,
}


pub fn verify_proof(leaf: Hash,proof: &MerkleProof,root: Hash) -> bool {
    let mut current = leaf;

    for node in &proof.nodes {
        current = 
        if node.is_left {
            hash_pair(&node.sibling,&current)
        } else {
            hash_pair(&current,&node.sibling)
        };
    }
    current == root
}