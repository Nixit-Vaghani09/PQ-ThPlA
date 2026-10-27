use crate::threshold::server_share::ServerShare;
use rand::rngs::OsRng;
use sharks::{Share, Sharks};

#[derive(Clone, Debug)]
pub struct ThresholdConfig {
    n: usize,
    t: usize,
}

impl ThresholdConfig {
    pub fn new(n: usize, t: usize) -> Self {
        assert!(t > 0);
        assert!(t <= n);

        Self { n, t }
    }

    pub fn n(&self) -> usize {
        self.n
    }

    pub fn t(&self) -> usize {
        self.t
    }
}

pub fn generate_server_shares(secret: &[u8], n: usize, t: usize) -> Vec<ServerShare> {
    assert!(t > 0);
    assert!(t <= n);

    let sharks = Sharks(u8::try_from(t).expect("threshold exceeds u8"));
    let dealer = sharks.dealer(secret);
    dealer
        .take(n)
        .enumerate()
        .map(|(index, share)| {
            let share_bytes: Vec<u8> = Vec::from(&share);
            ServerShare::new((index + 1) as u32, share_bytes)
        })
        .collect()
}
