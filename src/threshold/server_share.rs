#[derive(Clone,Debug)]
pub struct ServerShare {
     server_id: u32,
     share: Vec<u8>,
}


impl ServerShare {
    pub fn new(server_id: u32,share: Vec<u8>,) -> Self {
        Self {
            server_id,
            share,

        }
    }


}