#[derive(Clone,Debug)]
pub struct AuthRequest {
    pub user_id:String,
    pub session_id:String,
}

impl AuthRequest {
    pub fn new(user_id: String,session_id:String) -> Self {
        Self {
            user_id,
            session_id,
        }
    }
}