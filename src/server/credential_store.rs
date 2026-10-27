use std::collections::HashMap;

use crate::server::credential::StoredCredential;


pub struct CredentialStore {

    credentials:
        HashMap<String, StoredCredential>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials:
            HashMap:: new(),
        }
    }

    pub fn insert(&mut self,credential: StoredCredential,)
    {
        self.credentials.insert(
            credential.user_id.clone(),
            credential,
        );
    }

    pub fn get(&self,user_id: &str,) -> Option<&StoredCredential>{
        self.credentials.get(user_id)
    }

    pub fn remove(&mut self,user_id:&str,) -> Option<StoredCredential>{
        self.credentials.remove(user_id)
    }

    pub fn contains(&self,user_id:&str) -> bool {
        self.credentials.contains_key(user_id)
    }
}