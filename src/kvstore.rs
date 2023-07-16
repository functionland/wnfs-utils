use kv::*;

use anyhow::Result;
use libipld::Cid;

use wnfs::common::BlockStoreError;

use crate::blockstore::FFIStore;

#[derive(Clone)]
pub struct KVBlockStore {
    pub store: Store,
    pub codec: u64,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl KVBlockStore {
    /// Creates a new kv block store.
    pub fn new(db_path: String, codec: u64) -> Self {
        // Configure the database
        // Open the key/value store
        Self {
            store: Store::new(Config::new(db_path)).unwrap(),
            codec,
        }
    }
}

impl FFIStore for KVBlockStore {
    /// Retrieves an array of bytes from the block store with given CID.
    fn get_block(&self, cid: Vec<u8>) -> Result<Vec<u8>> {
        // A Bucket provides typed access to a section of the key/value store
        let bucket = self.store.bucket::<Raw, Raw>(Some("default"))?;

        let bytes = bucket
            .get(&Raw::from(cid.to_owned()))
            .map_err(|_| BlockStoreError::CIDNotFound(Cid::try_from(cid).unwrap()))?
            .unwrap()
            .to_vec();
        Ok(bytes)
    }

    /// Stores an array of bytes in the block store.
    fn put_block(&self, cid: Vec<u8>, bytes: Vec<u8>) -> Result<()> {
        let key = Raw::from(cid.to_owned());
        let value = Raw::from(bytes);

        // A Bucket provides typed access to a section of the key/value store
        let bucket = self.store.bucket::<Raw, Raw>(Some("default"))?;

        bucket.set(&key, &value)?;
        Ok(())
    }
}
