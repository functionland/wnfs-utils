use kv::*;
use libipld::{
    IpldCodec,
};
use anyhow::Result;


use wnfs::FsError;

use crate::blockstore::FFIStore;

pub struct KVBlockStore{
    pub store: Store,
    pub codec: IpldCodec
} 

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl KVBlockStore {
    /// Creates a new kv block store.
    pub fn new(db_path: String, codec: IpldCodec) -> Self {
        // Configure the database
        // Open the key/value store
        Self{
            store: Store::new(Config::new(db_path)).unwrap(),
            codec
        }
    }

}


impl<'a> FFIStore<'a> for KVBlockStore {
    /// Retrieves an array of bytes from the block store with given CID.
    fn get_block(&self, cid: Vec<u8>) -> Result<Vec<u8>>{
        // A Bucket provides typed access to a section of the key/value store
        let bucket = self.store.bucket::<Raw, Raw>(Some("default"))?;

        let bytes = bucket
            .get(&Raw::from(cid))
            .map_err(|_| FsError::CIDNotFoundInBlockstore)?.unwrap().to_vec();
        Ok(bytes)
    }

    /// Stores an array of bytes in the block store.
    fn put_block(&self, cid: Vec<u8>, bytes: Vec<u8>) -> Result<Vec<u8>>{
        let key = Raw::from(cid.to_owned());
        let value = Raw::from(bytes);
        // A Bucket provides typed access to a section of the key/value store
        let bucket = self.store.bucket::<Raw, Raw>(Some("default"))?;

        bucket.set(&key, &value)?;
        Ok(cid)
    }
}
