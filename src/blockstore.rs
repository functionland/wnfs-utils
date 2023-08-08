use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

use libipld::Cid;
use wnfs::common::{BlockStore, BlockStoreError};

pub trait FFIStore<'a>: FFIStoreClone<'a> {
    fn get_block(&self, cid: Vec<u8>) -> Result<Vec<u8>>;
    fn put_block(&self, cid: Vec<u8>, bytes: Vec<u8>) -> Result<()>;
}

pub trait FFIStoreClone<'a> {
    fn clone_box(&self) -> Box<dyn FFIStore<'a> + 'a>;
}

impl<'a, T> FFIStoreClone<'a> for T
where
    T: 'a + FFIStore<'a> + Clone,
{
    fn clone_box(&self) -> Box<dyn FFIStore<'a> + 'a> {
        Box::new(self.clone())
    }
}

impl<'a> Clone for Box<dyn FFIStore<'a> + 'a> {
    fn clone(&self) -> Box<dyn FFIStore<'a> + 'a> {
        self.clone_box()
    }
}

#[derive(Clone)]
pub struct FFIFriendlyBlockStore<'a> {
    pub ffi_store: Box<dyn FFIStore<'a> + 'a>,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<'a> FFIFriendlyBlockStore<'a> {
    /// Creates a new kv block store.
    pub fn new(ffi_store: Box<dyn FFIStore<'a> + 'a>) -> Self {
        Self { ffi_store }
    }
}

#[async_trait(?Send)]
impl<'a> BlockStore for FFIFriendlyBlockStore<'a> {
    /// Retrieves an array of bytes from the block store with given CID.
    async fn get_block(&self, cid: &Cid) -> Result<Bytes> {
        let bytes = self
            .ffi_store
            .get_block(cid.to_bytes())
            .map_err(|_| BlockStoreError::CIDNotFound(*cid))?;
        Ok(Bytes::copy_from_slice(&bytes))
    }

    /// Stores an array of bytes in the block store.
    async fn put_block(&self, bytes: impl Into<Bytes>, codec: u64) -> Result<Cid> {
        let data: Bytes = bytes.into();

        let cid_res = self.create_cid(&data, codec);
        match cid_res.is_err() {
            true => Err(cid_res.err().unwrap()),
            false => {
                let cid = cid_res.unwrap();
                let result = self
                    .ffi_store
                    .put_block(cid.to_owned().to_bytes(), data.to_vec());
                match result {
                    Ok(_) => Ok(cid.to_owned()),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod blockstore_tests;
