use std::{borrow::Cow};
use libipld::{
    cid::Version,
    Cid, IpldCodec,
};
use anyhow::Result;
use async_trait::async_trait;
use multihash::{Code, MultihashDigest};

use wnfs::FsError;
use wnfs::BlockStore;

pub trait FFIStore {
    fn get_block(&self, cid: Vec<u8>) -> Result<Vec<u8>>;
    fn put_block(&self, cid: Vec<u8>, bytes: Vec<u8>) -> Result<Vec<u8>>;
}

pub struct FFIFriendlyBlockStore{
    pub ffi_store: Box<dyn FFIStore>
} 

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl FFIFriendlyBlockStore {
    /// Creates a new kv block store.
    pub fn new(ffi_store: Box<dyn FFIStore>) -> Self
    {
        Self{
            ffi_store
        }
    }
}


#[async_trait(?Send)]
impl BlockStore for FFIFriendlyBlockStore {
    /// Retrieves an array of bytes from the block store with given CID.
    async fn get_block<'a>(&'a self, cid: &Cid) -> Result<Cow<'a, Vec<u8>>> {
        let bytes = self.ffi_store.get_block(cid.to_bytes())
            .map_err(|_| FsError::CIDNotFoundInBlockstore)?;
        Ok(Cow::Owned(bytes))
    }

    /// Stores an array of bytes in the block store.
    async fn put_block(&mut self, bytes: Vec<u8>, codec: IpldCodec) -> Result<Cid> {
        let hash = Code::Sha2_256.digest(&bytes);
        let cid = Cid::new(Version::V1, codec.into(), hash)?;
        self.ffi_store.put_block(cid.to_bytes(), bytes)?;
        Ok(cid)
    }
}



//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod blockstore_tests {
    use libipld::{cbor::DagCborCodec, codec::Encode, IpldCodec};

    use wnfs::*;

    use crate::{kvstore::KVBlockStore, blockstore::FFIFriendlyBlockStore};

    #[async_std::test]
    async fn inserted_items_can_be_fetched() {
        let store = KVBlockStore::new(String::from("./tmp/test1"), IpldCodec::DagCbor);
        let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));
        let first_bytes = {
            let mut tmp = vec![];
            vec![1, 2, 3, 4, 5]
                .to_vec()
                .encode(DagCborCodec, &mut tmp)
                .unwrap();
            tmp
        };

        let second_bytes = {
            let mut tmp = vec![];
            b"hello world"
                .to_vec()
                .encode(DagCborCodec, &mut tmp)
                .unwrap();
            tmp
        };

        let first_cid = &blockstore
            .put_block(first_bytes, IpldCodec::DagCbor)
            .await
            .unwrap();

        let second_cid = &blockstore
            .put_block(second_bytes, IpldCodec::DagCbor)
            .await
            .unwrap();

        let first_loaded: Vec<u8> = blockstore.get_deserializable(first_cid).await.unwrap();
        let second_loaded: Vec<u8> = blockstore.get_deserializable(second_cid).await.unwrap();

        assert_eq!(first_loaded, vec![1, 2, 3, 4, 5]);
        assert_eq!(second_loaded, b"hello world".to_vec());
    }
}
