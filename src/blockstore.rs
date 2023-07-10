use std::rc::Rc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

use libipld::Cid;
use wnfs::common::{BlockStore, BlockStoreError};

pub trait FFIStore<'a> {
    fn get_block<'b>(&'b self, cid: Vec<u8>) -> Result<Vec<u8>>;
    fn put_block<'b>(&'b self, cid: Vec<u8>, bytes: Vec<u8>) -> Result<()>;
}

#[derive(Clone)]
pub struct FFIFriendlyBlockStore<'a> {
    pub ffi_store: Rc<dyn FFIStore<'a>>,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl<'a> FFIFriendlyBlockStore<'a> {
    /// Creates a new kv block store.
    pub fn new(ffi_store: Rc<dyn FFIStore<'a>>) -> Self {
        Self { ffi_store }
    }
}

#[async_trait(?Send)]
impl<'b> BlockStore for FFIFriendlyBlockStore<'b> {
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
mod blockstore_tests {
    use std::rc::Rc;

    use libipld::{cbor::DagCborCodec, codec::Encode, IpldCodec};

    use wnfs::common::{BlockStore, CODEC_DAG_CBOR};

    use crate::{blockstore::FFIFriendlyBlockStore, kvstore::KVBlockStore};

    #[tokio::test]
    async fn inserted_items_can_be_fetched() {
        let store = KVBlockStore::new(String::from("./tmp/test1"), CODEC_DAG_CBOR);
        let blockstore = &mut FFIFriendlyBlockStore::new(Rc::new(store));
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
            .put_block(first_bytes, IpldCodec::DagCbor.into())
            .await
            .unwrap();

        let second_cid = &blockstore
            .put_block(second_bytes, IpldCodec::DagCbor.into())
            .await
            .unwrap();

        let first_loaded: Vec<u8> = blockstore.get_deserializable(first_cid).await.unwrap();
        let second_loaded: Vec<u8> = blockstore.get_deserializable(second_cid).await.unwrap();

        assert_eq!(first_loaded, vec![1, 2, 3, 4, 5]);
        assert_eq!(second_loaded, b"hello world".to_vec());
    }
}
