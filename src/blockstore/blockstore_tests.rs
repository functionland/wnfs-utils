use libipld::{cbor::DagCborCodec, codec::Encode, IpldCodec};

    use wnfs::common::{BlockStore, CODEC_DAG_CBOR};

    use crate::{blockstore::FFIFriendlyBlockStore, kvstore::KVBlockStore};

    #[tokio::test]
    async fn inserted_items_can_be_fetched() {
        let store = KVBlockStore::new(String::from("./tmp/test1"), CODEC_DAG_CBOR);
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