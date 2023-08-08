use wnfs::common::CODEC_DAG_CBOR;

use crate::blockstore::FFIFriendlyBlockStore;
use crate::kvstore::KVBlockStore;
use crate::private_forest::PrivateDirectoryHelper;

fn generate_dummy_data(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

#[tokio::test]
async fn test_parse_path() {
    let path = "root/test.txt".to_string();
    let out = PrivateDirectoryHelper::parse_path(path);
    assert_eq!(out[0], "root".to_string());
    assert_eq!(out[1], "test.txt".to_string());
}

#[tokio::test]
async fn iboverall() {
    let empty_key: Vec<u8> = vec![0; 32];
    let store = KVBlockStore::new(String::from("./tmp/test2"), CODEC_DAG_CBOR);
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));
    let (helper, access_key, cid) =
        &mut PrivateDirectoryHelper::init(blockstore, empty_key.to_owned())
            .await
            .unwrap();

    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());
    let cid = helper
        .write_file(
            &["root".into(), "hello".into(), "world.txt".into()],
            b"hello, world!".to_vec(),
            0,
        )
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);
    let ls_result = helper.ls_files(&["root".into()]).await;
    println!("ls: {:?}", ls_result);
    let cid = helper.mkdir(&["root".into(), "hi".into()]).await.unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);
    let ls_result = helper.ls_files(&["root".into()]).await.unwrap();
    assert_eq!(ls_result.get(0).unwrap().0, "hello");
    assert_eq!(ls_result.get(1).unwrap().0, "hi");
    let content = helper
        .read_file(&["root".into(), "hello".into(), "world.txt".into()])
        .await
        .unwrap();
    assert_eq!(content, b"hello, world!".to_vec());
    let cid = helper
        .rm(&["root".into(), "hello".into(), "world.txt".into()])
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());
    let content = helper
        .read_file(&["root".into(), "hello".into(), "world.txt".into()])
        .await;
    assert_eq!(content.ok(), None);
    println!("**************************reload test*****************");
    let helper_reloaded = &mut PrivateDirectoryHelper::reload(blockstore, cid)
        .await
        .unwrap();
    let cid_reloaded = helper_reloaded
        .write_file(
            &["root".into(), "hello2".into(), "world.txt".into()],
            b"hello, world2!".to_vec(),
            0,
        )
        .await
        .unwrap();

    let ls_result_reloaded = helper_reloaded.ls_files(&["root".into()]).await.unwrap();
    println!("ls_result_reloaded: {:?}", ls_result_reloaded);
    assert_eq!(ls_result_reloaded.get(0).unwrap().0, "hello");
    assert_eq!(ls_result_reloaded.get(2).unwrap().0, "hi");
    assert_eq!(ls_result_reloaded.get(1).unwrap().0, "hello2");
    println!("cid_reloaded: {:?}", cid_reloaded);

    // let last_root_dir = helper
    //     .get_root_dir(forest.to_owned(), access_key.to_owned())
    //     .await
    //     .unwrap();
    // let last_access_key = helper.get_access_key(empty_key, cid).await.unwrap();
    // println!("access_key: {:?}", access_key.to_owned());
    // println!("last_access_key: {:?}", last_access_key.to_owned());
    // assert_eq!(last_access_key.to_owned(), access_key.to_owned())
}

#[tokio::test]
async fn serialize_access_key() {
    let empty_key: Vec<u8> = vec![0; 32];
    let store = KVBlockStore::new(String::from("./tmp/test3"), CODEC_DAG_CBOR);
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));
    let (_, access_key, cid) = PrivateDirectoryHelper::init(blockstore, empty_key.to_owned())
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    let access_key_serialized = serde_json::to_string(&access_key).unwrap();
    println!("private ref: \n{}", access_key_serialized);
}

#[tokio::test]
async fn test_large_file_write() {
    let empty_key: Vec<u8> = vec![0; 32];
    let store = KVBlockStore::new(String::from("./tmp/test2"), CODEC_DAG_CBOR);
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));
    let (helper, access_key, cid) =
        &mut PrivateDirectoryHelper::init(blockstore, empty_key.to_owned())
            .await
            .unwrap();

    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());

    // Generate a dummy 600MB payload
    let data = generate_dummy_data(1000 * 1024 * 1024); // 1000MB in bytes

    let path = vec!["root".into(), "large_file.bin".into()];
    let cid = helper.write_file(&path, data.to_owned(), 0).await.unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert_eq!(ls_result.get(0).unwrap().0, "large_file.bin");

    let content = helper
        .read_file(&["root".into(), "large_file.bin".into()])
        .await
        .unwrap();
    assert_eq!(content, data);

    let cid = helper
        .write_file(
            &["root".into(), "world.txt".into()],
            b"hello, world!".to_vec(),
            0,
        )
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert_eq!(ls_result.get(0).unwrap().0, "large_file.bin");
    assert_eq!(ls_result.get(1).unwrap().0, "world.txt");

    let content = helper
        .read_file(&["root".into(), "world.txt".into()])
        .await
        .unwrap();
    assert_eq!(content, b"hello, world!".to_vec());
}