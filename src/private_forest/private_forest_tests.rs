use wnfs::common::CODEC_DAG_CBOR;

use crate::blockstore::FFIFriendlyBlockStore;
use crate::kvstore::KVBlockStore;
use crate::private_forest::PrivateDirectoryHelper;
use libipld::Cid;
use rand::RngCore;
use std::fs::{read, File};
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use tempfile::NamedTempFile;

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
async fn test_stream() {
    let empty_key: Vec<u8> = vec![0; 32];
    let store = KVBlockStore::new(String::from("./tmp/test_stream"), CODEC_DAG_CBOR);
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));
    let (helper, access_key, cid) =
        &mut PrivateDirectoryHelper::init(blockstore, empty_key.to_owned())
            .await
            .unwrap();

    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());

    let filename = "./tmp/test_file";
    let read_filename = "./tmp/test_read_file";
    let file_size = 10 * 1024 * 1024; // 10 MB
    let path_segments: Vec<String> = vec!["root".to_string(), "stream.bin".to_string()];

    // Create the directory if it doesn't exist
    std::fs::create_dir_all("./tmp").unwrap();

    // Create a test file of the desired size
    let mut file = File::create(filename).unwrap();
    file.write_all(&vec![0u8; file_size]).unwrap();

    // Call the write method
    let write_res = helper
        .write_file_stream_from_path(&path_segments, &filename.to_string())
        .await;
    assert!(write_res.is_ok(), "Writing the file failed!");

    let read_res = helper
        .read_filestream_to_path(&read_filename.to_string(), &path_segments, 0)
        .await;
    assert!(read_res.is_ok(), "Reading the file failed!");

    // Check if the read file has the same size as the original
    let original_content = read(Path::new(filename)).unwrap();
    let read_content = read(Path::new(read_filename)).unwrap();
    assert_eq!(
        original_content.len(),
        read_content.len(),
        "The size of the read file is different from the original"
    );
    let ls_result = helper.ls_files(&["root".into()]).await;
    println!("ls: {:?}", ls_result);

    // Clean up
    std::fs::remove_file(filename).unwrap();
    std::fs::remove_file(read_filename).unwrap();
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
    let store = KVBlockStore::new(String::from("./tmp/test_large_file_write"), CODEC_DAG_CBOR);
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));
    let (helper, access_key, cid) =
        &mut PrivateDirectoryHelper::init(blockstore, empty_key.to_owned())
            .await
            .unwrap();

    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());

    // Generate a dummy 600MB payload
    let data = generate_dummy_data(500 * 1024 * 1024); // 1000MB in bytes

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

#[tokio::test]
async fn test_large_file_write_stream() {
    let empty_key: Vec<u8> = vec![0; 32];
    let store = KVBlockStore::new(
        String::from("./tmp/test_large_file_write_stream"),
        CODEC_DAG_CBOR,
    );
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));
    let (helper, access_key, cid) =
        &mut PrivateDirectoryHelper::init(blockstore, empty_key.to_owned())
            .await
            .unwrap();

    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());

    // Generate first dummy 1MB payload
    let mut data = generate_dummy_data(1 * 1024 * 1024); // 1MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "file_stream1.bin".into()];
    let cid = helper
        .write_file_stream_from_path(&path, &path_string)
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result.get(0).unwrap().0.contains("file_stream1.bin"));

    // Generate second dummy 1MB payload
    let mut data = generate_dummy_data(1 * 1024 * 1024); // 1MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "file_stream2.bin".into()];
    let cid = helper
        .write_file_stream_from_path(&path, &path_string)
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result.iter().any(|item| item.0 == "file_stream2.bin"));

    // Generate third dummy 1MB payload
    let mut data = generate_dummy_data(1 * 1024 * 1024); // 1MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "file_stream3.bin".into()];
    let cid = helper
        .write_file_stream_from_path(&path, &path_string)
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result.iter().any(|item| item.0 == "file_stream3.bin"));

    // Generate a dummy 100MB payload
    let mut data = generate_dummy_data(100 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "large_file_stream.bin".into()];
    let cid = helper
        .write_file_stream_from_path(&path, &path_string)
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    helper
        .read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream.bin".into()],
            0,
        )
        .await
        .unwrap();

    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    assert_eq!(metadata1.len(), metadata2.len(), "File sizes do not match");

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);

    println!("read_file_stream_from_path checks done");

    // Generate second dummy 60MB payload
    let mut data = generate_dummy_data(60 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "large_file_stream2.bin".into()];
    let cid = helper
        .write_file_stream_from_path(&path, &path_string)
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream2.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    helper
        .read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream2.bin".into()],
            0,
        )
        .await
        .unwrap();
    println!("read_filestream_to_path2 done");
    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    assert_eq!(
        metadata1.len(),
        metadata2.len(),
        "File sizes 2 do not match"
    );

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);

    println!("read_file_stream_from_path2 checks done");

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
    assert!(ls_result.iter().any(|item| item.0 == "world.txt"));

    let content = helper
        .read_file(&["root".into(), "world.txt".into()])
        .await
        .unwrap();
    assert_eq!(content, b"hello, world!".to_vec());
}

#[test]
fn synced_test_large_file_write_stream() {
    let itteration = 2;
    let reload_itteration = 15;
    let empty_key: Vec<u8> = vec![0; 32];
    let store = KVBlockStore::new(
        String::from("./tmp/synced_test_large_file_write_stream"),
        CODEC_DAG_CBOR,
    );
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));
    let (helper, access_key, cid) =
        &mut PrivateDirectoryHelper::synced_init(blockstore, empty_key.to_owned()).unwrap();

    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());
    let mut cid: Cid;

    for i in 1..=itteration {
        let path = vec!["root".into(), format!("test_{}", i).into()];
        cid = helper.synced_mkdir(&path).unwrap();
        println!("CID for mkdir test_{}: {:?}", i, cid);
    }

    for i in 1..=itteration {
        println!(
            "*******************Starting write iteration {}******************",
            i
        );

        // Generate first dummy 1MB payload
        let mut data = generate_dummy_data(1 * 1024 * 1024); // 1MB in bytes
        rand::thread_rng().fill_bytes(&mut data);
        let tmp_file = NamedTempFile::new().unwrap();
        async_std::task::block_on(async {
            async_std::fs::write(tmp_file.path(), &data).await.unwrap();
        });

        let path_buf: PathBuf = tmp_file.path().to_path_buf();
        let path_string: String = path_buf.to_string_lossy().into_owned();

        let path = vec!["root".into(), format!("file_stream{}.bin", i)];
        let cid = helper
            .synced_write_file_stream_from_path(&path, &path_string)
            .unwrap();

        println!("cid: {:?}", cid);
        println!("access_key: {:?}", access_key);
    }

    let ls_result: Vec<(String, wnfs::common::Metadata)> =
        helper.synced_ls_files(&["root".into()]).unwrap();
    println!("ls: {:?}", ls_result);
    let filenames_from_ls: Vec<String> = ls_result.iter().map(|(name, _)| name.clone()).collect();

    let mut found = true;
    for i in 1..=itteration {
        let file_name = format!("file_stream{}.bin", i);
        if !filenames_from_ls.contains(&file_name) {
            found = false;
            break;
        }
    }

    assert!(found, "Not all expected files are present");

    // Generate a dummy 100MB payload
    let mut data = generate_dummy_data(100 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::task::block_on(async {
        async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    });
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "large_file_stream.bin".into()];
    let cid = helper
        .synced_write_file_stream_from_path(&path, &path_string)
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.synced_ls_files(&["root".into()]).unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    helper
        .synced_read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream.bin".into()],
            0,
        )
        .unwrap();

    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    println!(
        "original filesize: {:?} and read size: {:?}",
        metadata1.len(),
        metadata2.len()
    );
    assert_eq!(metadata1.len(), metadata2.len(), "File sizes do not match");

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);

    println!("read_file_stream_from_path checks done");

    // Generate second dummy 60MB payload
    let mut data = generate_dummy_data(60 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::task::block_on(async {
        async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    });
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "large_file_stream2.bin".into()];
    let cid = helper
        .synced_write_file_stream_from_path(&path, &path_string)
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let ls_result = helper.synced_ls_files(&["root".into()]).unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream2.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    helper
        .synced_read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream2.bin".into()],
            0,
        )
        .unwrap();
    println!("read_filestream_to_path2 done");
    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    println!(
        "original filesize: {:?} and read size: {:?}",
        metadata1.len(),
        metadata2.len()
    );
    assert_eq!(
        metadata1.len(),
        metadata2.len(),
        "File sizes 2 do not match"
    );

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);

    //Testing reload
    println!("read_file_stream_from_path2 checks done. Now testing reload");
    let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();

    let path = vec!["root".into(), "test_reload".into()];
    let mut cid = reload_helper.synced_mkdir(&path).unwrap();
    println!("CID for mkdir test_reload: {:?}", cid);

    for i in 1..=reload_itteration {
        let path = vec!["root".into(), format!("test_reload_{}", i).into()];
        cid = reload_helper.synced_mkdir(&path).unwrap();
        println!("CID for mkdir test_reload_{}: {:?}", i, cid);
    }

    for i in 1..=reload_itteration {
        println!(
            "*******************Starting reload write iteration {}******************",
            i
        );

        // Generate first dummy 1MB payload
        let mut data = generate_dummy_data(1 * 1024 * 1024); // 1MB in bytes
        rand::thread_rng().fill_bytes(&mut data);
        let tmp_file = NamedTempFile::new().unwrap();
        async_std::task::block_on(async {
            async_std::fs::write(tmp_file.path(), &data).await.unwrap();
        });

        let path_buf: PathBuf = tmp_file.path().to_path_buf();
        let path_string: String = path_buf.to_string_lossy().into_owned();

        let path = vec!["root".into(), format!("file_stream_reload{}.bin", i)];
        let cid = reload_helper
            .synced_write_file_stream_from_path(&path, &path_string)
            .unwrap();

        println!("cid_reload: {:?}", cid);
        println!("access_key_reload: {:?}", access_key);
    }

    let ls_result: Vec<(String, wnfs::common::Metadata)> =
        reload_helper.synced_ls_files(&["root".into()]).unwrap();
    println!("ls_reload: {:?}", ls_result);
    let filenames_from_ls: Vec<String> = ls_result.iter().map(|(name, _)| name.clone()).collect();

    let mut found = true;
    for i in 1..=reload_itteration {
        let file_name = format!("file_stream_reload{}.bin", i);
        if !filenames_from_ls.contains(&file_name) {
            found = false;
            break;
        }
    }

    assert!(found, "Not all expected files are present in reload");
    // Generate a dummy 100MB payload
    let mut data = generate_dummy_data(100 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file_reload = NamedTempFile::new().unwrap();
    async_std::task::block_on(async {
        async_std::fs::write(tmp_file_reload.path(), &data)
            .await
            .unwrap();
    });
    let path_buf: PathBuf = tmp_file_reload.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "large_file_stream_reload.bin".into()];
    let cid = reload_helper
        .synced_write_file_stream_from_path(&path, &path_string)
        .unwrap();
    println!("cid_reload: {:?}", cid);
    println!("access_key_reload: {:?}", access_key);

    let ls_result = reload_helper.synced_ls_files(&["root".into()]).unwrap();
    println!("ls_reload: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream_reload.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    reload_helper
        .synced_read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream2.bin".into()],
            0,
        )
        .unwrap();

    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    println!(
        "original filesize before reload: {:?} and read size afte reload: {:?}",
        metadata1.len(),
        metadata2.len()
    );
    assert_eq!(metadata1.len(), metadata2.len(), "File sizes do not match");

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);
}

#[test]
fn synced_test_large_file_write_stream_with_reload() {
    let itteration = 2;
    let empty_key: Vec<u8> = vec![0; 32];

    let store = KVBlockStore::new(
        String::from("./tmp/synced_test_large_file_write_stream"),
        CODEC_DAG_CBOR,
    );
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));

    let (helper, access_key, cid) =
        &mut PrivateDirectoryHelper::synced_init(blockstore, empty_key.to_owned()).unwrap();

    let mut cid = cid.to_owned();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());

    for i in 1..=itteration {
        let path = vec!["root".into(), format!("test_{}", i).into()];
        cid = helper.synced_mkdir(&path).unwrap();
        println!("CID for mkdir test_{}: {:?}", i, cid);
    }

    for i in 1..=itteration {
        let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();
        println!(
            "*******************Starting write iteration {}******************",
            i
        );

        // Generate first dummy 1MB payload
        let mut data = generate_dummy_data(1 * 1024 * 1024); // 1MB in bytes
        rand::thread_rng().fill_bytes(&mut data);
        let tmp_file = NamedTempFile::new().unwrap();
        async_std::task::block_on(async {
            async_std::fs::write(tmp_file.path(), &data).await.unwrap();
        });

        let path_buf: PathBuf = tmp_file.path().to_path_buf();
        let path_string: String = path_buf.to_string_lossy().into_owned();

        let path = vec!["root".into(), format!("file_stream{}.bin", i)];
        cid = reload_helper
            .synced_write_file_stream_from_path(&path, &path_string)
            .unwrap();

        println!("cid: {:?}", cid);
        println!("access_key: {:?}", access_key);
    }

    let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();
    let ls_result: Vec<(String, wnfs::common::Metadata)> =
        reload_helper.synced_ls_files(&["root".into()]).unwrap();
    println!("ls: {:?}", ls_result);
    let filenames_from_ls: Vec<String> = ls_result.iter().map(|(name, _)| name.clone()).collect();

    let mut found = true;
    for i in 1..=itteration {
        let file_name = format!("file_stream{}.bin", i);
        if !filenames_from_ls.contains(&file_name) {
            found = false;
            break;
        }
    }

    assert!(found, "Not all expected files are present");

    // Generate a dummy 100MB payload
    let mut data = generate_dummy_data(100 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::task::block_on(async {
        async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    });
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "large_file_stream.bin".into()];
    let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();
    cid = reload_helper
        .synced_write_file_stream_from_path(&path, &path_string)
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();
    let ls_result = reload_helper.synced_ls_files(&["root".into()]).unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();
    reload_helper
        .synced_read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream.bin".into()],
            0,
        )
        .unwrap();

    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    println!(
        "original filesize: {:?} and read size: {:?}",
        metadata1.len(),
        metadata2.len()
    );
    assert_eq!(metadata1.len(), metadata2.len(), "File sizes do not match");

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);

    println!("read_file_stream_from_path checks done");

    // Generate second dummy 60MB payload
    let mut data = generate_dummy_data(60 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::task::block_on(async {
        async_std::fs::write(tmp_file.path(), &data).await.unwrap();
    });
    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();
    let path = vec!["root".into(), "large_file_stream2.bin".into()];
    cid = reload_helper
        .synced_write_file_stream_from_path(&path, &path_string)
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();
    let ls_result = reload_helper.synced_ls_files(&["root".into()]).unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream2.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    let reload_helper = &mut PrivateDirectoryHelper::synced_reload(blockstore, cid).unwrap();
    reload_helper
        .synced_read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream2.bin".into()],
            0,
        )
        .unwrap();
    println!("read_filestream_to_path2 done");
    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    println!(
        "original filesize: {:?} and read size: {:?}",
        metadata1.len(),
        metadata2.len()
    );
    assert_eq!(
        metadata1.len(),
        metadata2.len(),
        "File sizes 2 do not match"
    );

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);
}

#[tokio::test]
async fn test_large_file_write_stream_with_reload() {
    let itteration = 2;
    let empty_key: Vec<u8> = vec![0; 32];

    let store = KVBlockStore::new(
        String::from("./tmp/synced_test_large_file_write_stream"),
        CODEC_DAG_CBOR,
    );
    let blockstore = &mut FFIFriendlyBlockStore::new(Box::new(store));

    let (helper, access_key, cid) =
        &mut PrivateDirectoryHelper::init(blockstore, empty_key.to_owned())
            .await
            .unwrap();

    let mut cid = cid.to_owned();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key.to_owned());

    for i in 1..=itteration {
        let path = vec!["root".into(), format!("test_{}", i).into()];
        cid = helper.mkdir(&path).await.unwrap();
        println!("CID for mkdir test_{}: {:?}", i, cid);
    }

    for i in 1..=itteration {
        let reload_helper = &mut PrivateDirectoryHelper::reload(blockstore, cid)
            .await
            .unwrap();
        println!(
            "*******************Starting write iteration {}******************",
            i
        );

        // Generate first dummy 1MB payload
        let mut data = generate_dummy_data(1 * 1024 * 1024); // 1MB in bytes
        rand::thread_rng().fill_bytes(&mut data);
        let tmp_file = NamedTempFile::new().unwrap();
        async_std::fs::write(tmp_file.path(), &data).await.unwrap();

        let path_buf: PathBuf = tmp_file.path().to_path_buf();
        let path_string: String = path_buf.to_string_lossy().into_owned();

        let path = vec!["root".into(), format!("file_stream{}.bin", i)];
        cid = reload_helper
            .write_file_stream_from_path(&path, &path_string)
            .await
            .unwrap();

        println!("cid: {:?}", cid);
        println!("access_key: {:?}", access_key);
    }

    let reload_helper = &mut PrivateDirectoryHelper::reload(blockstore, cid)
        .await
        .unwrap();
    let ls_result: Vec<(String, wnfs::common::Metadata)> =
        reload_helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    let filenames_from_ls: Vec<String> = ls_result.iter().map(|(name, _)| name.clone()).collect();

    let mut found = true;
    for i in 1..=itteration {
        let file_name = format!("file_stream{}.bin", i);
        if !filenames_from_ls.contains(&file_name) {
            found = false;
            break;
        }
    }

    assert!(found, "Not all expected files are present");

    // Generate a dummy 100MB payload
    let mut data = generate_dummy_data(100 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::fs::write(tmp_file.path(), &data).await.unwrap();

    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let path = vec!["root".into(), "large_file_stream.bin".into()];
    let reload_helper = &mut PrivateDirectoryHelper::reload(blockstore, cid)
        .await
        .unwrap();
    cid = reload_helper
        .write_file_stream_from_path(&path, &path_string)
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);
    let ls_result = reload_helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream.bin"));

    let reload_helper = &mut PrivateDirectoryHelper::reload(blockstore, cid)
        .await
        .unwrap();
    let ls_result = reload_helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    let reload_helper = &mut PrivateDirectoryHelper::reload(blockstore, cid)
        .await
        .unwrap();
    reload_helper
        .read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream.bin".into()],
            0,
        )
        .await
        .unwrap();

    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    println!(
        "original filesize: {:?} and read size: {:?}",
        metadata1.len(),
        metadata2.len()
    );
    assert_eq!(metadata1.len(), metadata2.len(), "File sizes do not match");

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);

    println!("read_file_stream_from_path checks done");

    // Generate second dummy 60MB payload
    let mut data = generate_dummy_data(60 * 1024 * 1024); // 1000MB in bytes
    rand::thread_rng().fill_bytes(&mut data);
    let tmp_file = NamedTempFile::new().unwrap();
    async_std::fs::write(tmp_file.path(), &data).await.unwrap();

    let path_buf: PathBuf = tmp_file.path().to_path_buf();
    let path_string: String = path_buf.to_string_lossy().into_owned();

    let reload_helper = &mut PrivateDirectoryHelper::reload(blockstore, cid)
        .await
        .unwrap();
    let path = vec!["root".into(), "large_file_stream2.bin".into()];
    cid = reload_helper
        .write_file_stream_from_path(&path, &path_string)
        .await
        .unwrap();
    println!("cid: {:?}", cid);
    println!("access_key: {:?}", access_key);

    let reload_helper = &mut PrivateDirectoryHelper::reload(blockstore, cid)
        .await
        .unwrap();
    let ls_result = reload_helper.ls_files(&["root".into()]).await.unwrap();
    println!("ls: {:?}", ls_result);
    assert!(ls_result
        .iter()
        .any(|item| item.0 == "large_file_stream2.bin"));

    let tmp_file_read = NamedTempFile::new().unwrap();
    let path_buf_read: PathBuf = tmp_file_read.path().to_path_buf();
    let path_string_read: String = path_buf_read.to_string_lossy().into_owned();
    let reload_helper = &mut PrivateDirectoryHelper::reload(blockstore, cid)
        .await
        .unwrap();
    reload_helper
        .read_filestream_to_path(
            &path_string_read,
            &["root".into(), "large_file_stream2.bin".into()],
            0,
        )
        .await
        .unwrap();
    println!("read_filestream_to_path2 done");
    let mut file1 = File::open(tmp_file.path()).unwrap();
    let mut file2 = File::open(tmp_file_read.path()).unwrap();

    let metadata1 = file1.metadata().unwrap();
    let metadata2 = file2.metadata().unwrap();
    println!(
        "original filesize: {:?} and read size: {:?}",
        metadata1.len(),
        metadata2.len()
    );
    assert_eq!(
        metadata1.len(),
        metadata2.len(),
        "File sizes 2 do not match"
    );

    let mut content1 = Vec::new();
    let mut content2 = Vec::new();

    file1.read_to_end(&mut content1).unwrap();
    file2.read_to_end(&mut content2).unwrap();
    assert_eq!(content1, content2);
}
