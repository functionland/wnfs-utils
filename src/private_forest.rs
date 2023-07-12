//! This example shows how to add a directory to a private forest (also HAMT) which encrypts it.
//! It also shows how to retrieve encrypted nodes from the forest using `AccessKey`s.

use chrono::{prelude::*, Utc};
use futures::StreamExt;
use libipld::Cid;
use rand::{rngs::ThreadRng, thread_rng};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    rc::Rc,
    sync::Mutex,
};
use wnfs::{common::Metadata, private::AesKey};
use wnfs::{
    common::{utils, BlockStore},
    hamt::Hasher,
    namefilter::Namefilter,
    private::{AccessKey, PrivateDirectory, PrivateForest, PrivateNode},
};

use anyhow::Result;
use log::trace;
use sha3::Sha3_256;

use crate::blockstore::FFIFriendlyBlockStore;

#[derive(Clone)]
struct State {
    initialized: bool,
    wnfs_key: Vec<u8>,
}
impl State {
    fn update(&mut self, initialized: bool, wnfs_key: Vec<u8>) {
        self.initialized = initialized;
        self.wnfs_key = wnfs_key;
    }
}
static mut STATE: Mutex<State> = Mutex::new(State {
    initialized: false,
    wnfs_key: Vec::new(),
});

pub struct PrivateDirectoryHelper {
    pub store: FFIFriendlyBlockStore,
    forest: Rc<PrivateForest>,
    root_dir: Rc<PrivateDirectory>,
    rng: ThreadRng,
}

// Single root (private ref) implementation of the wnfs private directory using KVBlockStore.
// TODO: we assumed all the write, mkdirs use same roots here. this could be done using prepend
// a root path to all path segments.
impl<'a> PrivateDirectoryHelper {
    async fn reload(
        store: &mut FFIFriendlyBlockStore,
        cid: Cid,
    ) -> Result<PrivateDirectoryHelper, String> {
        let initialized: bool;
        let wnfs_key: Vec<u8>;
        unsafe {
            initialized = STATE.lock().unwrap().initialized;
            wnfs_key = STATE.lock().unwrap().wnfs_key.to_owned();
        }
        if initialized {
            let helper_res =
                PrivateDirectoryHelper::load_with_wnfs_key(store, cid, wnfs_key.to_owned()).await;
            if helper_res.is_ok() {
                Ok(helper_res.ok().unwrap())
            } else {
                trace!(
                    "wnfsError in new: {:?}",
                    helper_res.as_ref().err().unwrap().to_string()
                );
                Err(helper_res.err().unwrap().to_string())
            }
        } else {
            Err("PrivateDirectoryHelper not initialized".into())
        }
    }

    async fn init(
        store: &mut FFIFriendlyBlockStore,
        wnfs_key: Vec<u8>,
    ) -> Result<(PrivateDirectoryHelper, AccessKey, Cid), String> {
        let rng = &mut thread_rng();
        let ratchet_seed: [u8; 32];
        let inumber: [u8; 32];
        if wnfs_key.is_empty() {
            let wnfs_random_key = AesKey::new(utils::get_random_bytes::<32>(rng));
            ratchet_seed = Sha3_256::hash(&wnfs_random_key.as_bytes());
            inumber = utils::get_random_bytes::<32>(rng); // Needs to be random
        } else {
            ratchet_seed = Sha3_256::hash(&wnfs_key);
            inumber = Sha3_256::hash(&ratchet_seed);
        }

        let forest_res = PrivateDirectoryHelper::create_private_forest(store.to_owned()).await;

        if forest_res.is_ok() {
            let (forest, _) = &mut forest_res.unwrap();
            // Create a root directory from the ratchet_seed, inumber and namefilter. Directory gets saved in forest.
            let root_dir_res = PrivateDirectory::new_with_seed_and_store(
                Namefilter::default(),
                Utc::now(),
                ratchet_seed,
                inumber,
                forest,
                store,
                rng,
            )
            .await;

            if root_dir_res.is_ok() {
                // Private ref contains data and keys for fetching and decrypting the directory node in the private forest.
                let root_dir = &mut root_dir_res.unwrap();
                let access_key = root_dir.as_node().store(forest, store, rng).await;
                if access_key.is_ok() {
                    let forest_cid = PrivateDirectoryHelper::update_private_forest(
                        store.to_owned(),
                        forest.to_owned(),
                    )
                    .await;
                    if forest_cid.is_ok() {
                        unsafe {
                            STATE.lock().unwrap().update(true, wnfs_key.to_owned());
                        }
                        Ok((
                            PrivateDirectoryHelper {
                                store: store.to_owned(),
                                forest: forest.to_owned(),
                                root_dir: root_dir.to_owned(),
                                rng: rng.to_owned(),
                            },
                            access_key.ok().unwrap(),
                            forest_cid.unwrap(),
                        ))
                    } else {
                        trace!(
                            "wnfsError in init: {:?}",
                            forest_cid.as_ref().err().unwrap().to_string()
                        );
                        Err(forest_cid.err().unwrap().to_string())
                    }
                } else {
                    trace!(
                        "wnfsError in init: {:?}",
                        access_key.as_ref().err().unwrap().to_string()
                    );
                    Err(access_key.err().unwrap().to_string())
                }
            } else {
                trace!(
                    "wnfsError occured in init: {:?}",
                    root_dir_res.as_ref().to_owned().err().unwrap().to_string()
                );
                Err(root_dir_res.as_ref().to_owned().err().unwrap().to_string())
            }
        } else {
            let err = forest_res.as_ref().to_owned().err().unwrap().to_string();
            trace!("wnfsError occured in init: {:?}", err);
            Err(err)
        }
    }

    pub async fn load_with_wnfs_key(
        store: &mut FFIFriendlyBlockStore,
        forest_cid: Cid,
        wnfs_key: Vec<u8>,
    ) -> Result<PrivateDirectoryHelper, String> {
        let rng = &mut thread_rng();
        let ratchet_seed: [u8; 32];
        let inumber: [u8; 32];
        if wnfs_key.is_empty() {
            let wnfs_random_key = AesKey::new(utils::get_random_bytes::<32>(rng));
            ratchet_seed = Sha3_256::hash(&wnfs_random_key.as_bytes());
            inumber = utils::get_random_bytes::<32>(rng); // Needs to be random
        } else {
            ratchet_seed = Sha3_256::hash(&wnfs_key);
            inumber = Sha3_256::hash(&ratchet_seed);
        }

        let forest_res =
            PrivateDirectoryHelper::load_private_forest(store.to_owned(), forest_cid).await;
        if forest_res.is_ok() {
            let forest = &mut forest_res.unwrap();
            // Create a root directory from the ratchet_seed, inumber and namefilter. Directory gets saved in forest.
            let root_dir = PrivateDirectory::new_with_seed_and_store(
                Namefilter::default(),
                Utc::now(),
                ratchet_seed,
                inumber,
                forest,
                store,
                rng,
            )
            .await;

            if root_dir.is_ok() {
                let latest_root_dir = root_dir.unwrap().search_latest(forest, store).await;
                if latest_root_dir.is_ok() {
                    unsafe {
                        STATE.lock().unwrap().update(true, wnfs_key.to_owned());
                    }
                    Ok(PrivateDirectoryHelper {
                        store: store.to_owned(),
                        forest: forest.to_owned(),
                        root_dir: latest_root_dir.unwrap(),
                        rng: rng.to_owned(),
                    })
                } else {
                    trace!(
                        "wnfsError in load_with_wnfs_key: {:?}",
                        latest_root_dir.as_ref().err().unwrap().to_string()
                    );
                    Err(latest_root_dir.err().unwrap().to_string())
                }
            } else {
                trace!(
                    "wnfsError occured in load_with_wnfs_key: {:?}",
                    root_dir.as_ref().to_owned().err().unwrap().to_string()
                );
                Err(root_dir.as_ref().to_owned().err().unwrap().to_string())
            }
        } else {
            let err = forest_res.as_ref().to_owned().err().unwrap().to_string();
            trace!("wnfsError occured in load_with_wnfs_key: {:?}", err);
            Err(err)
        }
    }

    pub async fn load_with_access_key(
        store: &mut FFIFriendlyBlockStore,
        forest_cid: Cid,
        access_key: AccessKey,
    ) -> Result<PrivateDirectoryHelper, String> {
        let rng = thread_rng();

        let forest_res =
            PrivateDirectoryHelper::load_private_forest(store.to_owned(), forest_cid).await;
        if forest_res.is_ok() {
            let forest = &mut forest_res.unwrap();
            let node_res = PrivateNode::load(&access_key, &forest, store).await;

            if node_res.is_ok() {
                let root_dir = node_res.unwrap().as_dir();
                if root_dir.is_ok() {
                    let latest_root_dir = root_dir.unwrap().search_latest(forest, store).await;
                    if latest_root_dir.is_ok() {
                        Ok(PrivateDirectoryHelper {
                            store: store.to_owned(),
                            forest: forest.to_owned(),
                            root_dir: latest_root_dir.unwrap(),
                            rng,
                        })
                    } else {
                        trace!(
                            "wnfsError in load_with_wnfs_key: {:?}",
                            latest_root_dir.as_ref().err().unwrap().to_string()
                        );
                        Err(latest_root_dir.err().unwrap().to_string())
                    }
                } else {
                    trace!(
                        "wnfsError in load_with_wnfs_key: {:?}",
                        root_dir.as_ref().err().unwrap().to_string()
                    );
                    Err(root_dir.err().unwrap().to_string())
                }
            } else {
                trace!(
                    "wnfsError occured in load_with_wnfs_key: {:?}",
                    node_res.as_ref().to_owned().err().unwrap().to_string()
                );
                Err(node_res.as_ref().to_owned().err().unwrap().to_string())
            }
        } else {
            let err = forest_res.as_ref().to_owned().err().unwrap().to_string();
            trace!("wnfsError occured in load_with_wnfs_key: {:?}", err);
            Err(err)
        }
    }

    async fn create_private_forest(
        store: FFIFriendlyBlockStore,
    ) -> Result<(Rc<PrivateForest>, Cid), String> {
        // Create the private forest (a HAMT), a map-like structure where file and directory ciphertexts are stored.
        let forest = Rc::new(PrivateForest::new());

        // Doing this will give us a single root CID
        let private_root_cid = store.put_async_serializable(&forest).await;
        if private_root_cid.is_ok() {
            Ok((forest, private_root_cid.ok().unwrap()))
        } else {
            trace!(
                "wnfsError occured in create_private_forest: {:?}",
                private_root_cid.as_ref().err().unwrap()
            );
            Err(private_root_cid.err().unwrap().to_string())
        }
    }

    async fn load_private_forest(
        store: FFIFriendlyBlockStore,
        forest_cid: Cid,
    ) -> Result<Rc<PrivateForest>, String> {
        // Deserialize private forest from the blockstore.
        let forest = store.get_deserializable::<PrivateForest>(&forest_cid).await;
        if forest.is_ok() {
            Ok(Rc::new(forest.unwrap()))
        } else {
            trace!(
                "wnfsError occured in load__private_forest: {:?}",
                forest.as_ref().err().unwrap()
            );
            Err(forest.err().unwrap().to_string())
        }
    }

    pub async fn update_private_forest(
        store: FFIFriendlyBlockStore,
        forest: Rc<PrivateForest>,
    ) -> Result<Cid, String> {
        // Serialize the private forest to DAG CBOR.
        // Doing this will give us a single root CID
        let private_root_cid = store.put_async_serializable(&forest).await;
        if private_root_cid.is_ok() {
            Ok(private_root_cid.ok().unwrap())
        } else {
            trace!(
                "wnfsError occured in create_private_forest: {:?}",
                private_root_cid.as_ref().err().unwrap()
            );
            Err(private_root_cid.err().unwrap().to_string())
        }
    }

    fn get_file_as_byte_vec(&mut self, filename: &String) -> Result<(Vec<u8>, i64), String> {
        let f = File::open(&filename);
        if f.is_ok() {
            let metadata_res = std::fs::metadata(&filename);
            if metadata_res.is_ok() {
                let metadata = metadata_res.ok().unwrap();
                let modification_time_seconds = metadata.mtime();

                let mut buffer = vec![0; metadata.len() as usize];
                f.ok().unwrap().read(&mut buffer).expect("buffer overflow");
                Ok((buffer, modification_time_seconds))
            } else {
                trace!(
                    "wnfsError in get_file_as_byte_vec, unable to read metadata: {:?}",
                    metadata_res.err().unwrap()
                );
                Err("wnfsError unable to read metadata".to_string())
            }
        } else {
            trace!(
                "wnfsError in get_file_as_byte_vec, no file found: {:?}",
                f.err().unwrap()
            );
            Err("wnfsError no file found".to_string())
        }
    }

    pub async fn write_file_from_path(
        &mut self,
        path_segments: &[String],
        filename: &String,
    ) -> Result<Cid, String> {
        let content: Vec<u8>;
        let modification_time_seconds: i64;
        let try_content = self.get_file_as_byte_vec(filename);
        if try_content.is_ok() {
            (content, modification_time_seconds) = try_content.ok().unwrap();
            let writefile_res = self
                .write_file(path_segments, content, modification_time_seconds)
                .await;
            if writefile_res.is_ok() {
                Ok(writefile_res.ok().unwrap())
            } else {
                trace!(
                    "wnfsError in write_file_from_path: {:?}",
                    writefile_res.as_ref().err().unwrap()
                );
                Err(writefile_res.err().unwrap())
            }
        } else {
            trace!(
                "wnfsError in write_file_from_path: {:?}",
                try_content.as_ref().err().unwrap()
            );
            Err(try_content.err().unwrap())
        }
    }

    fn write_byte_vec_to_file(
        &mut self,
        filename: &String,
        file_content: Vec<u8>,
    ) -> Result<bool, String> {
        trace!("wnfs11 **********************write_byte_vec_to_file started**************filename={:?}", filename);
        trace!("wnfs11 **********************write_byte_vec_to_file started**************file_content={:?}", file_content);
        let file = File::create(filename);
        if file.is_ok() {
            let mut file_handler = file.ok().unwrap();
            trace!(
                "wnfs11 **********************write_byte_vec_to_file write created**************"
            );
            let write_res = file_handler.write_all(&file_content);
            if write_res.is_ok() {
                Ok(true)
            } else {
                trace!(
                    "wnfsError occured in write_byte_vec_to_file on write_res {:?}",
                    write_res.as_ref().err().unwrap().to_string()
                );
                Err(write_res.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError occured in write_byte_vec_to_file on file {:?}",
                file.as_ref().err().unwrap().to_string()
            );
            Err(file.err().unwrap().to_string())
        }
    }

    pub async fn write_file(
        &mut self,

        path_segments: &[String],
        content: Vec<u8>,
        modification_time_seconds: i64,
    ) -> Result<Cid, String> {
        let forest = &mut self.forest;
        let root_dir = &mut self.root_dir;
        let mut modification_time_utc: DateTime<Utc> = Utc::now();
        if modification_time_seconds > 0 {
            let naive_datetime =
                NaiveDateTime::from_timestamp_opt(modification_time_seconds, 0).unwrap();
            modification_time_utc = DateTime::from_utc(naive_datetime, Utc);
        }
        let write_res = root_dir
            .write(
                path_segments,
                true,
                modification_time_utc,
                content,
                forest,
                &mut self.store,
                &mut self.rng,
            )
            .await;
        if write_res.is_ok() {
            // Private ref contains data and keys for fetching and decrypting the directory node in the private forest.
            let access_key = root_dir
                .as_node()
                .store(forest, &mut self.store, &mut self.rng)
                .await;
            if access_key.is_ok() {
                let forest_cid = PrivateDirectoryHelper::update_private_forest(
                    self.store.to_owned(),
                    forest.to_owned(),
                )
                .await;
                if forest_cid.is_ok() {
                    Ok(forest_cid.ok().unwrap())
                } else {
                    trace!(
                        "wnfsError in write_file: {:?}",
                        forest_cid.as_ref().err().unwrap().to_string()
                    );
                    Err(forest_cid.err().unwrap().to_string())
                }
            } else {
                trace!(
                    "wnfsError in write_file: {:?}",
                    access_key.as_ref().err().unwrap().to_string()
                );
                Err(access_key.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError in write_file: {:?}",
                write_res.as_ref().err().unwrap().to_string()
            );
            Err(write_res.err().unwrap().to_string())
        }
    }

    pub async fn read_filestream_to_path(
        &mut self,
        local_filename: &String,
        path_segments: &[String],
        index: usize,
    ) -> Result<bool, String> {
        let forest = &mut self.forest;
        let root_dir = &mut self.root_dir;
        //let mut stream_content: Vec<u8> = vec![];
        let local_file = File::create(local_filename);
        if local_file.is_ok() {
            let mut local_file_handler = local_file.ok().unwrap();

            let private_node_result = root_dir
                .get_node(path_segments, true, forest, &mut self.store)
                .await;
            if private_node_result.is_ok() {
                let result = private_node_result.ok().unwrap();
                if result.is_some() {
                    let private_node = result.unwrap();
                    let is_file = private_node.is_file();
                    if is_file {
                        let file_res = private_node.as_file();
                        if file_res.is_ok() {
                            let file = file_res.ok().unwrap();
                            let mut stream = file.stream_content(index, &forest, &mut self.store);
                            while let Some(block) = stream.next().await {
                                let write_result = local_file_handler.write_all(&block.unwrap());
                                if write_result.is_err() {
                                    trace!("wnfsError occured in read_filestream_to_path on write_result: {:?}", write_result.as_ref().err().unwrap().to_string());
                                }
                                //stream_content.extend_from_slice(&block.unwrap());
                            }
                            Ok(true)
                        } else {
                            trace!(
                                "wnfsError occured in read_filestream_to_path on file_res: {:?}",
                                file_res.as_ref().err().unwrap().to_string()
                            );
                            Err(file_res.err().unwrap().to_string())
                        }
                    } else {
                        trace!("wnfsError occured in read_filestream_to_path on is_file");
                        Err("wnfsError occured in read_filestream_to_path on is_file".to_string())
                    }
                } else {
                    trace!("wnfsError occured in read_filestream_to_path on result");
                    Err("wnfsError occured in read_filestream_to_path on result".to_string())
                }
            } else {
                trace!(
                    "wnfsError occured in read_filestream_to_path on private_node_result: {:?}",
                    private_node_result.as_ref().err().unwrap().to_string()
                );
                Err(private_node_result.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError occured in read_filestream_to_path on local_file {:?}",
                local_file.as_ref().err().unwrap().to_string()
            );
            Err(local_file.err().unwrap().to_string())
        }
    }

    pub async fn read_file_to_path(
        &mut self,
        path_segments: &[String],
        filename: &String,
    ) -> Result<String, String> {
        let file_content_res = self.read_file(path_segments).await;
        if file_content_res.is_ok() {
            let res = self.write_byte_vec_to_file(filename, file_content_res.ok().unwrap());
            if res.is_ok() {
                Ok(filename.to_string())
            } else {
                trace!(
                    "wnfsError occured in read_file_to_path on res: {:?}",
                    res.as_ref().err().unwrap().to_string()
                );
                Err(res.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError occured in read_file_to_path on file_content_res: {:?}",
                file_content_res.as_ref().err().unwrap().to_string()
            );
            Err(file_content_res.err().unwrap().to_string())
        }
    }

    pub async fn read_file(&mut self, path_segments: &[String]) -> Result<Vec<u8>, String> {
        let forest = &mut self.forest;
        let root_dir = &mut self.root_dir;
        let res = root_dir
            .read(path_segments, true, forest, &mut self.store)
            .await;
        if res.is_ok() {
            let result = res.ok().unwrap();
            Ok(result)
        } else {
            trace!(
                "wnfsError occured in read_file: {:?} ",
                res.as_ref().err().unwrap()
            );
            Err(res.err().unwrap().to_string())
        }
    }

    pub async fn mkdir(&mut self, path_segments: &[String]) -> Result<Cid, String> {
        let forest = &mut self.forest;
        let root_dir = &mut self.root_dir;
        let res = root_dir
            .mkdir(
                path_segments,
                true,
                Utc::now(),
                forest,
                &mut self.store,
                &mut self.rng,
            )
            .await;
        if res.is_ok() {
            // Private ref contains data and keys for fetching and decrypting the directory node in the private forest.
            let access_key = root_dir
                .as_node()
                .store(forest, &mut self.store, &mut self.rng)
                .await;
            if access_key.is_ok() {
                let forest_cid = PrivateDirectoryHelper::update_private_forest(
                    self.store.to_owned(),
                    forest.to_owned(),
                )
                .await;
                if forest_cid.is_ok() {
                    Ok(forest_cid.ok().unwrap())
                } else {
                    trace!(
                        "wnfsError in mkdir: {:?}",
                        forest_cid.as_ref().err().unwrap().to_string()
                    );
                    Err(forest_cid.err().unwrap().to_string())
                }
            } else {
                trace!(
                    "wnfsError in mkdir: {:?}",
                    access_key.as_ref().err().unwrap().to_string()
                );
                Err(access_key.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError occured in mkdir: {:?}",
                res.as_ref().err().unwrap()
            );
            Err(res.err().unwrap().to_string())
        }
    }

    pub async fn rm(&mut self, path_segments: &[String]) -> Result<Cid, String> {
        let forest = &mut self.forest;
        let root_dir = &mut self.root_dir;
        let result = root_dir
            .rm(path_segments, true, forest, &mut self.store)
            .await;
        if result.is_ok() {
            // Private ref contains data and keys for fetching and decrypting the directory node in the private forest.
            let access_key = root_dir
                .as_node()
                .store(forest, &mut self.store, &mut self.rng)
                .await;
            if access_key.is_ok() {
                let forest_cid = PrivateDirectoryHelper::update_private_forest(
                    self.store.to_owned(),
                    forest.to_owned(),
                )
                .await;
                if forest_cid.is_ok() {
                    Ok(forest_cid.ok().unwrap())
                } else {
                    trace!(
                        "wnfsError in result: {:?}",
                        forest_cid.as_ref().err().unwrap().to_string()
                    );
                    Err(forest_cid.err().unwrap().to_string())
                }
            } else {
                trace!(
                    "wnfsError in result: {:?}",
                    access_key.as_ref().err().unwrap().to_string()
                );
                Err(access_key.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError occured in rm result: {:?}",
                result.as_ref().err().unwrap()
            );
            Err(result.err().unwrap().to_string())
        }
    }

    pub async fn mv(
        &mut self,
        source_path_segments: &[String],
        target_path_segments: &[String],
    ) -> Result<Cid, String> {
        let forest = &mut self.forest;
        let root_dir = &mut self.root_dir;
        let mv_result = root_dir
            .basic_mv(
                source_path_segments,
                target_path_segments,
                true,
                Utc::now(),
                forest,
                &mut self.store,
                &mut self.rng,
            )
            .await;
        if mv_result.is_ok() {
            // Private ref contains data and keys for fetching and decrypting the directory node in the private forest.
            let access_key = root_dir
                .as_node()
                .store(forest, &mut self.store, &mut self.rng)
                .await;
            if access_key.is_ok() {
                let forest_cid = PrivateDirectoryHelper::update_private_forest(
                    self.store.to_owned(),
                    forest.to_owned(),
                )
                .await;
                if forest_cid.is_ok() {
                    Ok(forest_cid.ok().unwrap())
                } else {
                    trace!(
                        "wnfsError in mv_result: {:?}",
                        forest_cid.as_ref().err().unwrap().to_string()
                    );
                    Err(forest_cid.err().unwrap().to_string())
                }
            } else {
                trace!(
                    "wnfsError in mv_result: {:?}",
                    access_key.as_ref().err().unwrap().to_string()
                );
                Err(access_key.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError occured in mv mv_result: {:?}",
                mv_result.as_ref().err().unwrap()
            );
            Err(mv_result.err().unwrap().to_string())
        }
    }

    pub async fn cp(
        &mut self,
        source_path_segments: &[String],
        target_path_segments: &[String],
    ) -> Result<Cid, String> {
        let forest = &mut self.forest;
        let root_dir = &mut self.root_dir;
        let cp_result = root_dir
            .cp(
                source_path_segments,
                target_path_segments,
                true,
                Utc::now(),
                forest,
                &mut self.store,
                &mut self.rng,
            )
            .await;
        if cp_result.is_ok() {
            // Private ref contains data and keys for fetching and decrypting the directory node in the private forest.
            let access_key = root_dir
                .as_node()
                .store(forest, &mut self.store, &mut self.rng)
                .await;
            if access_key.is_ok() {
                let forest_cid = PrivateDirectoryHelper::update_private_forest(
                    self.store.to_owned(),
                    forest.to_owned(),
                )
                .await;
                if forest_cid.is_ok() {
                    Ok(forest_cid.ok().unwrap())
                } else {
                    trace!(
                        "wnfsError in cp_result: {:?}",
                        forest_cid.as_ref().err().unwrap().to_string()
                    );
                    Err(forest_cid.err().unwrap().to_string())
                }
            } else {
                trace!(
                    "wnfsError in cp_result: {:?}",
                    access_key.as_ref().err().unwrap().to_string()
                );
                Err(access_key.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError occured in cp cp_result: {:?}",
                cp_result.as_ref().err().unwrap()
            );
            Err(cp_result.err().unwrap().to_string())
        }
    }

    pub async fn ls_files(
        &mut self,
        path_segments: &[String],
    ) -> Result<Vec<(String, Metadata)>, String> {
        let forest = &mut self.forest;
        let root_dir = &mut self.root_dir;
        let res = root_dir
            .ls(path_segments, true, forest, &mut self.store)
            .await;
        if res.is_ok() {
            let result = res.ok().unwrap();
            Ok(result)
        } else {
            trace!(
                "wnfsError occured in ls_files: {:?}",
                res.as_ref().err().unwrap().to_string()
            );
            Err(res.err().unwrap().to_string())
        }
    }
}

// Implement synced version of the library for using in android jni.
impl PrivateDirectoryHelper {
    pub fn synced_init(
        store: &mut FFIFriendlyBlockStore,
        wnfs_key: Vec<u8>,
    ) -> Result<(PrivateDirectoryHelper, AccessKey, Cid), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(PrivateDirectoryHelper::init(store, wnfs_key));
    }

    pub fn synced_load_with_wnfs_key(
        store: &mut FFIFriendlyBlockStore,
        forest_cid: Cid,
        wnfs_key: Vec<u8>,
    ) -> Result<PrivateDirectoryHelper, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(PrivateDirectoryHelper::load_with_wnfs_key(
            store, forest_cid, wnfs_key,
        ));
    }

    // pub fn synced_load_with_access_key(
    //     store: &mut FFIFriendlyBlockStore<'a>,
    //     forest_cid: Cid,
    //     wnfs_key: Vec<u8>,
    // ) -> Result<PrivateDirectoryHelper, String> {
    //     let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    //     return runtime.block_on(PrivateDirectoryHelper::load_with_wnfs_key(
    //         store, forest_cid, wnfs_key,
    //     ));
    // }

    pub fn synced_reload(
        store: &mut FFIFriendlyBlockStore,
        forest_cid: Cid,
    ) -> Result<PrivateDirectoryHelper, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(PrivateDirectoryHelper::reload(store, forest_cid));
    }

    pub fn synced_write_file_from_path(
        &mut self,
        path_segments: &[String],
        filename: &String,
    ) -> Result<Cid, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.write_file_from_path(path_segments, filename));
    }

    pub fn synced_write_file(
        &mut self,
        path_segments: &[String],
        content: Vec<u8>,
        modification_time_seconds: i64,
    ) -> Result<Cid, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.write_file(
            path_segments,
            content,
            modification_time_seconds,
        ));
    }

    pub fn synced_read_file_to_path(
        &mut self,
        path_segments: &[String],
        filename: &String,
    ) -> Result<String, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.read_file_to_path(path_segments, filename));
    }

    pub fn synced_read_file(&mut self, path_segments: &[String]) -> Result<Vec<u8>, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.read_file(path_segments));
    }

    pub fn synced_read_filestream_to_path(
        &mut self,
        local_filename: &String,
        path_segments: &[String],
        index: usize,
    ) -> Result<bool, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.read_filestream_to_path(
            local_filename,
            path_segments,
            index,
        ));
    }

    pub fn synced_mkdir(&mut self, path_segments: &[String]) -> Result<Cid, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.mkdir(path_segments));
    }

    pub fn synced_mv(
        &mut self,
        source_path_segments: &[String],
        target_path_segments: &[String],
    ) -> Result<Cid, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.mv(source_path_segments, target_path_segments));
    }

    pub fn synced_cp(
        &mut self,
        source_path_segments: &[String],
        target_path_segments: &[String],
    ) -> Result<Cid, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.cp(source_path_segments, target_path_segments));
    }

    pub fn synced_rm(&mut self, path_segments: &[String]) -> Result<Cid, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.rm(path_segments));
    }

    pub fn synced_ls_files(
        &mut self,
        path_segments: &[String],
    ) -> Result<Vec<(String, Metadata)>, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.ls_files(path_segments));
    }

    pub fn parse_path(path: String) -> Vec<String> {
        path.trim()
            .trim_matches('/')
            .split("/")
            .map(|s| s.to_string())
            .collect()
    }
}

#[cfg(test)]
mod private_tests {

    use wnfs::common::CODEC_DAG_CBOR;

    use crate::blockstore::FFIFriendlyBlockStore;
    use crate::kvstore::KVBlockStore;
    use crate::private_forest::PrivateDirectoryHelper;

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
}
