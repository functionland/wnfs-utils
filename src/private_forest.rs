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

pub struct PrivateDirectoryHelper<'a> {
    pub store: FFIFriendlyBlockStore<'a>,
    rng: ThreadRng,
}

// Single root (private ref) implementation of the wnfs private directory using KVBlockStore.
// TODO: we assumed all the write, mkdirs use same roots here. this could be done using prepend
// a root path to all path segments.
impl<'a> PrivateDirectoryHelper<'a> {
    pub fn new(block_store: FFIFriendlyBlockStore<'a>) -> Self
where {
        Self {
            store: block_store,
            rng: thread_rng(),
        }
    }

    pub async fn create_private_forest(&mut self) -> Result<Cid, String> {
        // Create the private forest (a HAMT), a map-like structure where file and directory ciphertexts are stored.
        let forest = &mut Rc::new(PrivateForest::new());

        // Doing this will give us a single root CID
        let private_root_cid = self.store.put_async_serializable(forest).await;
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

    pub async fn load_forest(&mut self, forest_cid: Cid) -> Result<Rc<PrivateForest>, String> {
        // Deserialize private forest from the blockstore.
        let forest = self
            .store
            .get_deserializable::<PrivateForest>(&forest_cid)
            .await;
        if forest.is_ok() {
            Ok(Rc::new(forest.ok().unwrap()))
        } else {
            trace!(
                "wnfsError occured in load_forest: {:?}",
                forest.as_ref().err().unwrap()
            );
            Err(forest.err().unwrap().to_string())
        }
    }

    pub async fn update_forest(&mut self, hamt: &mut Rc<PrivateForest>) -> Result<Cid, String> {
        // Serialize the private forest to DAG CBOR.
        // Doing this will give us a single root CID
        let private_root_cid = self.store.put_async_serializable(hamt.as_ref()).await;
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

    pub async fn get_root_dir(
        &mut self,
        forest: Rc<PrivateForest>,
        access_key: AccessKey,
    ) -> Result<Rc<PrivateDirectory>, String> {
        // Fetch and decrypt root directory from the private forest using provided private ref.
        // Fetch and decrypt a directory from the private forest using provided private ref.
        let forest_res = PrivateNode::load(&access_key, &forest, &mut self.store).await;
        if forest_res.is_ok() {
            let dir = forest_res.ok().unwrap().as_dir();
            if dir.is_ok() {
                Ok(dir.ok().unwrap())
            } else {
                trace!(
                    "wnfsError occured in get_root_dir: {:?}",
                    dir.as_ref().err().unwrap().to_string()
                );
                Err(dir.err().unwrap().to_string())
            }
        } else {
            trace!(
                "wnfsError occured in get_root_dir: {:?}",
                forest_res.as_ref().err().unwrap().to_string()
            );
            Err(forest_res.err().unwrap().to_string())
        }
    }

    pub async fn get_root_dir_with_wnfs_key(
        &mut self,
        forest: Rc<PrivateForest>,
        wnfs_key: Vec<u8>,
    ) -> Result<Rc<PrivateDirectory>, String> {
        let ratchet_seed: [u8; 32] = Sha3_256::hash(&wnfs_key);
        let inumber: [u8; 32] = Sha3_256::hash(&ratchet_seed);

        let fetched_node = Rc::new(PrivateDirectory::with_seed(
            Namefilter::default(),
            Utc::now(),
            ratchet_seed,
            inumber,
        ));
        let tmp_node = fetched_node.search_latest(&forest, &mut self.store).await;
        if tmp_node.is_ok() {
            Ok(tmp_node.ok().unwrap())
        } else {
            trace!(
                "wnfsError in get_root_dir_with_key: tmp_node {:?}",
                tmp_node.as_ref().err().unwrap().to_string()
            );
            Err(tmp_node.err().unwrap().to_string())
        }
    }

    pub async fn init(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        wnfs_key: Vec<u8>,
    ) -> Result<(Cid, AccessKey), String> {
        let ratchet_seed: [u8; 32];
        let inumber: [u8; 32];
        if wnfs_key.is_empty() {
            let wnfs_random_key = AesKey::new(utils::get_random_bytes::<32>(&mut self.rng));
            ratchet_seed = Sha3_256::hash(&wnfs_random_key.as_bytes());
            inumber = utils::get_random_bytes::<32>(&mut self.rng); // Needs to be random
        } else {
            ratchet_seed = Sha3_256::hash(&wnfs_key);
            inumber = Sha3_256::hash(&ratchet_seed);
        }

        // Create a root directory from the ratchet_seed, inumber and namefilter. Directory gets saved in forest.
        let root_dir = &mut PrivateDirectory::new_with_seed_and_store(
            Namefilter::default(),
            Utc::now(),
            ratchet_seed,
            inumber,
            forest,
            &mut self.store,
            &mut self.rng,
        )
        .await;

        if root_dir.is_ok() {
            // Private ref contains data and keys for fetching and decrypting the directory node in the private forest.
            let access_key = root_dir
                .as_ref()
                .unwrap()
                .as_node()
                .store(forest, &mut self.store, &mut self.rng)
                .await;
            if access_key.is_ok() {
                let forest_cid = self.update_forest(forest).await;
                if forest_cid.is_ok() {
                    Ok((forest_cid.ok().unwrap(), access_key.ok().unwrap()))
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
                root_dir.as_ref().to_owned().err().unwrap().to_string()
            );
            Err(root_dir.as_ref().to_owned().err().unwrap().to_string())
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
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
        filename: &String,
    ) -> Result<(Cid, AccessKey), String> {
        let content: Vec<u8>;
        let modification_time_seconds: i64;
        let try_content = self.get_file_as_byte_vec(filename);
        if try_content.is_ok() {
            (content, modification_time_seconds) = try_content.ok().unwrap();
            let writefile_res = self
                .write_file(
                    forest,
                    root_dir,
                    path_segments,
                    content,
                    modification_time_seconds,
                )
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
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
        content: Vec<u8>,
        modification_time_seconds: i64,
    ) -> Result<(Cid, AccessKey), String> {
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
                let forest_cid = self.update_forest(forest).await;
                if forest_cid.is_ok() {
                    Ok((forest_cid.ok().unwrap(), access_key.ok().unwrap()))
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
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
        index: usize,
    ) -> Result<bool, String> {
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
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
        filename: &String,
    ) -> Result<String, String> {
        let file_content_res = self.read_file(forest, root_dir, path_segments).await;
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

    pub async fn read_file(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
    ) -> Result<Vec<u8>, String> {
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

    pub async fn mkdir(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
    ) -> Result<(Cid, AccessKey), String> {
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
                let forest_cid = self.update_forest(forest).await;
                if forest_cid.is_ok() {
                    Ok((forest_cid.ok().unwrap(), access_key.ok().unwrap()))
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

    pub async fn rm(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
    ) -> Result<(Cid, AccessKey), String> {
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
                let forest_cid = self.update_forest(forest).await;
                if forest_cid.is_ok() {
                    Ok((forest_cid.ok().unwrap(), access_key.ok().unwrap()))
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
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        source_path_segments: &[String],
        target_path_segments: &[String],
    ) -> Result<(Cid, AccessKey), String> {
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
                let forest_cid = self.update_forest(forest).await;
                if forest_cid.is_ok() {
                    Ok((forest_cid.ok().unwrap(), access_key.ok().unwrap()))
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
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        source_path_segments: &[String],
        target_path_segments: &[String],
    ) -> Result<(Cid, AccessKey), String> {
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
                let forest_cid = self.update_forest(forest).await;
                if forest_cid.is_ok() {
                    Ok((forest_cid.ok().unwrap(), access_key.ok().unwrap()))
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
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
    ) -> Result<Vec<(String, Metadata)>, String> {
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
impl<'a> PrivateDirectoryHelper<'a> {
    pub fn synced_create_private_forest(&mut self) -> Result<Cid, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.create_private_forest());
    }

    pub fn synced_load_forest(&mut self, forest_cid: Cid) -> Result<Rc<PrivateForest>, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.load_forest(forest_cid));
    }

    pub fn synced_get_root_dir(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        access_key: AccessKey,
    ) -> Result<Rc<PrivateDirectory>, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.get_root_dir(forest.to_owned(), access_key));
    }

    pub fn synced_get_root_dir_with_wnfs_key(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        wnfs_key: Vec<u8>,
    ) -> Result<Rc<PrivateDirectory>, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.get_root_dir_with_wnfs_key(forest.to_owned(), wnfs_key));
    }

    pub fn synced_init(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        wnfs_key: Vec<u8>,
    ) -> Result<(Cid, AccessKey), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.init(forest, wnfs_key));
    }

    pub fn synced_write_file_from_path(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
        filename: &String,
    ) -> Result<(Cid, AccessKey), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.write_file_from_path(
            forest,
            root_dir,
            path_segments,
            filename,
        ));
    }

    pub fn synced_write_file(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
        content: Vec<u8>,
        modification_time_seconds: i64,
    ) -> Result<(Cid, AccessKey), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.write_file(
            forest,
            root_dir,
            path_segments,
            content,
            modification_time_seconds,
        ));
    }

    pub fn synced_read_file_to_path(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
        filename: &String,
    ) -> Result<String, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.read_file_to_path(forest, root_dir, path_segments, filename));
    }

    pub fn synced_read_file(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
    ) -> Result<Vec<u8>, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.read_file(forest, root_dir, path_segments));
    }

    pub fn synced_read_filestream_to_path(
        &mut self,
        local_filename: &String,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
        index: usize,
    ) -> Result<bool, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.read_filestream_to_path(
            local_filename,
            forest,
            root_dir,
            path_segments,
            index,
        ));
    }

    pub fn synced_mkdir(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
    ) -> Result<(Cid, AccessKey), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.mkdir(forest, root_dir, path_segments));
    }

    pub fn synced_mv(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        source_path_segments: &[String],
        target_path_segments: &[String],
    ) -> Result<(Cid, AccessKey), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.mv(
            forest,
            root_dir,
            source_path_segments,
            target_path_segments,
        ));
    }

    pub fn synced_cp(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        source_path_segments: &[String],
        target_path_segments: &[String],
    ) -> Result<(Cid, AccessKey), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.cp(
            forest,
            root_dir,
            source_path_segments,
            target_path_segments,
        ));
    }

    pub fn synced_rm(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
    ) -> Result<(Cid, AccessKey), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.rm(forest, root_dir, path_segments));
    }

    pub fn synced_ls_files(
        &mut self,
        forest: &mut Rc<PrivateForest>,
        root_dir: &mut Rc<PrivateDirectory>,
        path_segments: &[String],
    ) -> Result<Vec<(String, Metadata)>, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.ls_files(forest, root_dir, path_segments));
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

    use crate::{
        blockstore::FFIFriendlyBlockStore, kvstore::KVBlockStore,
        private_forest::PrivateDirectoryHelper,
    };

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
        let blockstore = FFIFriendlyBlockStore::new(Box::new(store));
        let helper = &mut PrivateDirectoryHelper::new(blockstore);
        let forest_cid = helper.create_private_forest().await.unwrap();
        println!("cid: {:?}", forest_cid);
        let forest = &mut helper.load_forest(forest_cid).await.unwrap();
        let (cid, access_key) = helper.init(forest, empty_key.to_owned()).await.unwrap();
        let root_dir = &mut helper
            .get_root_dir(forest.to_owned(), access_key.to_owned())
            .await
            .unwrap();
        println!("cid: {:?}", cid);
        println!("access_key: {:?}", access_key.to_owned());
        let (cid, access_key) = helper
            .write_file(
                forest,
                root_dir,
                &["root".into(), "hello".into(), "world.txt".into()],
                b"hello, world!".to_vec(),
                0,
            )
            .await
            .unwrap();
        println!("cid: {:?}", cid);
        println!("access_key: {:?}", access_key);
        let ls_result = helper.ls_files(forest, root_dir, &["root".into()]).await;
        println!("ls: {:?}", ls_result);
        let (cid, access_key) = helper
            .mkdir(forest, root_dir, &["root".into(), "hi".into()])
            .await
            .unwrap();
        println!("cid: {:?}", cid);
        println!("access_key: {:?}", access_key);
        let ls_result = helper
            .ls_files(forest, root_dir, &["root".into()])
            .await
            .unwrap();
        assert_eq!(ls_result.get(0).unwrap().0, "hello");
        assert_eq!(ls_result.get(1).unwrap().0, "hi");
        let content = helper
            .read_file(
                forest,
                root_dir,
                &["root".into(), "hello".into(), "world.txt".into()],
            )
            .await
            .unwrap();
        assert_eq!(content, b"hello, world!".to_vec());
        let (cid, access_key) = helper
            .rm(
                forest,
                root_dir,
                &["root".into(), "hello".into(), "world.txt".into()],
            )
            .await
            .unwrap();
        println!("cid: {:?}", cid);
        println!("access_key: {:?}", access_key.to_owned());
        let content = helper
            .read_file(
                forest,
                root_dir,
                &["root".into(), "hello".into(), "world.txt".into()],
            )
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
        let blockstore = FFIFriendlyBlockStore::new(Box::new(store));
        let helper = &mut PrivateDirectoryHelper::new(blockstore);
        let forest_cid = helper.create_private_forest().await.unwrap();
        println!("cid: {:?}", forest_cid);
        let forest = &mut helper.load_forest(forest_cid).await.unwrap();
        let (_, access_key) = helper.init(forest, empty_key.to_owned()).await.unwrap();
        let access_key_serialized = serde_json::to_string(&access_key).unwrap();
        println!("private ref: \n{}", access_key_serialized);
    }
}
