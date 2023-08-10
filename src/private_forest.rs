//! This example shows how to add a directory to a private forest (also HAMT) which encrypts it.
//! It also shows how to retrieve encrypted nodes from the forest using `AccessKey`s.

use async_trait::async_trait;
use chrono::{prelude::*, Utc};
use futures::StreamExt;
use libipld::Cid;
use rand::{rngs::ThreadRng, thread_rng};
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use rsa::{traits::PublicKeyParts, BigUint, Oaep, RsaPrivateKey, RsaPublicKey};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    rc::Rc,
    sync::Mutex,
    time::SystemTime,
};

use wnfs::{
    common::{utils, BlockStore, Metadata, CODEC_RAW},
    hamt::Hasher,
    namefilter::Namefilter,
    private::{
        share::{recipient, sharer},
        AccessKey, AesKey, ExchangeKey, PrivateDirectory, PrivateForest, PrivateKey,
        PUBLIC_KEY_EXPONENT,
    },
    public::{PublicDirectory, PublicLink, PublicNode},
};

use anyhow::{anyhow, Result};
use log::trace;
use sha3::Sha3_256;

use crate::blockstore::FFIFriendlyBlockStore;
use tokio::fs::File as TokioFile;
use tokio::io::Result as IoResult;

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

pub struct PrivateDirectoryHelper<'a> {
    pub store: FFIFriendlyBlockStore<'a>,
    forest: Rc<PrivateForest>,
    root_dir: Rc<PrivateDirectory>,
    rng: ThreadRng,
}

// Single root (private ref) implementation of the wnfs private directory using KVBlockStore.
// TODO: we assumed all the write, mkdirs use same roots here. this could be done using prepend
// a root path to all path segments.
impl<'a> PrivateDirectoryHelper<'a> {
    async fn reload(
        store: &mut FFIFriendlyBlockStore<'a>,
        cid: Cid,
    ) -> Result<PrivateDirectoryHelper<'a>, String> {
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

    fn bytes_to_hex_str(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    async fn setup_seeded_keypair_access(
        forest: &mut Rc<PrivateForest>,
        access_key: AccessKey,
        store: &mut FFIFriendlyBlockStore<'a>,
        seed: [u8; 32],
    ) -> Result<[u8; 32]> {
        let root_did = Self::bytes_to_hex_str(&seed);
        let exchange_keypair = SeededExchangeKey::from_seed(seed.clone())?;

        // Store the public key inside some public WNFS.
        // Building from scratch in this case. Would actually be stored next to the private forest usually.
        let public_key_cid = exchange_keypair.store_public_key(store).await?;
        let mut exchange_root = Rc::new(PublicDirectory::new(Utc::now()));
        exchange_root
            .write(
                &["main".into(), "v1.exchange_key".into()],
                public_key_cid,
                Utc::now(),
                store,
            )
            .await?;
        let exchange_root = PublicLink::new(PublicNode::Dir(exchange_root));

        // The user identity's root DID. In practice this would be e.g. an ed25519 key used
        // for e.g. UCANs or key usually used for authenticating writes.

        let counter = recipient::find_latest_share_counter(
            0,
            1000,
            &exchange_keypair.encode_public_key(),
            &root_did,
            forest,
            store,
        )
        .await?
        .map(|x| x + 1)
        .unwrap_or_default();

        // Write the encrypted AccessKey into the forest
        sharer::share::<PublicExchangeKey>(
            &access_key,
            counter,
            &root_did,
            forest,
            exchange_root,
            store,
        )
        .await?;
        Ok(seed)
    }

    async fn init(
        store: &mut FFIFriendlyBlockStore<'a>,
        wnfs_key: Vec<u8>,
    ) -> Result<(PrivateDirectoryHelper<'a>, AccessKey, Cid), String> {
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
            let (forest, _) = &mut forest_res.ok().unwrap();
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
                let root_dir = &mut root_dir_res.ok().unwrap();
                let access_key = root_dir.as_node().store(forest, store, rng).await;
                if access_key.is_ok() {
                    let seed: [u8; 32] = wnfs_key.to_owned().try_into().expect("Length mismatch");
                    let access_key_unwrapped = access_key.ok().unwrap();
                    let seed_res = Self::setup_seeded_keypair_access(
                        forest,
                        access_key_unwrapped.to_owned(),
                        store,
                        seed,
                    )
                    .await;
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
                            Self {
                                store: store.to_owned(),
                                forest: forest.to_owned(),
                                root_dir: root_dir.to_owned(),
                                rng: rng.to_owned(),
                            },
                            access_key_unwrapped,
                            forest_cid.unwrap(),
                        ))
                    } else {
                        trace!(
                            "wnfsError in init:setup_seeded_keypair_access : {:?}",
                            seed_res.as_ref().err().unwrap().to_string()
                        );
                        Err(seed_res.err().unwrap().to_string())
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
        store: &mut FFIFriendlyBlockStore<'a>,
        forest_cid: Cid,
        wnfs_key: Vec<u8>,
    ) -> Result<PrivateDirectoryHelper<'a>, String> {
        trace!("wnfsutils: load_with_wnfs_key started");
        let rng = &mut thread_rng();
        let root_did: String;
        let seed: [u8; 32];
        if wnfs_key.is_empty() {
            let wnfs_random_key = AesKey::new(utils::get_random_bytes::<32>(rng));
            let ratchet_seed = Sha3_256::hash(&wnfs_random_key.as_bytes());
            root_did = Self::bytes_to_hex_str(&ratchet_seed);
            seed = ratchet_seed;
        } else {
            root_did = Self::bytes_to_hex_str(&wnfs_key);
            seed = wnfs_key.to_owned().try_into().expect("Length mismatch");
        }
        let exchange_keypair_res = SeededExchangeKey::from_seed(seed);
        if exchange_keypair_res.is_ok() {
            let exchange_keypair = exchange_keypair_res.ok().unwrap();
            trace!(
                "wnfsutils: load_with_wnfs_key with forest_cid: {:?}",
                forest_cid
            );
            let forest_res =
                PrivateDirectoryHelper::load_private_forest(store.to_owned(), forest_cid).await;
            if forest_res.is_ok() {
                let forest = &mut forest_res.ok().unwrap();
                // Create a root directory from the ratchet_seed, inumber and namefilter. Directory gets saved in forest.
                // Re-load private node from forest
                let counter_res = recipient::find_latest_share_counter(
                    0,
                    1000,
                    &exchange_keypair.encode_public_key(),
                    &root_did,
                    forest,
                    store,
                )
                .await;
                if counter_res.is_ok() {
                    let counter = counter_res.ok().unwrap().map(|x| x).unwrap_or_default();
                    trace!("wnfsutils: load_with_wnfs_key with counter: {:?}", counter);
                    let label = sharer::create_share_label(
                        counter,
                        &root_did,
                        &exchange_keypair.encode_public_key(),
                    );
                    let node_res =
                        recipient::receive_share(label, &exchange_keypair, forest, store).await;
                    if node_res.is_ok() {
                        let node = node_res.ok().unwrap();
                        let latest_node = node.search_latest(forest, store).await;

                        if latest_node.is_ok() {
                            let latest_root_dir = latest_node.ok().unwrap().as_dir();
                            if latest_root_dir.is_ok() {
                                unsafe {
                                    STATE.lock().unwrap().update(true, wnfs_key.to_owned());
                                }
                                Ok(Self {
                                    store: store.to_owned(),
                                    forest: forest.to_owned(),
                                    root_dir: latest_root_dir.ok().unwrap(),
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
                                latest_node.as_ref().to_owned().err().unwrap().to_string()
                            );
                            Err(latest_node.as_ref().to_owned().err().unwrap().to_string())
                        }
                    } else {
                        let err = node_res.as_ref().to_owned().err().unwrap().to_string();
                        trace!(
                            "wnfsError occured in load_with_wnfs_key node_res: {:?}",
                            err
                        );
                        Err(err)
                    }
                } else {
                    let err = counter_res.as_ref().to_owned().err().unwrap().to_string();
                    trace!(
                        "wnfsError occured in load_with_wnfs_key counter_res: {:?}",
                        err
                    );
                    Err(err)
                }
            } else {
                let err = forest_res.as_ref().to_owned().err().unwrap().to_string();
                trace!("wnfsError occured in load_with_wnfs_key: {:?}", err);
                Err(err)
            }
        } else {
            let err = exchange_keypair_res
                .as_ref()
                .to_owned()
                .err()
                .unwrap()
                .to_string();
            trace!(
                "wnfsError occured in load_with_wnfs_key exchange_keypair_res: {:?}",
                err
            );
            Err(err)
        }
    }

    async fn create_private_forest(
        store: FFIFriendlyBlockStore<'a>,
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
        store: FFIFriendlyBlockStore<'a>,
        forest_cid: Cid,
    ) -> Result<Rc<PrivateForest>, String> {
        // Deserialize private forest from the blockstore.
        let forest = store.get_deserializable::<PrivateForest>(&forest_cid).await;
        if forest.is_ok() {
            Ok(Rc::new(forest.ok().unwrap()))
        } else {
            trace!(
                "wnfsError occured in load__private_forest: {:?}",
                forest.as_ref().err().unwrap()
            );
            Err(forest.err().unwrap().to_string())
        }
    }

    pub async fn update_private_forest(
        store: FFIFriendlyBlockStore<'a>,
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

    // The new get_file_as_stream method:
    pub async fn get_file_as_stream(&self, filename: &String) -> IoResult<(TokioFile, i64)> {
        let file = TokioFile::open(filename).await?;
        let metadata = tokio::fs::metadata(filename).await?;
        let modified = metadata
            .modified()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let modification_time_seconds = modified
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
            .as_secs() as i64;

        Ok((file, modification_time_seconds))
    }

    pub async fn write_file_stream_from_path(
        &mut self,
        path_segments: &[String],
        filename: &String,
    ) -> Result<Cid, String> {
        let filedata = async_std::fs::File::open(filename).await;
        if let Ok(file) = filedata {
            let metadata = file.metadata().await;
            if metadata.is_err() {
                return Err(format!(
                    "Failed to get file metadata: {:?}",
                    metadata.err().unwrap()
                ));
            }
            let modification_time_seconds = metadata
                .unwrap()
                .modified()
                .unwrap()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let mut reader = async_std::io::BufReader::new(file);
            let writefile_res = self
                .write_file_stream(path_segments, &mut reader, modification_time_seconds)
                .await;
            match writefile_res {
                Ok(res) => Ok(res),
                Err(e) => {
                    trace!("wnfsError in write_file_stream_from_path: {:?}", e);
                    Err(e.to_string())
                }
            }
        } else {
            let e = filedata.err().unwrap();
            trace!("wnfsError in write_file_stream_from_path: {:?}", e);
            Err(e.to_string())
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

    pub async fn write_file_stream(
        &mut self,

        path_segments: &[String],
        mut content: &mut async_std::io::BufReader<async_std::fs::File>,
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

        let file_open_res = root_dir
            .open_file_mut(
                path_segments,
                true,
                modification_time_utc,
                forest,
                &mut self.store,
                &mut self.rng,
            )
            .await;
        if file_open_res.is_ok() {
            let file = file_open_res.unwrap();
            let write_res = file
                .set_content(
                    modification_time_utc,
                    &mut content,
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
        } else {
            trace!(
                "wnfsError in write_file_stream: {:?}",
                file_open_res.as_ref().err().unwrap().to_string()
            );
            Err(file_open_res.err().unwrap().to_string())
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
                                if block.is_ok() {
                                    let write_result = local_file_handler.write_all(&block.unwrap());
                                    if write_result.is_err() {
                                        trace!("wnfsError occured in read_filestream_to_path on write_result: {:?}", write_result.as_ref().err().unwrap().to_string());
                                    }
                                } else {
                                    trace!(
                                        "wnfsError occured in read_filestream_to_path on file_res: {:?}",
                                        block.as_ref().err().unwrap().to_string()
                                    );
                                    return Err(
                                        block
                                        .err()
                                        .unwrap()
                                        .to_string()
                                    )
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
impl<'a> PrivateDirectoryHelper<'a> {
    pub fn synced_init(
        store: &mut FFIFriendlyBlockStore<'a>,
        wnfs_key: Vec<u8>,
    ) -> Result<(PrivateDirectoryHelper<'a>, AccessKey, Cid), String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(PrivateDirectoryHelper::init(store, wnfs_key));
    }

    pub fn synced_load_with_wnfs_key(
        store: &mut FFIFriendlyBlockStore<'a>,
        forest_cid: Cid,
        wnfs_key: Vec<u8>,
    ) -> Result<PrivateDirectoryHelper<'a>, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(PrivateDirectoryHelper::load_with_wnfs_key(
            store, forest_cid, wnfs_key,
        ));
    }

    pub fn synced_reload(
        store: &mut FFIFriendlyBlockStore<'a>,
        forest_cid: Cid,
    ) -> Result<PrivateDirectoryHelper<'a>, String> {
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

    pub fn synced_write_file_stream_from_path(
        &mut self,
        path_segments: &[String],
        filename: &String,
    ) -> Result<Cid, String> {
        let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        return runtime.block_on(self.write_file_stream_from_path(path_segments, filename));
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

struct SeededExchangeKey(RsaPrivateKey);

struct PublicExchangeKey(RsaPublicKey);

impl SeededExchangeKey {
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let rng = &mut ChaCha12Rng::from_seed(seed);
        let private_key = RsaPrivateKey::new(rng, 2048)?;
        Ok(Self(private_key))
    }

    pub async fn store_public_key(&self, store: &impl BlockStore) -> Result<Cid> {
        store.put_block(self.encode_public_key(), CODEC_RAW).await
    }

    pub fn encode_public_key(&self) -> Vec<u8> {
        self.0.n().to_bytes_be()
    }
}

#[async_trait(?Send)]
impl PrivateKey for SeededExchangeKey {
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha3_256>();
        self.0.decrypt(padding, ciphertext).map_err(|e| anyhow!(e))
    }
}

#[async_trait(?Send)]
impl ExchangeKey for PublicExchangeKey {
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha3_256>();
        self.0
            .encrypt(&mut rand::thread_rng(), padding, data)
            .map_err(|e| anyhow!(e))
    }

    async fn from_modulus(modulus: &[u8]) -> Result<Self> {
        let n = BigUint::from_bytes_be(modulus);
        let e = BigUint::from(PUBLIC_KEY_EXPONENT);

        Ok(Self(rsa::RsaPublicKey::new(n, e).map_err(|e| anyhow!(e))?))
    }
}

#[cfg(test)]
mod private_forest_tests;
