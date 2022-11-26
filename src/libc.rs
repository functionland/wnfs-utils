pub mod libc {
    extern crate libc;
    use libipld::Cid;
    use std::os::raw::c_char;
    use std::ffi::CString;
    use std::ptr::null_mut;
    use crate::blockstore::FFIStore;
    use crate::private_forest::PrivateDirectoryHelper;

    struct Store {

    }
    impl FFIStore for Store{
        fn get_block(&self, cid: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

        fn put_block(&self, cid: Vec<u8>, bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        todo!()
    }
    }
    #[no_mangle]
    pub extern "C" fn c_create_private_forest(
        c_db_path: *mut c_char,
    ) -> *mut c_char {
        unsafe {
            if c_db_path.is_null() {
                // No data there, already freed probably.
                return null_mut();
            }
    
            let db_path = CString::from_raw(c_db_path);
            let helper = &mut PrivateDirectoryHelper::new();
            serialize_cid(helper.synced_create_private_forest().unwrap())
        }
    }

    #[no_mangle]
    pub extern fn serialize_cid(
        cid: Cid,
    ) -> *mut c_char {
        // Convert the String into a CString
        let c_string: CString = CString::new(cid.to_string()).expect("Could not convert to CString");

        // Instead of returning the CString, we return a pointer for it.
        return c_string.into_raw();
    }

}
