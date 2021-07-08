#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AuthItem {
    All = auth_item_t_AUTHV_ALL,
    Challenge = auth_item_t_AUTHV_CHALLENGE,
    Class = auth_item_t_AUTHV_CLASS,
    Name = auth_item_t_AUTHV_NAME,
    Service = auth_item_t_AUTHV_SERVICE,
    Style = auth_item_t_AUTHV_STYLE,
    Interactive = auth_item_t_AUTHV_INTERACTIVE,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_open() {
        let session = unsafe { auth_open() };
        assert_ne!(session, std::ptr::null_mut());
        unsafe { auth_clean(session) };
    }

    #[test]
    fn test_auth_setoption() {
        let session = unsafe { auth_open() };
        assert_ne!(session, std::ptr::null_mut());
        let option = std::ffi::CString::new("some").unwrap();
        let value = std::ffi::CString::new("option").unwrap();
        let ret = unsafe { auth_setoption(session, option.into_raw(), value.into_raw()) };
        assert_ne!(ret, -1);
        unsafe { auth_clean(session) };
    }

    #[test]
    fn test_auth_clroption() {
        let session = unsafe { auth_open() };
        assert_ne!(session, std::ptr::null_mut());
        let option = std::ffi::CString::new("some").unwrap();
        let value = std::ffi::CString::new("option").unwrap();
        let ret = unsafe { auth_setoption(session, option.clone().into_raw(), value.into_raw()) };
        assert_ne!(ret, -1);
        unsafe { auth_clroption(session, option.into_raw()) };
        unsafe { auth_clean(session) };
    }

    #[test]
    fn test_auth_clroptions() {
        let session = unsafe { auth_open() };
        assert_ne!(session, std::ptr::null_mut());
        let option = std::ffi::CString::new("some").unwrap();
        let value = std::ffi::CString::new("option").unwrap();
        let ret = unsafe { auth_setoption(session, option.into_raw(), value.into_raw()) };
        assert_ne!(ret, -1);
        unsafe { auth_clroptions(session) };
        unsafe { auth_clean(session) };
    }

    #[test]
    fn test_auth_setdata() {
        let session = unsafe { auth_open() };
        assert_ne!(session, std::ptr::null_mut());
        let mut data = [0x65, 0x69, 0x66, 0x42];
        let data_ptr = data.as_mut_ptr() as *mut _;
        let ret = unsafe { auth_setdata(session, data_ptr, data.len() as u64) };
        assert_ne!(ret, -1);
        unsafe { auth_clean(session) };
    }

    #[test]
    fn test_auth_setitem() {
        let session = unsafe { auth_open() };
        assert_ne!(session, std::ptr::null_mut());

        let name = std::ffi::CString::new("nobody").unwrap();
        let name_ptr = name.clone().into_raw();
        let ret = unsafe { auth_setitem(session, AuthItem::Name as u32, name_ptr) };
        assert_eq!(ret, 0);

        let c_item = unsafe { auth_getitem(session, AuthItem::Name as u32) };
        assert_ne!(c_item, std::ptr::null_mut());
        let item = unsafe { std::ffi::CString::from_raw(c_item) };
        assert_eq!(item, name);

        // convert back to raw pointer to avoid double-free
        let _ptr = item.into_raw();

        let val = std::ffi::CString::new("value").unwrap();
        let val_ptr = val.clone().into_raw();
        let ret = unsafe { auth_setitem(session, AuthItem::Challenge as u32, val_ptr) };
        assert_eq!(ret, 0);

        let c_item = unsafe { auth_getitem(session, AuthItem::Challenge as u32) };
        assert_ne!(c_item, std::ptr::null_mut());
        let item = unsafe { std::ffi::CString::from_raw(c_item) };
        assert_eq!(item, val);

        let _ptr = item.into_raw();

        let ret = unsafe { auth_setitem(session, AuthItem::Class as u32, val.clone().into_raw()) };
        assert_eq!(ret, 0);

        let c_item = unsafe { auth_getitem(session, AuthItem::Class as u32) };
        assert_ne!(c_item, std::ptr::null_mut());
        let item = unsafe { std::ffi::CString::from_raw(c_item) };
        assert_eq!(item, val);

        let _ptr = item.into_raw();

        let ret = unsafe { auth_setitem(session, AuthItem::Service as u32, val.clone().into_raw()) };
        assert_eq!(ret, 0);

        let c_item = unsafe { auth_getitem(session, AuthItem::Service as u32) };
        assert_ne!(c_item, std::ptr::null_mut());
        let item = unsafe { std::ffi::CString::from_raw(c_item) };
        assert_eq!(item, val);

        let _ptr = item.into_raw();

        /* **DO NOT** allow setting Service with null ptr
         *
         * Sets session->service to defservice, which may point to invalid memory
         * In high-level bsd_auth lib, reject this pair as invalid
         *
         * let ret = unsafe { auth_setitem(session, AuthItem::Service as u32, std::ptr::null_mut()) };
         * assert_eq!(ret, 0);
         **/

        let ret = unsafe { auth_setitem(session, AuthItem::Style as u32, val.clone().into_raw()) };
        assert_eq!(ret, 0);

        let c_item = unsafe { auth_getitem(session, AuthItem::Style as u32) };
        assert_ne!(c_item, std::ptr::null_mut());
        let item = unsafe { std::ffi::CString::from_raw(c_item) };
        assert_eq!(item, val);

        let _ptr = item.into_raw();

        // Set Interactive item to any non-null to enable the flag
        let ret = unsafe { auth_setitem(session, AuthItem::Interactive as u32, val.clone().into_raw()) };
        assert_eq!(ret, 0);

        // Set Interactive with a null pointer to disable the flag
        let ret = unsafe { auth_setitem(session, AuthItem::Interactive as u32, std::ptr::null_mut()) };
        assert_eq!(ret, 0);

        let c_item = unsafe { auth_getitem(session, AuthItem::Interactive as u32) };
        assert_eq!(c_item, std::ptr::null_mut());

        let ret = unsafe { auth_setitem(session, AuthItem::All as u32, name.clone().into_raw()) };
        assert_eq!(ret, -1);

        let ret = unsafe { auth_setitem(session, AuthItem::All as u32, std::ptr::null_mut()) };
        assert_eq!(ret, 0);

        unsafe { auth_clean(session) };
    }

    #[test]
    fn test_auth_setpwd() {
        let session = unsafe { auth_open() };
        assert_ne!(session, std::ptr::null_mut());

        let ret = unsafe { auth_setpwd(session, std::ptr::null_mut()) };
        assert_eq!(ret, -1);

        let name = std::ffi::CString::new("nobody").unwrap();
        let ret = unsafe { auth_setitem(session, AuthItem::Name as u32, name.into_raw()) };
        assert_eq!(ret, 0);

        let ret = unsafe { auth_setpwd(session, std::ptr::null_mut()) };
        assert_eq!(ret, 0);

        unsafe { auth_clean(session) };
    }
}
