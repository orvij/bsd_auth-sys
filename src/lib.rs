#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

//include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Request item values for auth_getitem()
///
/// Item documentation from `auth_subr(3)`
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AuthItem {
    /// All items
    All = 0,
    /// The latest challenge, if any, set for the session
    Challenge = 1,
    /// The class of the user, as defined by the `/etc/login.conf` file.
    /// This value is not directly used by BSD Authentication, rather, it is passed to the login
    /// scripts for their possible use.
    Class = 2,
    /// The name of the user being authenticated.
    /// The name should include the instance, if any, that is being requested.
    Name = 3,
    /// The service requesting the authentication.
    /// Initially it is set to the default service which provides the traditional interactive service.
    Service = 4,
    /// The style of authentication being performed, as defined by the `/etc/login.conf` file.
    /// The style determines which login script should actually be used.
    Style = 5,
    /// If set to any value, then the session is tagged as interactive. If not set, the session is
    /// not interactive. When the value is requested it is always either NULL or "True".
    /// The auth subroutines may choose to provide additional information to standard output or
    /// standard error when the session is interactive.
    /// There is no functional change in the operation of the subroutines.
    Interactive = 6,
}


/// Raw FFI interface to authentication session struct
///
/// No access to internal members
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct auth_session_t {
    _unused: [u8; 0],
}

extern "C" {
    /// Opens a BSD Authentication session
    ///
    /// Returns a raw pointer to an auth_session_t
    /// Returns a null pointer if unable to allocate memory for the session
    pub fn auth_open() -> *mut auth_session_t;
    
    /// Get a challenge string for the BSD Authentication session
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// The `auth_challenge()` function queries the login script defined by the current `style` for a
    /// challenge for the user specified by `name`. It internally uses the `auth_call()` function.
    /// The generated challenge is returned. NULL is returned on error or if no challenge was
    /// generated. The challenge can also be extracted by the `auth_getchallenge()` function, which
    /// simply returns the last challenge generated for this session.
    /// ```
    pub fn auth_challenge(_as: *mut auth_session_t) -> *mut libc::c_char;
    
    /// Terminates the BSD Authentication session
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// Also sets any environment variables requested by the login script (assuming the user was
    /// not rejected) or removes files created b the login script if the authentication was not
    /// successful. It returns the final state of the authentication request. A return value of 0
    /// implies the user was not authenticated. A non-zero return value is made up of 1 or more of
    /// the following values ORed together:
    ///
    /// AUTH_OKAY       The user was authenticated.
    ///
    /// AUTH_ROOTOKAY   The user was authenticated with a root instance.
    ///
    /// AUTH_SECURE     The user was authenticated via a mechanism which is not subject to
    ///                 eavesdropping attacks (such as provided by token cards).
    /// ```
    pub fn auth_close(_as: *mut auth_session_t) -> libc::c_int;
    
    /// Get the full state of the session
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// In addtion to the values for `auth_close()`, it also may contain the bits:
    ///
    /// AUTH_SILENT     Do not report an error, the user was not authenticated for access and was
    ///                 not expected to be. This is returned by login scripts that allow changing
    ///                 of the user's password, for instance. This value is stripped off for normal
    ///                 returns.
    ///
    /// AUTH_CHALLENGE  The user was not authenticated for access and a challenge was issued. The
    ///                 challenge should be displayed to the user, a response received, and the
    ///                 result verified. This value is stripped off for normal returns.
    ///
    /// AUTH_EXPIRED    The user's account has expired.
    ///
    /// AUTH_PWEXPIRED  The user's password has expired and needs to be changed.
    /// ```
    pub fn auth_getstate(_as: *mut auth_session_t) -> libc::c_int;

    /// Clean the BSD Authentication session
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// This function removes any files created by a login script in this session and clears all
    /// state associated with this session, with the exception of the option settings. It is not
    /// necessary to call `auth_clean()` if `auth_close()` is called.
    /// ```
    pub fn auth_clean(_as: *mut auth_session_t);
    
    /// Add/delete environment variables from the BSD Authentication session
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// Adds/deletes any environment variables requested by the login script to the current
    /// environemnt.
    /// ```
    pub fn auth_setenv(_as: *mut auth_session_t);
    
    /// Clear requests set by the login script
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// Clears any requests set by a login script for environment variables to be set.
    /// ```
    pub fn auth_clrenv(_as: *mut auth_session_t);
    
    /// Get the value of the `item`
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// The `item` may be one of:
    ///
    /// AUTH_CHALLENGE      The latest challenge, if any, set for the session
    ///
    /// AUTH_CLASS          The class of the user, as defined by the `/etc/login.conf` file. This 
    ///                     value is not directly used by BSD Authentication, rather, it is passed
    ///                     to the login scripts for their possible use.
    ///
    /// AUTH_NAME           The name of the user being authenticated. The name should include the
    ///                     instance, if any, that is being requested.
    ///
    /// AUTH_SERVICE        The service requesting the authentication. Initially it is set to the
    ///                     default service which provides the traditional interactive service.
    ///
    /// AUTH_STYLE          The style of authentication being performed, as defined by the
    ///                     `/etc/login.conf` file. The style determines which login script should
    ///                     actually be used.
    ///
    /// AUTH_INTERACTIVE    If set to any value, then the session is tagged as interactive. If not
    ///                     set, the session is not interactive. When the value is requested it is
    ///                     always either NULL or "True". The auth subroutines may choose to provide
    ///                     additional information to standard output or standard error when the
    ///                     session is interactive. There is no functional change in the operation
    ///                     of the subroutines.
    /// ```
    pub fn auth_getitem(
        _as: *mut auth_session_t,
        _item: libc::c_uint,
    ) -> *mut libc::c_char;
    
    /// Assigns value to the specified item
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// Assigns `value` to the specified `item`. The items are described above with the
    /// `auth_getitem()` function. In addition, if `value` is NULL, the `item` is cleared. If
    /// `value` is NULL` and `item` is AUTH_ALL then all items are cleared.
    /// ```
    pub fn auth_setitem(
        _as: *mut auth_session_t,
        _item: libc::c_uint,
        _value: *mut libc::c_char,
    ) -> libc::c_int;
    
    /// Set an option specified by name with the given value
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// Requests that the option `name` be set with the value of `value` when a script is executed
    /// by `auth_call()`. The actual arguments to the script will be placed at the beginning of the
    /// argument vector. For each option two arguments will be issued: -v name=value.
    /// ```
    pub fn auth_setoption(
        _as: *mut auth_session_t,
        _name: *mut libc::c_char,
        _value: *mut libc::c_char,
    ) -> libc::c_int;

    /// Set the password for the auth session
    pub fn auth_setpwd(
        _as: *mut auth_session_t,
        _pwd: *mut libc::passwd
    ) -> libc::c_int;

    /// Manually set the authenticatio state for the session
    pub fn auth_setstate(_as: *mut auth_session_t, _state: libc::c_int);
    
    /// Clears all previously set options
    pub fn auth_clroptions(_as: *mut auth_session_t);
    
    /// Clears the previously set option `name`
    pub fn auth_clroption(_as: *mut auth_session_t, _name: *mut libc::c_char);
    
    /// Pass data to the BSD Authentication session to be used by a login script
    ///
    /// From `auth_subr(3)`:
    ///
    /// ```no_build
    /// Makes a copy of `len` bytes of data pointed to by `ptr` for use by `auth_call()`. The data
    /// will be passed on the back channel to the next login script called.
    /// ```
    pub fn auth_setdata(
        _as: *mut auth_session_t,
        _ptr: *mut libc::c_void,
        _len: u64,
    ) -> libc::c_int;
    
    /// A single function interface to `auth_userokay`, but returns the opened BSD Authentication
    /// session
    ///
    /// From `authenticate(3)`:
    ///
    /// ```no_build
    /// The `auth_usercheck()` function operates the same as the `auth_userokay()` function except
    /// that it does not close the BSD Authentication session created. Rather than returning the
    /// status of the session, it returns a pointer to the newly created BSD Authentication
    /// session.
    /// ```
    pub fn auth_usercheck(
        _name: *mut libc::c_char,
        _style: *mut libc::c_char,
        _type: *mut libc::c_char,
        _password: *mut libc::c_char,
    ) -> *mut auth_session_t;
    
    /// Provides a single function interface to a BSD Authentication session
    ///
    /// From `authenticate(3)`:
    ///
    /// ```no_build
    /// Provided with a user's name in `name`, and an optional `style`, `type`, and `password`, the
    /// `auth_userokay()` function returns a simple yes/no response. A return value of 0 implies
    /// failure; a non-zero return value implies success. If `style` is not NULL, it specifies the
    /// desired style of authentication to be used. If it is NULL then the default style for the
    /// user is used. In this case, `name` may include the desired style by appending it to the
    /// user's name with a single colon (':') as a separator. If `type` is not NULL then it is used
    /// as the authentication type (such as "auth-myservice"). If `password` is NULL then
    /// `auth_userokay()` operates in an interactive mode with the user on standard input, output,
    /// and error. If `password` is specified, `auth_userokay()` operates in a non-interactive mode
    /// and only tests the specified passwords. This non-interactive method does not work with
    /// challenge-response authentication styles. For security reasons, when a `password` is
    /// specified, `auth_userokay()` will zero out its value before it returns.
    /// ```
    pub fn auth_userokay(
        _name: *mut libc::c_char,
        _style: *mut libc::c_char,
        _type: *mut libc::c_char,
        _password: *mut libc::c_char,
    ) -> libc::c_int;
    
    /// Create a BSD Authentication session, and get a challenge for a challenge-response
    /// authentication flow
    ///
    /// From `authenticate(3)`:
    ///
    /// ```no_build
    /// Takes the same `name`, `style`, and `type` argments as does `auth_userokay()`. However,
    /// rather than authenticating the user, it returns a possible challenge in the pointer pointed
    /// to by `challengep`. The return value of the function is a pointer to a newly created BSD
    /// Authentication session. This challenge, if not NULL, should be displayed to the user.
    /// ```
    pub fn auth_userchallenge(
        _name: *mut libc::c_char,
        _style: *mut libc::c_char,
        _type: *mut libc::c_char,
        _challengep: *mut *mut libc::c_char,
    ) -> *mut auth_session_t;
    
    /// Complete the challenge-response authentication initiated by `auth_userchallenge`
    ///
    /// Closes the BSD Authentication session
    ///
    /// From `authenticate(3)`:
    ///
    /// ```no_build
    /// The user should provide a password which is the `response`. In addition to the password,
    /// the pointer returned `auth_userchallenge()` shoud be passed in as `as` and the value of
    /// `more` should be non-zero if the program wishes to allow more attempts. If `more` is zero
    /// then the session will be closed. The `auth_userresponse()` function closes the BSD
    /// Authentication session and has the same return value as `auth_userokay()`. For security
    /// reasons, when a `response` is specified, `auth_userresponse()` will zero out its value
    /// before it returns.
    /// ```
    pub fn auth_userresponse(
        _as: *mut auth_session_t,
        _response: *mut libc::c_char,
        _more: libc::c_int,
    ) -> libc::c_int; 
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
