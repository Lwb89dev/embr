//! Windows named-pipe endpoints with a **user-only DACL**.
//!
//! A named pipe created with default security is readable by other users. Embr builds a security
//! descriptor `D:P(A;;GA;;;<current-user-SID>)` (protected DACL, one ACE: full access for the user who
//! runs the daemon, nobody else — not even Administrators or SYSTEM get an explicit entry), refuses
//! remote clients, and creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE` so a process
//! that squatted the pipe name makes the daemon fail to start instead of being talked to.
//!
//! This is the only module in the workspace that uses `unsafe`: Win32 calls via `windows-sys`.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The SID (as `S-1-5-21-…`) of the user running this process.
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: standard token query. Every pointer passed is to a live local; buffers are sized by the
    // two-call GetTokenInformation protocol; the token handle and the SID string are released.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error());
        }
        let result = (|| {
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                return Err(last_error());
            }
            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) == 0
            {
                return Err(last_error());
            }
            let user = &*(buf.as_ptr().cast::<TOKEN_USER>());
            let mut pstr: *mut u16 = ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut pstr) == 0 {
                return Err(last_error());
            }
            let mut len = 0usize;
            while *pstr.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(pstr, len));
            LocalFree(pstr.cast());
            Ok(s)
        })();
        CloseHandle(token);
        result
    }
}

/// A security descriptor granting access to the current user only. Frees itself on drop.
pub struct UserOnlySecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attrs: SECURITY_ATTRIBUTES,
}

// SAFETY: the descriptor is an immutable, self-contained block of memory owned by this value.
unsafe impl Send for UserOnlySecurity {}
unsafe impl Sync for UserOnlySecurity {}

impl UserOnlySecurity {
    /// Builds the descriptor for the current user.
    pub fn new() -> io::Result<Self> {
        let sddl = wide(&format!("D:P(A;;GA;;;{})", current_user_sid()?));
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string that outlives the call; `descriptor` receives
        // a LocalAlloc'd block that we free in `Drop`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok(Self { descriptor, attrs })
    }
}

impl Drop for UserOnlySecurity {
    fn drop(&mut self) {
        // SAFETY: `descriptor` was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            LocalFree(self.descriptor.cast());
        }
    }
}

/// Creates one instance of the named pipe `name` (`\\.\pipe\…`): user-only DACL, remote clients
/// refused; `first` adds `FILE_FLAG_FIRST_PIPE_INSTANCE` (fails if the name already exists).
pub fn create_pipe_instance(
    name: &str,
    first: bool,
    security: &UserOnlySecurity,
) -> io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first).reject_remote_clients(true);
    let attrs = ptr::addr_of!(security.attrs).cast_mut().cast::<c_void>();
    // SAFETY: `attrs` points to a SECURITY_ATTRIBUTES (with a valid descriptor) that lives at least as
    // long as `security`, which the caller holds across this call; CreateNamedPipe copies the descriptor.
    unsafe { opts.create_with_security_attributes_raw(name, attrs) }
}

/// Process id of the client connected to `server`, if Windows reports one. A *hint* only.
pub fn pipe_client_pid(server: &NamedPipeServer) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: the handle belongs to a live pipe server; `pid` is a valid out pointer.
    let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as HANDLE, &mut pid) };
    (ok != 0).then_some(pid)
}
