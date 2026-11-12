use super::*;
use sha2::{Digest, Sha256};
use std::{ffi::c_void, mem, os::windows::{ffi::OsStrExt, fs::MetadataExt, io::{AsRawHandle, FromRawHandle, OwnedHandle}}, ptr, time::Duration};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::*,
    Security::{*, Authorization::*},
    Storage::FileSystem::*,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct LocalMemory(*mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() { unsafe { LocalFree(self.0); } }
    }
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Windows path or pipe must be owned by this user and allow only this user and SYSTEM")
}
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) { return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path")); }
    value.push(0);
    Ok(value)
}
fn sid_text(sid: PSID) -> io::Result<String> {
    let mut output = ptr::null_mut();
    if unsafe { IsValidSid(sid) } == 0 { return Err(denied()); }
    if unsafe { ConvertSidToStringSidW(sid, &mut output) } == 0 { return Err(io::Error::last_os_error()); }
    let _allocation = LocalMemory(output.cast());
    let length = (0..256).find(|index| unsafe { *output.add(*index) == 0 }).ok_or_else(denied)?;
    Ok(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(output, length) }))
}
fn current_user() -> io::Result<String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut needed = 0;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, ptr::null_mut(), 0, &mut needed); }
    if needed == 0 { return Err(io::Error::last_os_error()); }
    let mut storage = vec![0usize; (needed as usize).div_ceil(mem::size_of::<usize>())];
    if unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, storage.as_mut_ptr().cast(), needed, &mut needed) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    sid_text(user.User.Sid)
}
fn descriptor(directory: bool) -> io::Result<LocalMemory> {
    let user = current_user()?;
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("O:{user}D:P(A;{inheritance};FA;;;{user})(A;{inheritance};FA;;;SY)");
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut result = ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut result, ptr::null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalMemory(result))
}
fn attributes(descriptor: &LocalMemory) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}
fn validate_security(owner: PSID, acl: *mut ACL) -> io::Result<()> {
    let user = current_user()?;
    if owner.is_null() || acl.is_null() || sid_text(owner)? != user { return Err(denied()); }
    let mut has_user = false;
    for index in 0..unsafe { (*acl).AceCount } {
        let mut entry = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut entry) } == 0 { return Err(io::Error::last_os_error()); }
        let header = unsafe { &*entry.cast::<ACE_HEADER>() };
        match header.AceType {
            0 => {
                // ACCESS_ALLOWED_ACE has a variable-length SID beginning at SidStart.
                if usize::from(header.AceSize) < mem::size_of::<ACCESS_ALLOWED_ACE>() { return Err(denied()); }
                let allowed = unsafe { &*entry.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = ptr::addr_of!(allowed.SidStart).cast_mut().cast();
                let name = sid_text(sid)?;
                if name == user { has_user = true; }
                else if name != "S-1-5-18" { return Err(denied()); }
            }
            1 => {}, // A deny ACE cannot broaden access.
            _ => return Err(denied()),
        }
    }
    if !has_user { return Err(denied()); }
    Ok(())
}
fn validate_handle(handle: HANDLE) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut security = ptr::null_mut();
    let status = unsafe { GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &mut owner, ptr::null_mut(), &mut acl, ptr::null_mut(), &mut security) };
    if status != 0 { return Err(io::Error::from_raw_os_error(status as i32)); }
    let _allocation = LocalMemory(security);
    validate_security(owner, acl)
}
fn validate_path(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || metadata.is_dir() != directory
        || (!directory && !metadata.is_file()) { return Err(denied()); }
    let path = wide(path)?;
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut security = ptr::null_mut();
    let status = unsafe { GetNamedSecurityInfoW(path.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &mut owner, ptr::null_mut(), &mut acl, ptr::null_mut(), &mut security) };
    if status != 0 { return Err(io::Error::from_raw_os_error(status as i32)); }
    let _allocation = LocalMemory(security);
    validate_security(owner, acl)
}
pub fn validate_private_directory(path: &Path) -> io::Result<()> { validate_path(path, true) }
pub fn validate_private_file(path: &Path) -> io::Result<()> { validate_path(path, false) }
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "absolute private directory required")); }
    let descriptor = descriptor(true)?;
    let attributes = attributes(&descriptor);
    if unsafe { CreateDirectoryW(wide(path)?.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists { return Err(error); }
    }
    validate_private_directory(path)
}
pub fn create_private_file(path: &Path) -> io::Result<fs::File> {
    let descriptor = descriptor(false)?;
    let attributes = attributes(&descriptor);
    let handle = unsafe { CreateFileW(wide(path)?.as_ptr(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, ptr::null_mut()) };
    if handle == INVALID_HANDLE_VALUE { return Err(io::Error::last_os_error()); }
    Ok(unsafe { fs::File::from_raw_handle(handle) })
}
pub fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    if unsafe { MoveFileExW(wide(source)?.as_ptr(), wide(destination)?.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub fn validate_endpoint(path: &Path) -> io::Result<()> {
    // The .sock path is a logical endpoint on Windows, never a file or TCP listener.
    match fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(io::ErrorKind::AlreadyExists, "logical pipe path is occupied by a file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
fn pipe_name(path: &Path) -> io::Result<String> {
    validate_endpoint_parent(path)?;
    validate_endpoint(path)?;
    let parent = fs::canonicalize(path.parent().ok_or_else(|| io::Error::other("parent missing"))?)?;
    let normalized = parent.join(path.file_name().ok_or_else(|| io::Error::other("name missing"))?)
        .to_str().ok_or_else(|| io::Error::other("pipe path must be Unicode"))?.to_lowercase();
    let identity = format!("{}\n{normalized}", current_user()?);
    Ok(format!(r"\\.\pipe\zedlink-{:x}", Sha256::digest(identity.as_bytes())))
}
fn new_server(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let descriptor = descriptor(false)?;
    let mut attributes = attributes(&descriptor);
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first).reject_remote_clients(true).in_buffer_size(65536).out_buffer_size(65536);
    // The descriptor and SECURITY_ATTRIBUTES live until CreateNamedPipeW returns.
    unsafe { options.create_with_security_attributes_raw(name, ptr::from_mut(&mut attributes).cast()) }
}
pub struct Listener { name: String, pending: NamedPipeServer }
impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let name = pipe_name(path)?;
        let pending = new_server(&name, true)?;
        Ok(Self { name, pending })
    }
    pub async fn accept(&mut self) -> io::Result<asynchronous::Stream> {
        self.pending.connect().await?;
        // Reserve the next instance before releasing this one to prevent name takeover.
        let next = new_server(&self.name, false)?;
        let connected = mem::replace(&mut self.pending, next);
        Ok(Box::new(connected))
    }
}
pub async fn connect(path: &Path) -> io::Result<asynchronous::Stream> {
    let name = pipe_name(path)?;
    loop {
        match ClientOptions::new().security_qos_flags(SECURITY_IDENTIFICATION).open(&name) {
            Ok(client) => {
                validate_handle(client.as_raw_handle())?;
                return Ok(Box::new(client));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => return Err(error),
        }
    }
}
