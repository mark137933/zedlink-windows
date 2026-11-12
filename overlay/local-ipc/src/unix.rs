use super::*;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};

fn validate(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || metadata.is_dir() != directory
        || (!directory && !metadata.is_file()) || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "path must be private and owned by this user"));
    }
    Ok(())
}
pub fn validate_private_directory(path: &Path) -> io::Result<()> { validate(path, true) }
pub fn validate_private_file(path: &Path) -> io::Result<()> { validate(path, false) }
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => validate_private_directory(path),
        Err(error) => Err(error),
    }
}
pub fn create_private_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)
}
pub fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    fs::File::open(destination.parent().ok_or_else(|| io::Error::other("parent missing"))?)?.sync_all()
}
pub fn validate_endpoint(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "local socket must be private"));
    }
    Ok(())
}
pub struct Listener(tokio::net::UnixListener);
impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        validate_endpoint_parent(path)?;
        if fs::symlink_metadata(path).is_ok() {
            validate_endpoint(path)?;
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => return Err(io::Error::new(io::ErrorKind::AddrInUse, "local endpoint already active")),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(path)?,
                Err(error) => return Err(error),
            }
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(Self(listener))
    }
    pub async fn accept(&mut self) -> io::Result<asynchronous::Stream> {
        Ok(Box::new(self.0.accept().await?.0))
    }
}
pub async fn connect(path: &Path) -> io::Result<asynchronous::Stream> {
    Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
}
