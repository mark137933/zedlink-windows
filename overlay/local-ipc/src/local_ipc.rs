use std::{fs, io, path::Path};

#[cfg(windows)]
mod windows;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
use windows as platform;
#[cfg(unix)]
use unix as platform;

pub use platform::{create_private_directory, validate_private_directory, validate_private_file};

pub fn validate_endpoint_parent(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "local endpoint must be an absolute file path"));
    }
    validate_private_directory(path.parent().ok_or_else(|| io::Error::other("endpoint parent missing"))?)
}

pub fn validate_endpoint(path: &Path) -> io::Result<()> {
    validate_endpoint_parent(path)?;
    platform::validate_endpoint(path)
}

pub fn save_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let directory = path.parent().ok_or_else(|| io::Error::other("state parent missing"))?;
    validate_private_directory(directory)?;
    if path.exists() {
        validate_private_file(path)?;
    }
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?.as_nanos();
    let temporary = directory.join(format!(".state-{}-{nonce}.tmp", std::process::id()));
    let result = (|| {
        let mut file = platform::create_private_file(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        platform::replace_file(&temporary, path)
    })();
    if result.is_err() && temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    result
}

pub mod asynchronous {
    use super::*;
    use tokio::io::{AsyncRead, AsyncWrite};
    pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
    pub type Stream = Box<dyn Duplex>;
    pub use super::platform::Listener;

    pub async fn connect(path: &Path) -> io::Result<Stream> {
        validate_endpoint(path)?;
        platform::connect(path).await
    }
}

pub mod blocking {
    use super::*;
    use std::{sync::LazyLock, time::Duration};
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, runtime::{Builder, Runtime}};

    static RUNTIME: LazyLock<io::Result<Runtime>> = LazyLock::new(|| {
        Builder::new_multi_thread().worker_threads(1).enable_all().thread_name("zedlink-local-io").build()
    });
    fn runtime() -> io::Result<&'static Runtime> {
        RUNTIME.as_ref().map_err(|error| io::Error::other(error.to_string()))
    }
    pub struct Listener(asynchronous::Listener);
    impl Listener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            let _entered = runtime()?.enter();
            Ok(Self(asynchronous::Listener::bind(path)?))
        }
        pub fn incoming(&mut self) -> impl Iterator<Item = io::Result<Stream>> + '_ {
            std::iter::from_fn(move || Some(runtime().and_then(|runtime| {
                runtime.block_on(self.0.accept()).map(|inner| Stream {
                    inner, read_timeout: Duration::from_secs(3), write_timeout: Duration::from_secs(3),
                })
            })))
        }
    }
    pub struct Stream {
        inner: asynchronous::Stream,
        read_timeout: Duration,
        write_timeout: Duration,
    }
    impl Stream {
        pub fn connect(path: &Path) -> io::Result<Self> {
            let inner = runtime()?.block_on(async {
                tokio::time::timeout(Duration::from_secs(3), asynchronous::connect(path)).await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local connect timed out"))?
            })?;
            Ok(Self { inner, read_timeout: Duration::from_secs(6), write_timeout: Duration::from_secs(3) })
        }
        pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.read_timeout = timeout.filter(|value| !value.is_zero())
                .ok_or_else(|| io::Error::other("a positive bounded read timeout is required"))?;
            Ok(())
        }
        pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.write_timeout = timeout.filter(|value| !value.is_zero())
                .ok_or_else(|| io::Error::other("a positive bounded write timeout is required"))?;
            Ok(())
        }
    }
    impl io::Read for Stream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            runtime()?.block_on(async {
                tokio::time::timeout(self.read_timeout, self.inner.read(buffer)).await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local read timed out"))?
            })
        }
    }
    impl io::Write for Stream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            runtime()?.block_on(async {
                tokio::time::timeout(self.write_timeout, self.inner.write(buffer)).await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local write timed out"))?
            })
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
}
