use std::{fs, io::{Read, Write}, time::Duration};
use zedlink_local_ipc::{self as ipc, asynchronous, blocking};

fn private_directory() -> (tempfile::TempDir, std::path::PathBuf) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let directory = temporary.path().join("private");
    ipc::create_private_directory(&directory).expect("private directory");
    (temporary, directory)
}

#[test]
fn private_state_replacement_preserves_permissions() {
    let (_temporary, directory) = private_directory();
    let state = directory.join("state.json");
    ipc::save_private(&state, b"first").expect("initial state");
    ipc::save_private(&state, b"second").expect("atomic replacement");
    ipc::validate_private_file(&state).expect("private state ACL");
    assert_eq!(fs::read(state).expect("read state"), b"second");
    assert_eq!(fs::read_dir(directory).expect("list directory").count(), 1);
}

#[test]
fn an_active_endpoint_cannot_be_replaced() {
    let (_temporary, directory) = private_directory();
    let endpoint = directory.join("probe.sock");
    let first = blocking::Listener::bind(&endpoint).expect("first listener");
    assert!(blocking::Listener::bind(&endpoint).is_err());
    drop(first);
    let _replacement = blocking::Listener::bind(&endpoint).expect("rebind after shutdown");
}

#[test]
fn refuses_regular_files_as_endpoints() {
    let (_temporary, directory) = private_directory();
    let endpoint = directory.join("probe.sock");
    ipc::save_private(&endpoint, b"preserve").expect("occupied path");
    assert!(blocking::Listener::bind(&endpoint).is_err());
    assert!(blocking::Stream::connect(&endpoint).is_err());
    assert_eq!(fs::read(endpoint).expect("original file"), b"preserve");
}

#[tokio::test]
async fn asynchronous_clients_can_reconnect() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_temporary, directory) = private_directory();
    let endpoint = directory.join("probe.sock");
    let mut listener = asynchronous::Listener::bind(&endpoint).expect("listener");
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let mut stream = listener.accept().await.expect("accept");
            let mut request = [0; 4];
            stream.read_exact(&mut request).await.expect("request");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.expect("response");
        }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..3 {
            let mut client = asynchronous::connect(&endpoint).await.expect("connect");
            client.write_all(b"ping").await.expect("request");
            let mut response = [0; 4];
            client.read_exact(&mut response).await.expect("response");
            assert_eq!(&response, b"pong");
        }
        server.await.expect("server task");
    }).await.expect("bounded roundtrip");
}

#[test]
fn blocking_read_times_out_without_a_response() {
    let (_temporary, directory) = private_directory();
    let endpoint = directory.join("probe.sock");
    let mut listener = blocking::Listener::bind(&endpoint).expect("listener");
    let server = std::thread::spawn(move || {
        let mut stream = listener.incoming().next().expect("incoming").expect("accept");
        let mut request = [0; 1];
        stream.read_exact(&mut request).expect("request");
        std::thread::sleep(Duration::from_millis(300));
    });
    let mut client = blocking::Stream::connect(&endpoint).expect("connect");
    client.set_read_timeout(Some(Duration::from_millis(30))).expect("timeout");
    client.write_all(b"?").expect("request");
    let error = client.read(&mut [0; 1]).expect_err("bounded read");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    server.join().expect("server thread");
}

#[cfg(unix)]
#[test]
fn rejects_public_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let (_temporary, directory) = private_directory();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("public directory");
    assert!(ipc::validate_private_directory(&directory).is_err());
}

#[cfg(windows)]
#[test]
fn rejects_a_directory_granted_to_everyone() {
    let (_temporary, directory) = private_directory();
    let status = std::process::Command::new("icacls.exe")
        .arg(&directory).args(["/grant", "*S-1-1-0:(OI)(CI)F", "/q"])
        .status().expect("modify disposable test directory ACL");
    assert!(status.success());
    assert!(ipc::validate_private_directory(&directory).is_err());
    assert!(blocking::Listener::bind(&directory.join("probe.sock")).is_err());
}
