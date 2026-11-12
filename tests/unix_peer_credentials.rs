#![cfg(any(target_os = "linux", target_os = "macos"))]

// A no-filesystem, no-network identity experiment against the actual Tokio
// socketpair/peer_cred APIs. A mismatched expected UID is synthetic; this does
// not claim to exercise a separate OS user or user namespace.
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

fn own_effective_uid() -> io::Result<u32> {
    let (first, second) = UnixStream::pair()?;
    let first = first.peer_cred()?;
    let second = second.peer_cred()?;
    if first.uid() != second.uid() {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(first.uid())
}

fn require_uid(stream: &UnixStream, expected: u32) -> io::Result<()> {
    if stream.peer_cred()?.uid() == expected {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[tokio::test]
async fn anonymous_pair_supplies_own_uid_and_both_peer_credentials() -> io::Result<()> {
    let own_uid = own_effective_uid()?;
    let (mut client, mut server) = UnixStream::pair()?;
    require_uid(&client, own_uid)?;
    require_uid(&server, own_uid)?;
    assert_eq!(client.peer_cred()?.gid(), server.peer_cred()?.gid());
    for stream in [&client, &server] {
        if let Some(pid) = stream.peer_cred()?.pid() {
            assert_eq!(u32::try_from(pid).unwrap(), std::process::id());
        }
    }
    timeout(Duration::from_secs(1), async {
        let client_io = async {
            client.write_all(b"synthetic-ping").await?;
            let mut reply = [0; 14];
            client.read_exact(&mut reply).await?;
            assert_eq!(&reply, b"synthetic-pong");
            Ok::<_, io::Error>(())
        };
        let server_io = async {
            let mut request = [0; 14];
            server.read_exact(&mut request).await?;
            assert_eq!(&request, b"synthetic-ping");
            server.write_all(b"synthetic-pong").await
        };
        tokio::try_join!(client_io, server_io)?;
        Ok::<_, io::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn mismatched_expected_uid_rejects_both_ends_before_any_bytes() -> io::Result<()> {
    let own_uid = own_effective_uid()?;
    let (client, server) = UnixStream::pair()?;
    for stream in [&client, &server] {
        assert_eq!(
            require_uid(stream, own_uid.wrapping_add(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            stream.try_read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    Ok(())
}
