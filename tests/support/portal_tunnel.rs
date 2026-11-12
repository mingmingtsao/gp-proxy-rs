//! Portal fixture tunnel: raw-IP TCP echo plus an actual bounded DNS answer.
//! No operating-system DNS, business socket, or virtual interface is involved.
use super::{echo_peer, gp, State, STEP};
use hickory_proto::{
    op::{Message, MessageType},
    rr::{rdata::A, RData, Record, RecordType},
};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr},
};
use std::{
    io,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

fn dns_answer(packet: &[u8], state: &State) -> Option<Vec<u8>> {
    let ip = Ipv4Packet::new_checked(packet).unwrap();
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(ip.dst_addr(), Ipv4Addr::new(10, 77, 0, 1));
    assert_eq!(udp.dst_port(), 53);
    assert!(udp.payload().len() <= 1232);
    let mut response = Message::from_vec(udp.payload()).unwrap();
    assert_eq!(response.metadata.message_type, MessageType::Query);
    assert_eq!(response.queries.len(), 1);
    let query = &response.queries[0];
    assert!(query
        .name()
        .to_ascii()
        .ends_with(".synthetic-portal.invalid."));
    assert_eq!(query.query_type(), RecordType::A);
    response.add_answer(Record::from_rdata(
        query.name().clone(),
        60,
        RData::A(A(Ipv4Addr::new(10, 77, 0, 1))),
    ));
    response.metadata.message_type = MessageType::Response;
    let bytes = response.to_vec().unwrap();
    assert!(bytes.len() <= 1232);
    let mut output = vec![0; 28 + bytes.len()];
    Ipv4Repr {
        src_addr: ip.dst_addr(),
        dst_addr: ip.src_addr(),
        next_header: IpProtocol::Udp,
        payload_len: 8 + bytes.len(),
        hop_limit: 64,
    }
    .emit(
        &mut Ipv4Packet::new_unchecked(&mut output[..20]),
        &ChecksumCapabilities::default(),
    );
    UdpRepr {
        src_port: 53,
        dst_port: udp.src_port(),
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut output[20..]),
        &IpAddress::Ipv4(ip.dst_addr()),
        &IpAddress::Ipv4(ip.src_addr()),
        bytes.len(),
        |buffer| buffer.copy_from_slice(&bytes),
        &ChecksumCapabilities::default(),
    );
    state.dns_queries.fetch_add(1, Ordering::SeqCst);
    Some(output)
}

pub(super) async fn run(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<State>,
) -> io::Result<()> {
    tls.write_all(b"START_TUNNEL").await?;
    tls.flush().await?;
    let stop = CancellationToken::new();
    let _cancel = stop.clone().drop_guard();
    let (input, incoming) = mpsc::channel(64);
    let (output, mut outgoing) = mpsc::channel(64);
    let (mut reader, mut writer) = tokio::io::split(tls);
    let mut tasks = JoinSet::new();
    tasks.spawn(echo_peer::run_peer(
        incoming,
        output.clone(),
        stop.clone(),
        Arc::new(Mutex::new(echo_peer::PeerStats::default())),
        Arc::new(AtomicBool::new(false)),
        4,
        837,
    ));
    let stopping = stop.clone();
    tasks.spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = stopping.cancelled() => break,
                result = gp::read_frame(&mut reader, 1400) => result,
            };
            match frame {
                Ok(gp::Frame::Ip(packet)) => {
                    let sent = if let Some(answer) = dns_answer(&packet, &state) {
                        tokio::select! { _ = stopping.cancelled() => break, sent = output.send(answer) => sent }
                    } else {
                        state.tcp_packets.fetch_add(1, Ordering::SeqCst);
                        tokio::select! { _ = stopping.cancelled() => break, sent = input.send(packet) => sent }
                    };
                    if sent.is_err() { break; }
                }
                Ok(gp::Frame::Keepalive) => {},
                Err(_) => break,
            }
        }
        Ok::<_, io::Error>(())
    });
    loop {
        tokio::select! {
            result = tasks.join_next() => { let _ = result.unwrap().unwrap(); break; },
            packet = outgoing.recv() => match packet {
                Some(packet) => if gp::write_frame(&mut writer, &gp::Frame::Ip(packet), 1400).await.is_err() { break; },
                None => break,
            },
        }
    }
    stop.cancel();
    let _ = timeout(STEP, writer.shutdown()).await;
    timeout(STEP, async {
        while let Some(result) = tasks.join_next().await {
            let _ = result.unwrap();
        }
    })
    .await
    .expect("portal memory peer task join deadline");
    Ok(())
}
