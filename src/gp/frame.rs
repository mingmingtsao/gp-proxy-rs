use super::GpError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];
const HEADER_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Keepalive,
    Ip(Vec<u8>),
}

fn ip_type(packet: &[u8]) -> Result<u16, GpError> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => {
            if packet.len() < 20
                || usize::from(packet[0] & 0xf) * 4 < 20
                || usize::from(packet[0] & 0xf) * 4 > packet.len()
                || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
            {
                return Err(GpError::Protocol("invalid IPv4 packet length"));
            }
            Ok(0x0800)
        }
        Some(6) => {
            if packet.len() < 40
                || usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 != packet.len()
            {
                return Err(GpError::Protocol("invalid IPv6 packet length"));
            }
            Ok(0x86dd)
        }
        _ => Err(GpError::Protocol("invalid IP version")),
    }
}

impl Frame {
    pub fn encode(&self, max_packet: usize) -> Result<Vec<u8>, GpError> {
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(&MAGIC);
        match self {
            Self::Keepalive => Ok(header.to_vec()),
            Self::Ip(packet) => {
                if packet.len() > max_packet || packet.len() > u16::MAX as usize {
                    return Err(GpError::Protocol("IP packet exceeds tunnel MTU"));
                }
                header[4..6].copy_from_slice(&ip_type(packet)?.to_be_bytes());
                header[6..8].copy_from_slice(&(packet.len() as u16).to_be_bytes());
                header[8] = 1;
                let mut result = Vec::with_capacity(HEADER_LEN + packet.len());
                result.extend_from_slice(&header);
                result.extend_from_slice(packet);
                Ok(result)
            }
        }
    }
}

/// Use a dedicated reader task. Cancelling this future mid-frame loses framing.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_packet: usize,
) -> Result<Frame, GpError> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    if header[..4] != MAGIC {
        return Err(GpError::Protocol("invalid tunnel frame magic"));
    }
    let ethertype = u16::from_be_bytes([header[4], header[5]]);
    let len = usize::from(u16::from_be_bytes([header[6], header[7]]));
    if ethertype == 0 {
        if header[6..] != [0; 10] {
            return Err(GpError::Protocol("invalid keepalive frame"));
        }
        return Ok(Frame::Keepalive);
    }
    if !matches!(ethertype, 0x0800 | 0x86dd)
        || header[8..] != [1, 0, 0, 0, 0, 0, 0, 0]
        || len > max_packet
        || len < 20
    {
        return Err(GpError::Protocol("invalid tunnel data header"));
    }
    let mut packet = vec![0; len];
    reader.read_exact(&mut packet).await?;
    if ip_type(&packet)? != ethertype {
        return Err(GpError::Protocol("IP version and EtherType differ"));
    }
    Ok(Frame::Ip(packet))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
    max_packet: usize,
) -> Result<(), GpError> {
    writer.write_all(&frame.encode(max_packet)?).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> Vec<u8> {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[3] = 20;
        p
    }

    #[tokio::test]
    async fn split_and_coalesced_frames_preserve_boundaries() {
        let expected = Frame::Ip(packet());
        let encoded = expected.encode(1400).unwrap();
        let (mut tx, mut rx) = tokio::io::duplex(1);
        let task = tokio::spawn(async move {
            for b in encoded {
                tx.write_all(&[b]).await.unwrap();
            }
            tx.write_all(&Frame::Keepalive.encode(1400).unwrap())
                .await
                .unwrap();
        });
        assert_eq!(read_frame(&mut rx, 1400).await.unwrap(), expected);
        assert_eq!(read_frame(&mut rx, 1400).await.unwrap(), Frame::Keepalive);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_headers_fail_before_allocating_payload() {
        let valid = Frame::Ip(packet()).encode(1400).unwrap();
        for index in [0, 4, 8, 15] {
            let mut frame = valid.clone();
            frame[index] ^= 0xff;
            assert!(read_frame(&mut frame.as_slice(), 1400).await.is_err());
        }
        assert!(read_frame(&mut valid.as_slice(), 19).await.is_err());
        assert!(read_frame(&mut &valid[..19], 1400).await.is_err());
    }

    #[test]
    fn packet_length_and_version_are_validated() {
        let mut p = packet();
        p[3] = 21;
        assert!(Frame::Ip(p).encode(1400).is_err());
        assert!(Frame::Ip(vec![0; 20]).encode(1400).is_err());
        assert_eq!(
            Frame::Keepalive.encode(1400).unwrap(),
            [0x1a, 0x2b, 0x3c, 0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
