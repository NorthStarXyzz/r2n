use r2n_proto::{CONTROL_MAGIC, ControlFrame, DATA_HEADER_SIZE, DataHeader, DataHeaderError};
use std::net::SocketAddr;
use std::ops::Range;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;

use stun_rs::attributes::stun::XorMappedAddress;
use stun_rs::methods::BINDING;
use stun_rs::{
    MessageClass, MessageDecoderBuilder, MessageEncoderBuilder, StunAttribute, StunMessageBuilder,
};

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Data header error: {0}")]
    DataHeader(#[from] DataHeaderError),
    #[error("Operation timed out")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Debug, Clone)]
pub struct DataFrameView {
    pub header: DataHeader,
    pub payload_range: Range<usize>,
}

#[derive(Debug, Clone)]
pub enum TransportPacket {
    Control(ControlFrame),
    Data(DataFrameView),
}

#[derive(Debug, Clone, Copy)]
pub struct BatchMessage<'a> {
    pub target: SocketAddr,
    pub payload: &'a [u8],
}

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    const STUN_TIMEOUT: Duration = Duration::from_secs(2);

    /// Bind to a specific address.
    pub async fn bind(addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket })
    }

    fn check_family(&self, target: SocketAddr) -> bool {
        if let Ok(local) = self.socket.local_addr() {
            local.is_ipv4() == target.is_ipv4()
        } else {
            true
        }
    }

    /// Send a control frame to a specific address.
    pub async fn send_control(&self, frame: &ControlFrame, target: SocketAddr) -> Result<usize> {
        if !self.check_family(target) {
            return Ok(0);
        }
        let mut buf = CONTROL_MAGIC.to_vec();
        buf.extend_from_slice(&postcard::to_stdvec(frame)?);
        let len = self.socket.send_to(&buf, target).await?;
        Ok(len)
    }

    /// Send a prebuilt dataplane frame without extra serialization.
    pub async fn send_raw(&self, frame: &[u8], target: SocketAddr) -> Result<usize> {
        if !self.check_family(target) {
            return Ok(0);
        }
        let len = self.socket.send_to(frame, target).await?;
        Ok(len)
    }

    /// Send multiple datagrams, using `sendmmsg` on Linux when available.
    pub async fn send_batch(&self, messages: &[BatchMessage<'_>]) -> Result<usize> {
        let filtered: Vec<&BatchMessage<'_>> = messages
            .iter()
            .filter(|m| self.check_family(m.target))
            .collect();

        if filtered.is_empty() {
            return Ok(0);
        }

        #[cfg(target_os = "linux")]
        {
            // For Linux, we convert Vec<&BatchMessage> to Vec<BatchMessage> or update the signature/call.
            // Wait, try_send_batch_linux takes &[BatchMessage], so if we want to batch only filtered ones,
            // we can construct a Vec<BatchMessage> of the filtered ones.
            let owned_filtered: Vec<BatchMessage<'_>> = filtered.iter().map(|&&m| m).collect();
            if let Ok(sent) = self.try_send_batch_linux(&owned_filtered).await {
                return Ok(sent);
            }
        }

        let mut sent = 0;
        for message in filtered {
            self.socket.send_to(message.payload, message.target).await?;
            sent += 1;
        }
        Ok(sent)
    }

    /// Receive either a control or dataplane packet.
    pub async fn recv_packet(&self, buf: &mut [u8]) -> Result<(TransportPacket, SocketAddr)> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        if len >= CONTROL_MAGIC.len() && buf[0..4] == CONTROL_MAGIC {
            let packet = postcard::from_bytes(&buf[4..len])?;
            return Ok((TransportPacket::Control(packet), addr));
        }

        if len < DATA_HEADER_SIZE {
            return Err(TransportError::DataHeader(DataHeaderError::BufferTooShort));
        }

        let header = DataHeader::decode(&buf[..DATA_HEADER_SIZE])?;
        let payload_range = header.payload_range();
        if payload_range.end != len {
            return Err(TransportError::DataHeader(
                DataHeaderError::InvalidPayloadLength,
            ));
        }
        Ok((
            TransportPacket::Data(DataFrameView {
                header,
                payload_range,
            }),
            addr,
        ))
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Discover public address using a STUN server.
    pub async fn discover_public_addr(&self, stun_server: &str) -> Result<SocketAddr> {
        let msg = StunMessageBuilder::new(BINDING, MessageClass::Request).build();
        let mut buffer = [0u8; 512];
        let encoder = MessageEncoderBuilder::default().build();
        let size = encoder
            .encode(&mut buffer, &msg)
            .map_err(|err| std::io::Error::other(format!("STUN encode error: {err}")))?;

        self.socket.send_to(&buffer[..size], stun_server).await?;

        let mut recv_buffer = [0u8; 512];
        let (n, _) =
            tokio::time::timeout(Self::STUN_TIMEOUT, self.socket.recv_from(&mut recv_buffer))
                .await
                .map_err(|_| TransportError::Timeout)??;

        let decoder = MessageDecoderBuilder::default().build();
        let (decoded_msg, _) = decoder
            .decode(&recv_buffer[..n])
            .map_err(|err| std::io::Error::other(format!("STUN decode error: {err}")))?;

        if let Some(StunAttribute::XorMappedAddress(attr)) = decoded_msg.get::<XorMappedAddress>() {
            Ok(*attr.socket_address())
        } else {
            Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "XOR-MAPPED-ADDRESS not found",
            )))
        }
    }

    /// Detect NAT type using multiple STUN servers.
    pub async fn detect_nat_type(&self, servers: &[&str]) -> Result<r2n_common::NatType> {
        if servers.len() < 2 {
            return Ok(r2n_common::NatType::Unknown);
        }

        let addr1 = self.discover_public_addr(servers[0]).await?;
        let addr2 = self.discover_public_addr(servers[1]).await?;

        if addr1 == addr2 {
            Ok(r2n_common::NatType::Cone)
        } else {
            Ok(r2n_common::NatType::Symmetric)
        }
    }

    #[cfg(target_os = "linux")]
    async fn try_send_batch_linux(&self, messages: &[BatchMessage<'_>]) -> Result<usize> {
        self.socket.writable().await?;
        let fd = self.socket.as_raw_fd();
        let mut iovecs: Vec<libc::iovec> = messages
            .iter()
            .map(|message| libc::iovec {
                iov_base: message.payload.as_ptr() as *mut libc::c_void,
                iov_len: message.payload.len(),
            })
            .collect();
        let mut addresses = Vec::with_capacity(messages.len());
        let mut headers = Vec::with_capacity(messages.len());

        for message in messages {
            let (storage, len) = socket_addr_to_storage(message.target);
            addresses.push((storage, len));
        }

        for (index, (storage, len)) in addresses.iter_mut().enumerate() {
            // Safety: zeroed initialization keeps target-specific padding fields valid.
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_name = storage as *mut _ as *mut libc::c_void;
            hdr.msg_namelen = *len;
            hdr.msg_iov = &mut iovecs[index];
            hdr.msg_iovlen = 1;
            hdr.msg_control = std::ptr::null_mut();
            hdr.msg_controllen = 0;
            hdr.msg_flags = 0;
            headers.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }

        // Safety: all pointers live until syscall returns and were derived from valid slices.
        let result = unsafe { libc::sendmmsg(fd, headers.as_mut_ptr(), headers.len() as u32, 0) };
        if result < 0 {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }
        Ok(result as usize)
    }
}

#[cfg(target_os = "linux")]
fn socket_addr_to_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    match addr {
        SocketAddr::V4(addr_v4) => {
            // Safety: zeroed storage is immediately written with a valid sockaddr_in layout.
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr_v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr_v4.ip().octets()).to_be(),
                },
                sin_zero: [0; 8],
            };
            // Safety: storage is large enough for sockaddr_in.
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, sockaddr);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(addr_v6) => {
            // Safety: zeroed storage is immediately written with a valid sockaddr_in6 layout.
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr_v6.port().to_be(),
                sin6_flowinfo: addr_v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr_v6.ip().octets(),
                },
                sin6_scope_id: addr_v6.scope_id(),
            };
            // Safety: storage is large enough for sockaddr_in6.
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, sockaddr);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2n_common::{NodeId, PacketId, RoomId, SessionId};
    use r2n_proto::{DataPacketType, PROTOCOL_VERSION};

    #[tokio::test]
    async fn recv_packet_rejects_payload_length_past_datagram() {
        let receiver = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let payload = b"short";
        let header = DataHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            packet_type: DataPacketType::IPv4,
            reserved: 0,
            ttl: 0,
            room_id: RoomId([1; 16]),
            src_node: NodeId([2; 32]),
            dst_node: NodeId([3; 32]),
            origin_node: NodeId([2; 32]),
            session_id: SessionId(1),
            nonce: 7,
            packet_id: PacketId(0),
            payload_len: 64,
        };

        let mut frame = vec![0u8; DATA_HEADER_SIZE + payload.len()];
        header
            .encode_into(&mut frame[..DATA_HEADER_SIZE])
            .expect("encode header");
        frame[DATA_HEADER_SIZE..].copy_from_slice(payload);

        sender
            .send_raw(&frame, receiver_addr)
            .await
            .expect("send frame");

        let mut buf = [0u8; 512];
        let err = receiver
            .recv_packet(&mut buf)
            .await
            .expect_err("invalid length");
        assert!(matches!(
            err,
            TransportError::DataHeader(DataHeaderError::InvalidPayloadLength)
        ));
    }

    #[tokio::test]
    async fn recv_packet_rejects_payload_length_before_datagram_end() {
        let receiver = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let payload = b"ok";
        let header = DataHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            packet_type: DataPacketType::IPv4,
            reserved: 0,
            ttl: 0,
            room_id: RoomId([1; 16]),
            src_node: NodeId([2; 32]),
            dst_node: NodeId([3; 32]),
            origin_node: NodeId([2; 32]),
            session_id: SessionId(1),
            nonce: 7,
            packet_id: PacketId(0),
            payload_len: payload.len() as u16,
        };

        let mut frame = vec![0u8; DATA_HEADER_SIZE + payload.len() + 1];
        header
            .encode_into(&mut frame[..DATA_HEADER_SIZE])
            .expect("encode header");
        frame[DATA_HEADER_SIZE..DATA_HEADER_SIZE + payload.len()].copy_from_slice(payload);
        frame[DATA_HEADER_SIZE + payload.len()] = 0xff;

        sender
            .send_raw(&frame, receiver_addr)
            .await
            .expect("send frame");

        let mut buf = [0u8; 512];
        let err = receiver
            .recv_packet(&mut buf)
            .await
            .expect_err("invalid length");
        assert!(matches!(
            err,
            TransportError::DataHeader(DataHeaderError::InvalidPayloadLength)
        ));
    }
}
