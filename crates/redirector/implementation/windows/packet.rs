//! Reading the endpoints of IP packets, and writing UDP ones.
//!
//! Adapted from mitmproxy_rs's `src/network/udp.rs`, Copyright (c) 2022, Fabio Valentini and Maximilian Hils, MIT; see LICENSE-mitmproxy.

use std::net::{IpAddr, SocketAddr};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, IpRepr, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket, UdpRepr,
};

/// The hop limit of the UDP packets written, as many routers as an IP packet can pass.
///
/// https://www.rfc-editor.org/rfc/rfc791#section-3.1
const HOP_LIMIT: u8 = u8::MAX;

/// A transport protocol whose packets are diverted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Transport {
    Tcp,
    Udp,
}

/// The parts of a TCP or UDP packet that route it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Segment<'a> {
    pub(crate) transport: Transport,
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
    /// Whether this is a TCP segment opening a connection: SYN without ACK.
    pub(crate) opens: bool,
    /// The UDP payload, or the whole TCP segment.
    pub(crate) payload: &'a [u8],
}

/// Reads an IPv4 or IPv6 packet carrying TCP or UDP, with no IPv6 extension headers; none for anything else.
pub(crate) fn parse(packet: &[u8]) -> Option<Segment<'_>> {
    let (source, destination, protocol, body) = match IpVersion::of_packet(packet).ok()? {
        IpVersion::Ipv4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.more_frags() || ip.frag_offset() != u16::MIN {
                return None;
            }
            (
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                ip.next_header(),
                ip.payload(),
            )
        }
        IpVersion::Ipv6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            (
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                ip.next_header(),
                ip.payload(),
            )
        }
    };
    let (transport, source_port, destination_port, opens, payload) = match protocol {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(body).ok()?;
            (
                Transport::Tcp,
                tcp.src_port(),
                tcp.dst_port(),
                tcp.syn() && !tcp.ack(),
                body,
            )
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(body).ok()?;
            (
                Transport::Udp,
                udp.src_port(),
                udp.dst_port(),
                false,
                udp.payload(),
            )
        }
        _ => return None,
    };
    Some(Segment {
        transport,
        source: SocketAddr::new(source, source_port),
        destination: SocketAddr::new(destination, destination_port),
        opens,
        payload,
    })
}

/// Writes an IP packet carrying a UDP datagram, with its checksums; none when the addresses' families differ.
///
/// An IPv4 source sent to an IPv6 destination is written as its IPv4-mapped IPv6 address.
pub(crate) fn udp(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let source_ip = match (source.ip(), destination.ip()) {
        (IpAddr::V4(v4), IpAddr::V6(_)) => IpAddr::V6(v4.to_ipv6_mapped()),
        (ip, _) => ip,
    };
    if source_ip.is_ipv4() != destination.is_ipv4() {
        return None;
    }
    let header = UdpRepr {
        src_port: source.port(),
        dst_port: destination.port(),
    };
    let ip = IpRepr::new(
        source_ip.into(),
        destination.ip().into(),
        IpProtocol::Udp,
        header.header_len() + payload.len(),
        HOP_LIMIT,
    );
    let checksums = ChecksumCapabilities::default();
    let mut packet = vec![u8::MIN; ip.buffer_len()];
    ip.emit(&mut packet[..], &checksums);
    let body = &mut packet[ip.header_len()..];
    let fill = |space: &mut [u8]| space.copy_from_slice(payload);
    header.emit(
        &mut UdpPacket::new_unchecked(body),
        &ip.src_addr(),
        &ip.dst_addr(),
        payload.len(),
        fill,
        &checksums,
    );
    Some(packet)
}

/// Addresses the tests of every module use.
#[cfg(test)]
pub(crate) mod examples {
    /// A program's address on its network.
    pub(crate) const PROGRAM: &str = "192.0.2.1:50000";
    /// The address the program sends to.
    pub(crate) const SERVER: &str = "198.51.100.7:443";
}

#[cfg(test)]
mod tests {
    use super::examples::{PROGRAM, SERVER};
    use super::*;
    /// The bytes a datagram carries.
    const PAYLOAD: &[u8] = b"quic";

    /// Checks that a written datagram reads back with its endpoints and payload.
    #[test]
    fn reads_back_a_written_datagram() {
        let (program, server) = (PROGRAM.parse().unwrap(), SERVER.parse().unwrap());
        let packet = udp(program, server, PAYLOAD).unwrap();
        let expected = Segment {
            transport: Transport::Udp,
            source: program,
            destination: server,
            opens: false,
            payload: PAYLOAD,
        };
        assert_eq!(parse(&packet), Some(expected));
    }

    /// Checks that a datagram from IPv4 to IPv6 comes from the IPv4-mapped address.
    #[test]
    fn maps_an_ipv4_source_for_an_ipv6_destination() {
        let program: SocketAddr = "[2001:db8::1]:50000".parse().unwrap();
        let server: SocketAddr = SERVER.parse().unwrap();
        let packet = udp(server, program, PAYLOAD).unwrap();
        let segment = parse(&packet).unwrap();
        assert_eq!(
            segment.source.ip(),
            IpAddr::V6("::ffff:198.51.100.7".parse().unwrap())
        );
        assert_eq!(segment.destination, program);
    }

    /// Checks that bytes that are no IP packet read as nothing.
    #[test]
    fn reads_nothing_from_what_is_no_packet() {
        assert_eq!(parse(PAYLOAD), None);
    }
}
