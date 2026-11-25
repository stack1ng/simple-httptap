//! The fate of each flow leaving the machine: diverted when one of the program's processes opened it, passed on otherwise.
//!
//! Packets of a flow wait a little for the socket event that names its process; with none, as for older flows, they pass.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::packet::{Segment, Transport};

/// How long packets of a flow wait for the socket event that opened it.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
pub(crate) const GRACE: Duration = Duration::from_secs(1);
/// How long a flow with no packets is remembered.
///
/// https://github.com/mitmproxy/mitmproxy_rs/blob/main/mitmproxy-windows/redirector/src/main2.rs
const IDLE: Duration = Duration::from_secs(600);
/// The packets a flow may hold while it waits; later ones pass on.
///
/// https://reqrypt.org/windivert-doc.html#divert_set_param
const HELD_MAX: usize = 64;

/// A flow as the local machine sees it: its transport, its local port, and the remote end.
///
/// The local address is left out, as socket events may report it unspecified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Flow {
    transport: Transport,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

/// The decision for a flow's packets: passed on unchanged, or diverted to the userspace stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fate {
    /// The packets go on unchanged.
    Pass,
    /// The packets go to the userspace stack.
    Divert,
}

/// The fates known so far, and the packets waiting for theirs.
#[derive(Debug)]
pub(crate) struct Table<P> {
    /// Each flow's fate and when it was last used.
    fates: HashMap<Flow, (Fate, Instant)>,
    /// The packets of flows whose fate is unknown, with when the first arrived.
    held: HashMap<Flow, (Instant, Vec<P>)>,
}

impl Flow {
    /// Returns the flow with the local port and the remote end, an IPv4-mapped IPv6 address read as IPv4.
    pub(crate) fn new(transport: Transport, local_port: u16, remote: SocketAddr) -> Self {
        Self {
            transport,
            local_port,
            remote_ip: remote.ip().to_canonical(),
            remote_port: remote.port(),
        }
    }

    /// Returns the flow of an outbound packet, whose source is local.
    pub(crate) fn outbound(segment: &Segment<'_>) -> Self {
        Self::new(
            segment.transport,
            segment.source.port(),
            segment.destination,
        )
    }
}

impl<P> Table<P> {
    /// Makes a table that knows no flows.
    pub(crate) fn new() -> Self {
        Self {
            fates: HashMap::new(),
            held: HashMap::new(),
        }
    }

    /// Returns the packet with its flow's fate, or holds it while the fate is unknown.
    pub(crate) fn sort(&mut self, flow: Flow, packet: P, now: Instant) -> Option<(Fate, P)> {
        if let Some((fate, used)) = self.fates.get_mut(&flow) {
            *used = now;
            return Some((*fate, packet));
        }
        let (_, packets) = self.held.entry(flow).or_insert_with(|| (now, Vec::new()));
        if packets.len() >= HELD_MAX {
            return Some((Fate::Pass, packet));
        }
        packets.push(packet);
        None
    }

    /// Records the fate of a flow a socket opened, and returns the packets it held.
    pub(crate) fn decide(&mut self, flow: Flow, fate: Fate, now: Instant) -> Vec<P> {
        self.fates.insert(flow, (fate, now));
        self.held
            .remove(&flow)
            .map(|(_, packets)| packets)
            .unwrap_or_default()
    }

    /// Passes on the flows that waited out the grace period, returning their packets, and forgets idle flows.
    pub(crate) fn expire(&mut self, now: Instant) -> Vec<P> {
        self.fates
            .retain(|_, (_, used)| now.duration_since(*used) < IDLE);
        let late: Vec<Flow> = self
            .held
            .iter()
            .filter(|(_, (first, _))| now.duration_since(*first) >= GRACE)
            .map(|(flow, _)| *flow)
            .collect();
        late.into_iter()
            .flat_map(|flow| self.decide(flow, Fate::Pass, now))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::packet::examples::{PROGRAM, SERVER};

    /// Returns a TCP flow from the program to the server.
    fn flow() -> Flow {
        Flow::new(
            Transport::Tcp,
            PROGRAM.parse::<SocketAddr>().unwrap().port(),
            SERVER.parse().unwrap(),
        )
    }

    /// Checks that packets wait for their flow's fate and then take it, and later ones take it at once.
    #[test]
    fn holds_packets_until_the_flow_is_known() {
        let (mut table, now) = (Table::new(), Instant::now());
        assert_eq!(table.sort(flow(), "syn", now), None);
        assert_eq!(table.decide(flow(), Fate::Divert, now), vec!["syn"]);
        assert_eq!(table.sort(flow(), "ack", now), Some((Fate::Divert, "ack")));
    }

    /// Checks that a flow no socket event names passes on after the grace period.
    #[test]
    fn passes_flows_that_stay_unknown() {
        let (mut table, now) = (Table::new(), Instant::now());
        assert_eq!(table.sort(flow(), "data", now), None);
        assert!(table.expire(now).is_empty());
        assert_eq!(table.expire(now + GRACE), vec!["data"]);
        assert_eq!(
            table.sort(flow(), "more", now + GRACE),
            Some((Fate::Pass, "more"))
        );
    }

    /// Checks that an IPv4-mapped address in a socket event names the flow of the IPv4 packets.
    #[test]
    fn reads_mapped_addresses_as_ipv4() {
        let (program, server): (SocketAddr, SocketAddr) =
            (PROGRAM.parse().unwrap(), SERVER.parse().unwrap());
        let packet = crate::packet::udp(program, server, b"").unwrap();
        let from_packet = Flow::outbound(&crate::packet::parse(&packet).unwrap());
        let IpAddr::V4(server_ip) = server.ip() else {
            unreachable!()
        };
        let mapped = SocketAddr::new(IpAddr::V6(server_ip.to_ipv6_mapped()), server.port());
        assert_eq!(
            Flow::new(Transport::Udp, program.port(), mapped),
            from_packet
        );
    }

    /// Checks that a flow unused for the idle timeout has no fate left, so its later packets wait again.
    #[test]
    fn forgets_idle_flows() {
        let (mut table, now) = (Table::new(), Instant::now());
        table.decide(flow(), Fate::Divert, now);
        table.expire(now + IDLE);
        assert_eq!(table.sort(flow(), "late", now + IDLE), None);
    }
}
