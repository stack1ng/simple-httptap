//! A userspace TCP/IP stack that ends the program's diverted packets and carries what they hold over SOCKS5.
//!
//! Each TCP connection gets a CONNECT, and each of the program's UDP sockets a UDP ASSOCIATE.
//! Adapted from mitmproxy_rs's `src/network`, Copyright (c) 2022, Fabio Valentini and Maximilian Hils, MIT; see LICENSE-mitmproxy.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Checksum, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};

use crate::packet::{self, Segment, Transport};
use crate::socks5;

/// The largest IP packet the stack writes, which leaves room for tunnels below.
///
/// https://github.com/mitmproxy/mitmproxy_rs/blob/main/src/network/virtual_device.rs
const MTU: usize = 1420;
/// The stack's own IPv4 address, on a prefix that covers every address, so that it answers for all of them.
///
/// https://github.com/mitmproxy/mitmproxy_rs/blob/main/src/network/tcp.rs
const OWN_IPV4: Ipv4Address = Ipv4Address::new(0, 0, 0, 1);
/// The stack's own IPv6 address, on a prefix that covers every address.
const OWN_IPV6: Ipv6Address = Ipv6Address::LOCALHOST;
/// The bytes each TCP connection buffers each way inside the stack.
///
/// https://github.com/mitmproxy/mitmproxy_rs/blob/main/src/network/tcp.rs
const TCP_BUFFER: usize = 64 * 1024;
/// How long a TCP connection may wait for the program to acknowledge data before it is dropped.
///
/// https://github.com/mitmproxy/mitmproxy_rs/blob/main/src/network/tcp.rs
const TCP_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(60);
/// How often an idle TCP connection checks that the program is still there.
///
/// https://github.com/mitmproxy/mitmproxy_rs/blob/main/src/network/tcp.rs
const TCP_KEEPALIVE: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(28);
/// How long a UDP association lasts with no datagram either way.
///
/// https://github.com/mitmproxy/mitmproxy_rs/blob/main/src/network/udp.rs
const UDP_IDLE: Duration = Duration::from_secs(60);
/// The chunks that wait in a channel between the stack and one relay, each way.
///
/// https://docs.rs/tokio/latest/tokio/sync/mpsc/fn.channel.html
const CHANNEL_DEPTH: usize = 16;
/// The largest UDP payload, which bounds what one read from the relay returns.
///
/// https://www.rfc-editor.org/rfc/rfc768
const DATAGRAM_MAX: usize = u16::MAX as usize;

/// A relay's message to the stack for the program: destination bytes, their end, or a reset.
#[derive(Debug)]
enum Downstream {
    /// Bytes the destination sent.
    Data(Vec<u8>),
    /// The destination finished sending.
    End,
    /// The proxy refused or the connection broke.
    Reset,
}

/// Serves the diverted packets until their channel closes, writing the stack's packets for the program to the replies.
pub(crate) async fn serve(
    proxy: SocketAddr,
    mut diverted: mpsc::Receiver<Vec<u8>>,
    replies: mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut stack = Stack::new(proxy, replies);
    let wake = Arc::clone(&stack.wake);
    loop {
        let delay = stack
            .interface
            .poll_delay(Instant::now(), &stack.sockets)
            .map(Duration::from);
        tokio::select! {
            packet = diverted.recv() => match packet {
                Some(packet) => stack.receive(packet),
                None => return,
            },
            () = wake.notified() => {}
            () = async { match delay { Some(delay) => tokio::time::sleep(delay).await, None => std::future::pending().await } } => {}
        }
        stack.poll();
    }
}

/// The smoltcp interface, its sockets, and the relays of each connection and association.
struct Stack {
    proxy: SocketAddr,
    interface: Interface,
    device: Device,
    sockets: SocketSet<'static>,
    connections: Vec<Connection>,
    /// The association of each of the program's UDP sockets, by its address.
    associations: HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Vec<u8>)>>,
    /// Woken by relays when they have something for the stack or room for more.
    wake: Arc<Notify>,
}

/// The stack's state for one TCP connection it terminated: its socket, endpoints and relay channels.
struct Connection {
    socket: SocketHandle,
    /// The program's address and the destination's.
    endpoints: (SocketAddr, SocketAddr),
    /// Bytes for the relay, none once the program finished sending.
    upstream: Option<mpsc::Sender<Vec<u8>>>,
    downstream: mpsc::Receiver<Downstream>,
    /// Bytes from the relay that wait for room in the socket.
    pending: VecDeque<u8>,
    /// Whether the destination finished sending, so the socket closes once `pending` is written.
    ending: bool,
}

impl Stack {
    /// Makes an interface that answers for every address, with no sockets.
    fn new(proxy: SocketAddr, replies: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        let mut device = Device {
            received: VecDeque::new(),
            replies,
        };
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::now(),
        );
        interface.set_any_ip(true);
        interface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(OWN_IPV4), u8::MIN));
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv6(OWN_IPV6), u8::MIN));
        });
        let _ = interface.routes_mut().add_default_ipv4_route(OWN_IPV4);
        let _ = interface.routes_mut().add_default_ipv6_route(OWN_IPV6);
        Self {
            proxy,
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            connections: Vec::new(),
            associations: HashMap::new(),
            wake: Arc::new(Notify::new()),
        }
    }

    /// Takes one packet the program sent: a datagram goes to its association, TCP to smoltcp.
    fn receive(&mut self, packet: Vec<u8>) {
        match packet::parse(&packet) {
            Some(Segment {
                transport: Transport::Udp,
                source,
                destination,
                payload,
                ..
            }) => self.send_datagram(source, destination, payload),
            Some(Segment {
                transport: Transport::Tcp,
                source,
                destination,
                opens,
                ..
            }) => {
                if opens
                    && !self
                        .connections
                        .iter()
                        .any(|connection| connection.endpoints == (source, destination))
                {
                    self.open(source, destination);
                }
                self.device.received.push_back(packet);
            }
            None => {}
        }
    }

    /// Makes a socket that accepts the connection the program opens, and a relay that connects to its destination.
    fn open(&mut self, program: SocketAddr, destination: SocketAddr) {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![u8::MIN; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![u8::MIN; TCP_BUFFER]),
        );
        if socket.listen(destination).is_err() {
            return;
        }
        socket.set_timeout(Some(TCP_TIMEOUT));
        socket.set_keep_alive(Some(TCP_KEEPALIVE));
        let (upstream, upstream_receiver) = mpsc::channel(CHANNEL_DEPTH);
        let (downstream_sender, downstream) = mpsc::channel(CHANNEL_DEPTH);
        tokio::spawn(relay(
            self.proxy,
            destination,
            upstream_receiver,
            downstream_sender,
            Arc::clone(&self.wake),
        ));
        let socket = self.sockets.add(socket);
        self.connections.push(Connection {
            socket,
            endpoints: (program, destination),
            upstream: Some(upstream),
            downstream,
            pending: VecDeque::new(),
            ending: false,
        });
    }

    /// Hands a datagram to the association of the socket it came from, starting one if there is none.
    fn send_datagram(&mut self, program: SocketAddr, destination: SocketAddr, payload: &[u8]) {
        let live = self
            .associations
            .get(&program)
            .is_some_and(|sender| !sender.is_closed());
        if !live {
            self.associations.retain(|_, sender| !sender.is_closed());
            let (sender, receiver) = mpsc::channel(CHANNEL_DEPTH);
            tokio::spawn(associate(
                self.proxy,
                program,
                receiver,
                self.device.replies.clone(),
            ));
            self.associations.insert(program, sender);
        }
        if let Some(sender) = self.associations.get(&program) {
            let _ = sender.try_send((destination, payload.to_vec()));
        }
    }

    /// Runs smoltcp, moves bytes between the sockets and the relays, and forgets closed connections.
    fn poll(&mut self) {
        self.interface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);
        for connection in &mut self.connections {
            connection.exchange(self.sockets.get_mut::<tcp::Socket>(connection.socket));
        }
        self.interface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);
        let sockets = &mut self.sockets;
        self.connections.retain(|connection| {
            let closed =
                sockets.get::<tcp::Socket>(connection.socket).state() == tcp::State::Closed;
            if closed {
                sockets.remove(connection.socket);
            }
            !closed
        });
    }
}

impl Connection {
    /// Moves what the program sent to the relay and what the relay sent to the program, as far as there is room.
    fn exchange(&mut self, socket: &mut tcp::Socket<'_>) {
        while let Some(upstream) = &self.upstream
            && socket.can_recv()
        {
            let closed = match upstream.try_reserve() {
                Ok(permit) => {
                    permit.send(
                        socket
                            .recv(|bytes| (bytes.len(), bytes.to_vec()))
                            .unwrap_or_default(),
                    );
                    false
                }
                Err(mpsc::error::TrySendError::Full(())) => break,
                Err(mpsc::error::TrySendError::Closed(())) => true,
            };
            if closed {
                self.upstream = None;
            }
        }
        let program_finished = matches!(
            socket.state(),
            tcp::State::CloseWait
                | tcp::State::LastAck
                | tcp::State::Closing
                | tcp::State::TimeWait
                | tcp::State::Closed
        );
        if program_finished && socket.recv_queue() == usize::MIN {
            self.upstream = None;
        }
        loop {
            if socket.may_send() && !self.pending.is_empty() {
                let (front, _) = self.pending.as_slices();
                let written = socket.send_slice(front).unwrap_or_default();
                self.pending.drain(..written);
            }
            if !self.pending.is_empty() || self.ending {
                break;
            }
            match self.downstream.try_recv() {
                Ok(Downstream::Data(bytes)) => self.pending.extend(bytes),
                Ok(Downstream::End) => self.ending = true,
                Ok(Downstream::Reset) | Err(mpsc::error::TryRecvError::Disconnected) => {
                    socket.abort();
                    return;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
            }
        }
        if self.ending && self.pending.is_empty() {
            socket.close();
        }
    }
}

/// Connects to the destination through the proxy and carries bytes both ways until both sides finish or the stack drops the connection.
async fn relay(
    proxy: SocketAddr,
    destination: SocketAddr,
    mut upstream: mpsc::Receiver<Vec<u8>>,
    downstream: mpsc::Sender<Downstream>,
    wake: Arc<Notify>,
) {
    let stream = match socks5::connect(proxy, destination).await {
        Ok(stream) => stream,
        Err(_) => {
            let _ = downstream.send(Downstream::Reset).await;
            wake.notify_one();
            return;
        }
    };
    let (mut reader, mut writer) = stream.into_split();
    let outward = async {
        while let Some(bytes) = upstream.recv().await {
            wake.notify_one();
            if writer.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = writer.shutdown().await;
    };
    let inward = async {
        let mut buffer = vec![u8::MIN; TCP_BUFFER];
        let last = loop {
            match reader.read(&mut buffer).await {
                Ok(usize::MIN) => break Downstream::End,
                Ok(length) => {
                    if downstream
                        .send(Downstream::Data(buffer[..length].to_vec()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    wake.notify_one();
                }
                Err(_) => break Downstream::Reset,
            }
        };
        let _ = downstream.send(last).await;
        wake.notify_one();
    };
    tokio::select! {
        _ = async { tokio::join!(outward, inward) } => {}
        () = downstream.closed() => {}
    }
}

/// Opens a UDP association for one of the program's sockets and carries its datagrams both ways until it is idle or the proxy ends it.
async fn associate(
    proxy: SocketAddr,
    program: SocketAddr,
    mut datagrams: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    replies: mpsc::UnboundedSender<Vec<u8>>,
) {
    let Ok(mut association) = socks5::associate(proxy).await else {
        return;
    };
    let mut buffer = vec![u8::MIN; DATAGRAM_MAX];
    let mut control = [u8::MIN];
    loop {
        tokio::select! {
            datagram = datagrams.recv() => {
                let Some((destination, payload)) = datagram else { return };
                let _ = association.socket.send(&socks5::wrap(destination, &payload)).await;
            }
            received = association.socket.recv(&mut buffer) => {
                if let Ok(length) = received
                    && let Some((source, payload)) = socks5::unwrap(&buffer[..length])
                    && let Some(packet) = packet::udp(source, program, payload)
                    && replies.send(packet).is_err()
                {
                    return;
                }
            }
            _ = association.control.read(&mut control) => return,
            () = tokio::time::sleep(UDP_IDLE) => return,
        }
    }
}

/// A smoltcp device whose received packets are queued by hand and whose sent packets go to a channel.
struct Device {
    received: VecDeque<Vec<u8>>,
    replies: mpsc::UnboundedSender<Vec<u8>>,
}

/// The receive token for one diverted packet, handed to smoltcp from the device's queue.
struct Received(Vec<u8>);

/// The transmit token for one packet from smoltcp, forwarded to the replies channel.
struct Reply<'a>(&'a mpsc::UnboundedSender<Vec<u8>>);

impl phy::Device for Device {
    type RxToken<'a> = Received;
    type TxToken<'a> = Reply<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(Received, Reply<'_>)> {
        let packet = self.received.pop_front()?;
        Some((Received(packet), Reply(&self.replies)))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Reply<'_>> {
        Some(Reply(&self.replies))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        let mut checksum = ChecksumCapabilities::default();
        (checksum.ipv4, checksum.tcp, checksum.udp) = (Checksum::Tx, Checksum::Tx, Checksum::Tx);
        capabilities.checksum = checksum;
        capabilities
    }
}

impl phy::RxToken for Received {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, read: F) -> R {
        read(&self.0)
    }
}

impl phy::TxToken for Reply<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, write: F) -> R {
        let mut packet = vec![u8::MIN; length];
        let result = write(&mut packet);
        let _ = self.0.send(packet);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;

    use crate::packet::examples::{PROGRAM, SERVER};
    use crate::socks5::echo;
    /// How long a test waits for the bytes to come back.
    const PATIENCE: Duration = Duration::from_secs(5);
    /// How long the test waits between steps of the program's stack.
    const STEP: Duration = Duration::from_millis(5);

    /// Starts the stack in front of an echoing proxy, returning where packets go in and where replies come out.
    async fn start(refuse: bool) -> (mpsc::Sender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>) {
        let proxy = echo::start(refuse).await;
        let (diverted, diverted_receiver) = mpsc::channel(CHANNEL_DEPTH);
        let (replies, reply_receiver) = mpsc::unbounded_channel();
        tokio::spawn(serve(proxy, diverted_receiver, replies));
        (diverted, reply_receiver)
    }

    /// Connects from a smoltcp stack playing the program, sends the message and, if `finish`, its end, and returns what came back.
    ///
    /// It waits for the connection to close when finishing, or else for the message to come back.
    async fn exchange(refuse: bool, message: &[u8], finish: bool) -> (Vec<u8>, tcp::State) {
        let (diverted, mut replies) = start(refuse).await;
        let (program, server): (SocketAddr, SocketAddr) =
            (PROGRAM.parse().unwrap(), SERVER.parse().unwrap());
        let (sent, mut outgoing) = mpsc::unbounded_channel();
        let mut device = Device {
            received: VecDeque::new(),
            replies: sent,
        };
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::now(),
        );
        let IpAddr::V4(program_ip) = program.ip() else {
            unreachable!()
        };
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(program_ip), u8::MIN))
                .unwrap()
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(program_ip)
            .unwrap();
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![u8::MIN; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![u8::MIN; TCP_BUFFER]),
        ));
        sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(interface.context(), server, program)
            .unwrap();
        let (mut received, mut written) = (Vec::new(), false);
        let deadline = std::time::Instant::now() + PATIENCE;
        while std::time::Instant::now() < deadline {
            interface.poll(Instant::now(), &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if !written && socket.can_send() {
                socket.send_slice(message).unwrap();
                if finish {
                    socket.close();
                }
                written = true;
            }
            if socket.can_recv() {
                received.extend(socket.recv(|bytes| (bytes.len(), bytes.to_vec())).unwrap());
            }
            let done = if finish {
                !socket.may_recv() && written
            } else {
                received.len() >= message.len()
            };
            if done || !socket.is_open() {
                break;
            }
            while let Ok(packet) = outgoing.try_recv() {
                diverted.send(packet).await.unwrap();
            }
            tokio::time::sleep(STEP).await;
            while let Ok(packet) = replies.try_recv() {
                device.received.push_back(packet);
            }
        }
        (received, sockets.get::<tcp::Socket>(handle).state())
    }

    /// Checks that bytes the program sends over TCP reach the proxy and its answer comes back.
    #[tokio::test]
    async fn carries_tcp_through_the_proxy() {
        let (received, state) = exchange(false, b"ping over tcp", false).await;
        assert_eq!(received, b"ping over tcp");
        assert_eq!(state, tcp::State::Established);
    }

    /// Checks that the end of the program's stream reaches the proxy, and the end of the proxy's comes back.
    #[tokio::test]
    async fn passes_on_the_end_of_each_stream() {
        let (received, state) = exchange(false, b"last words", true).await;
        assert_eq!(received, b"last words");
        assert!(
            matches!(state, tcp::State::TimeWait | tcp::State::Closed),
            "{state}"
        );
    }

    /// Checks that the program's side sees no data and a closed socket once the proxy refuses the CONNECT.
    #[tokio::test]
    async fn resets_a_connection_the_proxy_refuses() {
        let (received, state) = exchange(true, b"ping", false).await;
        assert!(received.is_empty());
        assert_eq!(state, tcp::State::Closed);
    }

    /// Checks that a datagram reaches the proxy's relay and its answer comes back as a packet from the destination.
    #[tokio::test]
    async fn carries_udp_through_the_proxy() {
        let (diverted, mut replies) = start(false).await;
        let (program, server) = (PROGRAM.parse().unwrap(), SERVER.parse().unwrap());
        diverted
            .send(packet::udp(program, server, b"ping over udp").unwrap())
            .await
            .unwrap();
        let reply = tokio::time::timeout(PATIENCE, replies.recv())
            .await
            .unwrap()
            .unwrap();
        let segment = packet::parse(&reply).unwrap();
        assert_eq!(
            (segment.source, segment.destination, segment.payload),
            (server, program, &b"ping over udp"[..])
        );
    }
}
