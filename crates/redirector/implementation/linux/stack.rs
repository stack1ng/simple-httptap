//! The userspace TCP/IP stack on the TUN device, which sends each TCP connection and UDP source through the SOCKS5 proxy.
//!
//! smoltcp ends each TCP connection, which goes on through a CONNECT; each UDP source's datagrams go through an ASSOCIATE.
//! One task owns the device and every socket, and each connection and source has a task that talks to the proxy.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, IpVersion, Ipv4Address,
    Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket, UdpRepr,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::{Instant, sleep, sleep_until, timeout};

use crate::socks;

/// The largest IP packet the TUN device carries out of the namespace: Ethernet's, which the kernel gives a TUN device.
///
/// https://www.rfc-editor.org/rfc/rfc894
pub(crate) const MTU: usize = 1500;
/// The most bytes read off the TUN device or a UDP relay at once: the largest packet an IP header can describe.
const LARGEST_PACKET: usize = u16::MAX as usize;
/// The address the stack gives itself, in a block no internet host has; with AnyIP on, it takes every IPv4 packet.
///
/// https://www.rfc-editor.org/rfc/rfc6890#section-2.2.2
const STACK_IPV4: Ipv4Address = Ipv4Address::new(198, 18, 0, 2);
/// The address the stack gives itself, a unique local address; with AnyIP on, it takes every IPv6 packet.
///
/// https://www.rfc-editor.org/rfc/rfc4193#section-3.1
const STACK_IPV6: Ipv6Address = Ipv6Address::new(0xfd68, 0x7474, 0x7074, 0x6170, 0, 0, 0, 2);
/// The bytes each TCP socket holds each way: Linux's own default, more than 64 KiB, so the window scales.
///
/// https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html#tcp-variables
const SOCKET_BUFFER: usize = 131_072;
/// The most bytes read from the program and not yet written to the proxy, per connection: a socket's worth.
const UPLOAD_WINDOW: usize = SOCKET_BUFFER;
/// The most bytes read from the proxy and not yet in the socket, per connection: a socket's worth, more than one chunk.
const DOWNLOAD_WINDOW: usize = SOCKET_BUFFER;
/// The most bytes moved in one message between a connection's task and the stack: as many as one packet holds.
const CHUNK: usize = LARGEST_PACKET;
/// How long the proxy may take to open a stream or a relay before the program is refused: as long as Linux tries to connect.
///
/// https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html#tcp-variables
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(127);
/// How long a UDP source may send and receive nothing before its relay closes: the least a NAT may keep a mapping.
///
/// https://www.rfc-editor.org/rfc/rfc4787#section-4.3
const UDP_IDLE: Duration = Duration::from_secs(120);
/// The datagrams from one UDP source that wait for its relay, as many as a TUN device queues; more are dropped.
///
/// https://github.com/torvalds/linux/blob/master/drivers/net/tun.c
const UDP_QUEUE: usize = 500;
/// The most packets read off the device before the stack lets its sockets run, as many as a network driver takes at once.
///
/// https://github.com/torvalds/linux/blob/master/include/linux/netdevice.h
const PACKETS_PER_TURN: usize = 64;
/// The hop limit of the UDP packets the stack writes to the program, the default IANA recommends.
///
/// https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
const HOP_LIMIT: u8 = 64;

/// The host's name servers that are on its loopback, which the namespace cannot reach, each with the address it has there instead.
#[derive(Debug, Clone, Default)]
pub(crate) struct NameServers {
    /// Each name server's address in the namespace, then its address on the host.
    pairs: Vec<(IpAddr, IpAddr)>,
}

impl NameServers {
    /// Returns name servers reached at the first address of each pair in the namespace and the second on the host.
    pub(crate) fn new(pairs: Vec<(IpAddr, IpAddr)>) -> Self {
        Self { pairs }
    }

    /// Returns the address the proxy reaches for an address the program sent to.
    fn outward(&self, address: SocketAddr) -> SocketAddr {
        let found = self
            .pairs
            .iter()
            .find(|(inside, _)| *inside == address.ip());
        found.map_or(address, |(_, outside)| {
            SocketAddr::new(*outside, address.port())
        })
    }

    /// Returns the address the program knows for an address the proxy heard from.
    fn inward(&self, address: SocketAddr) -> SocketAddr {
        let found = self
            .pairs
            .iter()
            .find(|(_, outside)| *outside == address.ip());
        found.map_or(address, |(inside, _)| {
            SocketAddr::new(*inside, address.port())
        })
    }
}

/// Runs the stack on the TUN device until the stop sender is used or dropped.
pub(crate) async fn serve(
    tun: AsyncFd<File>,
    proxy: SocketAddr,
    names: NameServers,
    mut stop: oneshot::Receiver<()>,
) {
    let (commands, mut orders) = mpsc::unbounded_channel();
    let mut stack = Stack::new(proxy, names, commands);
    let mut packet = vec![u8::MIN; LARGEST_PACKET];
    loop {
        let delay = stack
            .interface
            .poll_delay(smoltcp::time::Instant::now(), &stack.sockets)
            .map(Duration::from);
        tokio::select! {
            _ = &mut stop => return,
            readable = tun.readable() => {
                let Ok(mut guard) = readable else { return };
                for _ in usize::MIN..PACKETS_PER_TURN {
                    match guard.try_io(|file| file.get_ref().read(&mut packet)) {
                        Ok(Ok(length)) => stack.receive(&packet[..length]),
                        Ok(Err(_)) => return,
                        Err(_would_block) => break,
                    }
                }
            }
            command = orders.recv() => {
                let Some(command) = command else { return };
                stack.obey(command);
                while let Ok(command) = orders.try_recv() {
                    stack.obey(command);
                }
            }
            // With no timer set, only a packet or a message wakes the stack.
            () = sleep(delay.unwrap_or_default()), if delay.is_some() => {}
        }
        stack.turn();
        for packet in stack.device.outbound.drain(..) {
            // A TUN device takes a packet whole or not at all; one it cannot take is lost, as on any network.
            let _ = tun.get_ref().write(&packet);
        }
    }
}

/// A TCP connection's number, which no other connection of the stack has.
type FlowId = u64;

/// A message from a connection's or a UDP source's task to the stack.
enum Command {
    /// The proxy opened the connection's stream, so the stack answers the program's SYN.
    Connected {
        flow: FlowId,
        /// Where the stack sends what the program sends.
        upload: mpsc::UnboundedSender<Upload>,
        /// The bytes the task may hand over before the stack takes them in, which the stack gives back as it does.
        credit: Arc<Semaphore>,
    },
    /// The proxy could not open the connection's stream, so the stack resets the program's SYN.
    Refused(FlowId),
    /// Bytes the proxy sent for the program.
    Download(FlowId, Vec<u8>),
    /// The proxy sent all it will, so the stack closes the program's receiving side once it has the rest.
    Finish(FlowId),
    /// The stream to the proxy failed, so the stack resets the connection.
    Abort(FlowId),
    /// The task wrote this many of the program's bytes to the proxy.
    Uploaded(FlowId, usize),
    /// A datagram the relay brought for a UDP source of the program.
    Datagram {
        to: SocketAddr,
        from: SocketAddr,
        payload: Vec<u8>,
    },
    /// The relay of the UDP source closed.
    Dissociated(SocketAddr),
}

/// A message from the stack to a connection's task about what the program sent.
enum Upload {
    /// What the program sent next.
    Bytes(Vec<u8>),
    /// The program will send nothing more.
    End,
}

/// A TCP connection the program opened.
enum Flow {
    /// The program's SYN, kept until the proxy says whether the destination answered.
    Waiting {
        ends: (SocketAddr, SocketAddr),
        syn: Vec<u8>,
    },
    /// A connection the stack accepted.
    Open(Connection),
}

/// An accepted TCP connection: its socket and what moves between it and its task.
struct Connection {
    /// The program's address, then the destination's.
    ends: (SocketAddr, SocketAddr),
    handle: SocketHandle,
    /// Where the program's bytes go, none once the program ended its side.
    upload: Option<mpsc::UnboundedSender<Upload>>,
    /// The bytes sent to the task and not yet written to the proxy.
    uploading: usize,
    /// The proxy's bytes that the socket had no room for yet.
    download: VecDeque<u8>,
    credit: Arc<Semaphore>,
    /// Whether the socket closes its sending side once the download is empty.
    finishing: bool,
}

/// The stack's state: the smoltcp interface, its sockets, and the program's TCP connections and UDP sources.
struct Stack {
    interface: Interface,
    device: Queues,
    sockets: SocketSet<'static>,
    flows: HashMap<FlowId, Flow>,
    /// Each connection's number by its program's address and destination.
    by_ends: HashMap<(SocketAddr, SocketAddr), FlowId>,
    next_flow: FlowId,
    /// Where each UDP source's datagrams go, with their destination.
    associations: HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Vec<u8>)>>,
    commands: mpsc::UnboundedSender<Command>,
    proxy: SocketAddr,
    names: NameServers,
}

impl Stack {
    /// Returns a stack with no connections that sends to the proxy and has its tasks send to the commands' channel.
    fn new(
        proxy: SocketAddr,
        names: NameServers,
        commands: mpsc::UnboundedSender<Command>,
    ) -> Self {
        let mut device = Queues::default();
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            smoltcp::time::Instant::now(),
        );
        interface.set_any_ip(true);
        interface.update_ip_addrs(|addresses| {
            // Each prefix is of length zero, so every address is routed to the stack.
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(STACK_IPV4), u8::MIN));
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv6(STACK_IPV6), u8::MIN));
        });
        let _ = interface.routes_mut().add_default_ipv4_route(STACK_IPV4);
        let _ = interface.routes_mut().add_default_ipv6_route(STACK_IPV6);
        Self {
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            flows: HashMap::new(),
            by_ends: HashMap::new(),
            next_flow: FlowId::MIN,
            associations: HashMap::new(),
            commands,
            proxy,
            names,
        }
    }

    /// Takes a packet the program sent: a TCP segment goes to smoltcp or waits for the proxy, and a UDP datagram to its relay.
    fn receive(&mut self, packet: &[u8]) {
        let Some((protocol, source, destination, payload)) = parse(packet) else {
            return;
        };
        match protocol {
            IpProtocol::Tcp => self.receive_segment(packet, source, destination, payload),
            IpProtocol::Udp => {
                let Ok(datagram) = UdpPacket::new_checked(payload) else {
                    return;
                };
                let source = SocketAddr::new(source, datagram.src_port());
                let destination = SocketAddr::new(destination, datagram.dst_port());
                self.receive_datagram(source, destination, datagram.payload());
            }
            _ => {}
        }
    }

    /// Takes a TCP segment, starting a connection's task if it is a SYN no connection has.
    fn receive_segment(
        &mut self,
        packet: &[u8],
        source: IpAddr,
        destination: IpAddr,
        payload: &[u8],
    ) {
        let Ok(segment) = TcpPacket::new_checked(payload) else {
            return;
        };
        let ends = (
            SocketAddr::new(source, segment.src_port()),
            SocketAddr::new(destination, segment.dst_port()),
        );
        match self
            .by_ends
            .get(&ends)
            .and_then(|flow| self.flows.get(flow))
        {
            // The program sent its SYN again while the proxy connects; the first one is answered.
            Some(Flow::Waiting { .. }) => {}
            Some(Flow::Open(_)) => self.device.inbound.push_back(packet.to_vec()),
            None if segment.syn() && !segment.ack() && ends.1.port() != u16::MIN => {
                let flow = self.next_flow;
                self.next_flow += 1;
                self.by_ends.insert(ends, flow);
                self.flows.insert(
                    flow,
                    Flow::Waiting {
                        ends,
                        syn: packet.to_vec(),
                    },
                );
                tokio::spawn(carry(
                    flow,
                    self.proxy,
                    self.names.outward(ends.1),
                    self.commands.clone(),
                ));
            }
            // smoltcp resets a segment no socket takes.
            None => self.device.inbound.push_back(packet.to_vec()),
        }
    }

    /// Sends a datagram to its source's relay, opening the relay if the source has none.
    fn receive_datagram(&mut self, source: SocketAddr, destination: SocketAddr, payload: &[u8]) {
        let multicast = destination.ip().is_multicast()
            || destination.ip() == IpAddr::V4(std::net::Ipv4Addr::BROADCAST);
        if destination.port() == u16::MIN || multicast {
            return;
        }
        let datagram = (self.names.outward(destination), payload.to_vec());
        let datagram = match self.associations.get(&source) {
            Some(relay) => match relay.try_send(datagram) {
                Ok(()) | Err(TrySendError::Full(_)) => return,
                Err(TrySendError::Closed(datagram)) => datagram,
            },
            None => datagram,
        };
        let (relay, datagrams) = mpsc::channel(UDP_QUEUE);
        let _ = relay.try_send(datagram);
        self.associations.insert(source, relay);
        tokio::spawn(associate(
            source,
            self.proxy,
            datagrams,
            self.commands.clone(),
        ));
    }

    /// Carries out a message from a task.
    fn obey(&mut self, command: Command) {
        match command {
            Command::Connected {
                flow,
                upload,
                credit,
            } => self.accept(flow, upload, credit),
            Command::Refused(flow) => {
                if let Some(Flow::Waiting { ends, syn }) = self.flows.remove(&flow) {
                    self.by_ends.remove(&ends);
                    // No socket takes the SYN, so smoltcp resets it, and the program's connect fails.
                    self.device.inbound.push_back(syn);
                }
            }
            Command::Download(flow, bytes) => {
                if let Some(Flow::Open(connection)) = self.flows.get_mut(&flow) {
                    connection.download.extend(bytes);
                }
            }
            Command::Finish(flow) => {
                if let Some(Flow::Open(connection)) = self.flows.get_mut(&flow) {
                    connection.finishing = true;
                }
            }
            Command::Abort(flow) => {
                if let Some(Flow::Open(connection)) = self.flows.get_mut(&flow) {
                    self.sockets
                        .get_mut::<tcp::Socket>(connection.handle)
                        .abort();
                }
            }
            Command::Uploaded(flow, length) => {
                if let Some(Flow::Open(connection)) = self.flows.get_mut(&flow) {
                    connection.uploading = connection.uploading.saturating_sub(length);
                }
            }
            Command::Datagram { to, from, payload } => {
                let from = self.names.inward(from);
                if let Some(packet) = udp_packet(from, to, &payload) {
                    self.device.outbound.push(packet);
                }
            }
            Command::Dissociated(source) => {
                if let Entry::Occupied(relay) = self.associations.entry(source)
                    && relay.get().is_closed()
                {
                    relay.remove();
                }
            }
        }
    }

    /// Answers the waiting SYN of the connection with a socket of its own.
    fn accept(
        &mut self,
        flow: FlowId,
        upload: mpsc::UnboundedSender<Upload>,
        credit: Arc<Semaphore>,
    ) {
        let Some(Flow::Waiting { ends, syn }) = self.flows.remove(&flow) else {
            return;
        };
        let buffers = (
            tcp::SocketBuffer::new(vec![u8::MIN; SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![u8::MIN; SOCKET_BUFFER]),
        );
        let mut socket = tcp::Socket::new(buffers.0, buffers.1);
        let endpoint = IpListenEndpoint {
            addr: Some(IpAddress::from(ends.1.ip())),
            port: ends.1.port(),
        };
        if socket.listen(endpoint).is_err() {
            self.by_ends.remove(&ends);
            return;
        }
        socket.set_nagle_enabled(false);
        let handle = self.sockets.add(socket);
        self.device.inbound.push_back(syn);
        // The stack takes the SYN now, so the listening socket meets no other connection's SYN to the same destination.
        self.interface.poll(
            smoltcp::time::Instant::now(),
            &mut self.device,
            &mut self.sockets,
        );
        let connection = Connection {
            ends,
            handle,
            upload: Some(upload),
            uploading: usize::MIN,
            download: VecDeque::new(),
            credit,
            finishing: false,
        };
        self.flows.insert(flow, Flow::Open(connection));
    }

    /// Lets smoltcp take and send packets, moves bytes between the sockets and their tasks, and forgets the connections that ended.
    fn turn(&mut self) {
        self.interface.poll(
            smoltcp::time::Instant::now(),
            &mut self.device,
            &mut self.sockets,
        );
        for flow in self.flows.values_mut() {
            if let Flow::Open(connection) = flow {
                connection.exchange(self.sockets.get_mut::<tcp::Socket>(connection.handle));
            }
        }
        self.interface.poll(
            smoltcp::time::Instant::now(),
            &mut self.device,
            &mut self.sockets,
        );
        let sockets = &self.sockets;
        let ended: Vec<FlowId> = self
            .flows
            .iter()
            .filter_map(|(flow, state)| match state {
                // A socket back to listening had its handshake reset.
                Flow::Open(connection)
                    if matches!(
                        sockets.get::<tcp::Socket>(connection.handle).state(),
                        tcp::State::Closed | tcp::State::Listen
                    ) =>
                {
                    Some(*flow)
                }
                _ => None,
            })
            .collect();
        for flow in ended {
            if let Some(Flow::Open(connection)) = self.flows.remove(&flow) {
                self.by_ends.remove(&connection.ends);
                self.sockets.remove(connection.handle);
                // The task stops waiting for room, and sees the program's side reset unless it ended.
                connection.credit.close();
            }
        }
    }
}

impl Connection {
    /// Moves the proxy's bytes into the socket and the program's out of it, and passes on either side's end.
    fn exchange(&mut self, socket: &mut tcp::Socket<'static>) {
        while socket.can_send() && !self.download.is_empty() {
            let moved = socket
                .send_slice(self.download.as_slices().0)
                .unwrap_or(usize::MIN);
            if moved == usize::MIN {
                break;
            }
            self.download.drain(..moved);
            self.credit.add_permits(moved);
        }
        if self.finishing && self.download.is_empty() {
            socket.close();
            self.finishing = false;
        }
        let Some(upload) = &self.upload else { return };
        while socket.can_recv() && self.uploading < UPLOAD_WINDOW {
            let mut bytes = vec![u8::MIN; CHUNK.min(UPLOAD_WINDOW - self.uploading)];
            let length = socket.recv_slice(&mut bytes).unwrap_or(usize::MIN);
            if length == usize::MIN {
                break;
            }
            bytes.truncate(length);
            self.uploading += length;
            let _ = upload.send(Upload::Bytes(bytes));
        }
        let handshaking = matches!(
            socket.state(),
            tcp::State::Listen | tcp::State::SynReceived | tcp::State::Closed
        );
        if !handshaking && !socket.may_recv() {
            let _ = upload.send(Upload::End);
            self.upload = None;
        }
    }
}

/// Opens the connection's stream through the proxy and carries its bytes both ways, each side's end passed on alone.
async fn carry(
    flow: FlowId,
    proxy: SocketAddr,
    destination: SocketAddr,
    commands: mpsc::UnboundedSender<Command>,
) {
    let stream = match timeout(HANDSHAKE_TIMEOUT, socks::connect(proxy, destination)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            let _ = commands.send(Command::Refused(flow));
            return;
        }
    };
    let (upload, uploads) = mpsc::unbounded_channel();
    let credit = Arc::new(Semaphore::new(DOWNLOAD_WINDOW));
    if commands
        .send(Command::Connected {
            flow,
            upload,
            credit: credit.clone(),
        })
        .is_err()
    {
        return;
    }
    if relay(flow, stream, uploads, &credit, &commands)
        .await
        .is_err()
    {
        let _ = commands.send(Command::Abort(flow));
    }
}

/// Copies the program's bytes to the stream and the stream's to the program until both sides end, failing if either resets.
async fn relay(
    flow: FlowId,
    stream: TcpStream,
    mut uploads: mpsc::UnboundedReceiver<Upload>,
    credit: &Semaphore,
    commands: &mpsc::UnboundedSender<Command>,
) -> std::io::Result<()> {
    let reset = || std::io::Error::from(std::io::ErrorKind::ConnectionReset);
    let (mut reader, mut writer) = stream.into_split();
    let upward = async {
        loop {
            match uploads.recv().await.ok_or_else(reset)? {
                Upload::Bytes(bytes) => {
                    writer.write_all(&bytes).await?;
                    let _ = commands.send(Command::Uploaded(flow, bytes.len()));
                }
                Upload::End => return writer.shutdown().await,
            }
        }
    };
    let downward = async {
        let mut bytes = vec![u8::MIN; CHUNK];
        loop {
            let length = reader.read(&mut bytes).await?;
            if length == usize::MIN {
                let _ = commands.send(Command::Finish(flow));
                return Ok(());
            }
            let permits = u32::try_from(length).map_err(|_| reset())?;
            credit
                .acquire_many(permits)
                .await
                .map_err(|_| reset())?
                .forget();
            let _ = commands.send(Command::Download(flow, bytes[..length].to_vec()));
        }
    };
    tokio::try_join!(upward, downward).map(|_| ())
}

/// Relays a UDP source's datagrams through an association at the proxy until it goes idle or the proxy ends it, then tells the stack.
async fn associate(
    source: SocketAddr,
    proxy: SocketAddr,
    datagrams: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    commands: mpsc::UnboundedSender<Command>,
) {
    let _ = relay_datagrams(source, proxy, datagrams, &commands).await;
    let _ = commands.send(Command::Dissociated(source));
}

/// Opens the association and carries datagrams both ways, the replies to the stack for the source.
async fn relay_datagrams(
    source: SocketAddr,
    proxy: SocketAddr,
    mut datagrams: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    commands: &mpsc::UnboundedSender<Command>,
) -> std::io::Result<()> {
    let (mut control, relay) = timeout(HANDSHAKE_TIMEOUT, socks::associate(proxy)).await??;
    let local = SocketAddr::new(control.local_addr()?.ip(), u16::MIN);
    let socket = UdpSocket::bind(local).await?;
    socket.connect(relay).await?;
    let mut received = vec![u8::MIN; LARGEST_PACKET];
    let mut ignored = vec![u8::MIN; CHUNK];
    let mut deadline = Instant::now() + UDP_IDLE;
    loop {
        tokio::select! {
            datagram = datagrams.recv() => {
                let Some((destination, payload)) = datagram else { return Ok(()) };
                socket.send(&socks::wrap(destination, &payload)).await?;
                deadline = Instant::now() + UDP_IDLE;
            }
            length = socket.recv(&mut received) => {
                if let Some((from, payload)) = socks::unwrap(&received[..length?]) {
                    let _ = commands.send(Command::Datagram { to: source, from, payload: payload.to_vec() });
                    deadline = Instant::now() + UDP_IDLE;
                }
            }
            // The association lasts as long as its stream; the proxy sends nothing on it but its end.
            _ = control.read(&mut ignored) => return Ok(()),
            () = sleep_until(deadline) => return Ok(()),
        }
    }
}

/// Returns an IP packet's protocol, its addresses, and its payload, or none if it is no whole IPv4 or IPv6 packet.
fn parse(packet: &[u8]) -> Option<(IpProtocol, IpAddr, IpAddr, &[u8])> {
    match IpVersion::of_packet(packet).ok()? {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(packet).ok()?;
            // A fragment's ports are in its first piece only; smoltcp, built without reassembly, drops fragments too.
            if packet.more_frags() || packet.frag_offset() != u16::MIN {
                return None;
            }
            Some((
                packet.next_header(),
                packet.src_addr().into(),
                packet.dst_addr().into(),
                packet.payload(),
            ))
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(packet).ok()?;
            Some((
                packet.next_header(),
                packet.src_addr().into(),
                packet.dst_addr().into(),
                packet.payload(),
            ))
        }
    }
}

/// Returns the IP packet that brings the UDP payload to the program, or none if the addresses' families differ beyond mapping.
fn udp_packet(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let from_ip = match (from.ip(), to.ip()) {
        (IpAddr::V4(ip), IpAddr::V6(_)) => IpAddr::V6(ip.to_ipv6_mapped()),
        (IpAddr::V6(ip), IpAddr::V4(_)) => IpAddr::V4(ip.to_ipv4_mapped()?),
        (ip, _) => ip,
    };
    let udp = UdpRepr {
        src_port: from.port(),
        dst_port: to.port(),
    };
    let checksums = ChecksumCapabilities::default();
    let udp_length = udp.header_len() + payload.len();
    let (mut packet, header_length) = match (from_ip, to.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let ip = Ipv4Repr {
                src_addr: source,
                dst_addr: destination,
                next_header: IpProtocol::Udp,
                payload_len: udp_length,
                hop_limit: HOP_LIMIT,
            };
            let mut packet = vec![u8::MIN; ip.buffer_len() + udp_length];
            u16::try_from(packet.len()).ok()?;
            ip.emit(&mut Ipv4Packet::new_unchecked(&mut packet), &checksums);
            (packet, ip.buffer_len())
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let ip = Ipv6Repr {
                src_addr: source,
                dst_addr: destination,
                next_header: IpProtocol::Udp,
                payload_len: udp_length,
                hop_limit: HOP_LIMIT,
            };
            let mut packet = vec![u8::MIN; ip.buffer_len() + udp_length];
            u16::try_from(udp_length).ok()?;
            ip.emit(&mut Ipv6Packet::new_unchecked(&mut packet));
            (packet, ip.buffer_len())
        }
        _ => return None,
    };
    let mut datagram = UdpPacket::new_unchecked(&mut packet[header_length..]);
    udp.emit(
        &mut datagram,
        &IpAddress::from(from_ip),
        &IpAddress::from(to.ip()),
        payload.len(),
        |space| space.copy_from_slice(payload),
        &checksums,
    );
    Some(packet)
}

/// A smoltcp device made of two queues: packets read off the TUN device, and packets smoltcp sends.
#[derive(Default)]
struct Queues {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

impl Device for Queues {
    type RxToken<'a> = Inbound;
    type TxToken<'a> = Outbound<'a>;

    fn receive(&mut self, _timestamp: smoltcp::time::Instant) -> Option<(Inbound, Outbound<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((Inbound(packet), Outbound(&mut self.outbound)))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Outbound<'_>> {
        Some(Outbound(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities
    }
}

/// A packet smoltcp takes from the inbound queue.
struct Inbound(Vec<u8>);

impl RxToken for Inbound {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, take: F) -> R {
        take(&self.0)
    }
}

/// The place in the outbound queue for a packet smoltcp sends.
struct Outbound<'a>(&'a mut Vec<Vec<u8>>);

impl TxToken for Outbound<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, fill: F) -> R {
        let mut packet = vec![u8::MIN; length];
        let result = fill(&mut packet);
        self.0.push(packet);
        result
    }
}
