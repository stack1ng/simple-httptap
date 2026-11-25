//! A UDP association a client asked for: each destination it sends to becomes a flow of its own, relayed as sent.
//!
//! A flow is what the output calls a connection: one destination, its datagrams both ways, watched like TCP.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use simple_httptap_decoder::Direction;
use simple_httptap_sink::{Connection, Event, Transport};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::Shared;
use crate::socks::{self, Address, Status};
use crate::watch::Watch;

/// The largest datagram a UDP socket carries, with room for the SOCKS5 header in front.
const DATAGRAM_LIMIT: usize = 65_535;
/// How long a flow lives without a datagram either way before it is taken as closed.
///
/// QUIC's longest common idle timeout is 30 seconds, and this outlives it.
const FLOW_IDLE: Duration = Duration::from_secs(120);

/// A datagram one way: to the destination, from the client; or to the client, from the destination it names.
type Datagram = (Address, Vec<u8>);

/// Binds a relay for the client, tells it where, and relays its datagrams until it closes the control connection.
pub(crate) async fn serve(shared: Arc<Shared>, mut control: TcpStream, peer: SocketAddr) {
    let relay_ip = control.local_addr().map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |local| local.ip());
    let relay = match UdpSocket::bind(SocketAddr::new(relay_ip, u16::MIN)).await {
        Ok(relay) => relay,
        Err(_) => {
            let _ = socks::reply(&mut control, Status::GeneralFailure, unspecified(relay_ip)).await;
            return;
        }
    };
    let Ok(bound) = relay.local_addr() else { return };
    if socks::reply(&mut control, Status::Succeeded, bound).await.is_err() {
        return;
    }
    let (replies, mut to_client) = mpsc::unbounded_channel::<Datagram>();
    let mut flows: HashMap<Address, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    let mut client: Option<SocketAddr> = None;
    let mut buffer = vec![u8::MIN; DATAGRAM_LIMIT];
    let mut closed = [u8::MIN];
    loop {
        tokio::select! {
            read = control.read(&mut closed) => {
                if matches!(read, Ok(read) if read != usize::MIN) {
                    continue;
                }
                break;
            }
            received = relay.recv_from(&mut buffer) => {
                let Ok((size, from)) = received else { break };
                if from.ip() != peer.ip() || client.is_some_and(|client| client != from) {
                    continue;
                }
                client = Some(from);
                let Some((address, payload)) = socks::unwrap_datagram(&buffer[..size]) else { continue };
                let flow = flows.entry(address.clone()).or_insert_with(|| start_flow(&shared, from, address.clone(), replies.clone()));
                if flow.send(payload.to_vec()).is_err() {
                    let flow = start_flow(&shared, from, address.clone(), replies.clone());
                    let _ = flow.send(payload.to_vec());
                    flows.insert(address, flow);
                }
            }
            Some((address, payload)) = to_client.recv() => {
                if let Some(client) = client {
                    let _ = relay.send_to(&socks::wrap_datagram(&address, &payload), client).await;
                }
            }
        }
    }
}

/// Returns the unspecified address of the relay's family, for a reply that has nothing to tell.
fn unspecified(family: IpAddr) -> SocketAddr {
    let ip = if family.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) };
    SocketAddr::new(ip, u16::MIN)
}

/// Starts a flow to the destination, returning where to send the client's datagrams for it.
fn start_flow(shared: &Arc<Shared>, client: SocketAddr, target: Address, replies: mpsc::UnboundedSender<Datagram>) -> mpsc::UnboundedSender<Vec<u8>> {
    let (sender, from_client) = mpsc::unbounded_channel();
    let id = shared.next_id();
    tokio::spawn(run_flow(Arc::clone(shared), id, client, target, from_client, replies));
    sender
}

/// Relays one flow's datagrams both ways until it is idle or the association ends, sending copies to its watch.
async fn run_flow(
    shared: Arc<Shared>,
    id: u64,
    client: SocketAddr,
    target: Address,
    mut from_client: mpsc::UnboundedReceiver<Vec<u8>>,
    replies: mpsc::UnboundedSender<Datagram>,
) {
    let outbound = match Outbound::open(&shared, &target).await {
        Ok(outbound) => outbound,
        Err(fault) => {
            shared.emit(Event::Refused { connection: id, detail: format!("relaying UDP to {target}: {fault}") });
            shared.emit(Event::Closed { connection: id });
            return;
        }
    };
    let connection = Connection { id, client, target: target.to_string(), transport: Transport::Udp, tls: false, protocol: None };
    let (copies, received) = mpsc::unbounded_channel();
    let watching = tokio::spawn(Watch::new(Arc::clone(&shared), connection).run(received));
    let mut buffer = vec![u8::MIN; DATAGRAM_LIMIT];
    loop {
        tokio::select! {
            datagram = from_client.recv() => {
                let Some(datagram) = datagram else { break };
                let _ = copies.send((Direction::Client, datagram.clone()));
                if outbound.send(&datagram).await.is_err() {
                    break;
                }
            }
            received = outbound.receive(&mut buffer) => {
                let Ok(payload) = received else { break };
                let _ = copies.send((Direction::Server, payload.clone()));
                if replies.send((target.clone(), payload)).is_err() {
                    break;
                }
            }
            () = tokio::time::sleep(FLOW_IDLE) => break,
        }
    }
    drop(copies);
    let _ = watching.await;
}

/// The way a flow's datagrams reach the destination: straight, or through the upstream proxy's relay.
enum Outbound {
    Direct(UdpSocket),
    Upstream { socket: UdpSocket, target: Address, _control: TcpStream },
}

impl Outbound {
    /// Opens a socket of the flow's own toward the destination.
    async fn open(shared: &Shared, target: &Address) -> std::io::Result<Self> {
        let Some(upstream) = &shared.upstream else {
            let destination = target.resolve().await?;
            let socket = UdpSocket::bind(unspecified(destination.ip())).await?;
            socket.connect(destination).await?;
            return Ok(Self::Direct(socket));
        };
        let (control, relay) = socks::associate_upstream(upstream).await?;
        let socket = UdpSocket::bind(unspecified(relay.ip())).await?;
        socket.connect(relay).await?;
        Ok(Self::Upstream { socket, target: target.clone(), _control: control })
    }

    /// Sends one datagram to the destination.
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Direct(socket) => socket.send(payload).await.map(drop),
            Self::Upstream { socket, target, .. } => socket.send(&socks::wrap_datagram(target, payload)).await.map(drop),
        }
    }

    /// Receives the next datagram from the destination.
    async fn receive(&self, buffer: &mut [u8]) -> std::io::Result<Vec<u8>> {
        loop {
            match self {
                Self::Direct(socket) => {
                    let size = socket.recv(buffer).await?;
                    return Ok(buffer[..size].to_vec());
                }
                Self::Upstream { socket, .. } => {
                    let size = socket.recv(buffer).await?;
                    if let Some((_, payload)) = socks::unwrap_datagram(&buffer[..size]) {
                        return Ok(payload.to_vec());
                    }
                }
            }
        }
    }
}
