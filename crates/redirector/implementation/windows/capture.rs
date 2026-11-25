//! A started program with its packets diverted: the WinDivert handles, the threads that read them, and the stack.

use std::net::SocketAddr;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use simple_httptap_redirector::Program;

use crate::divert::{self, Address, Handle};
use crate::owners;
use crate::packet;
use crate::process::Job;
use crate::stack;
use crate::table::{Fate, Flow, GRACE, Table};

/// Every TCP and UDP socket operation, of every process; the job decides which matter.
const SOCKET_FILTER: &std::ffi::CStr = c"tcp || udp";
/// The network-layer WinDivert filter, which leaves loopback, multicast and broadcast traffic to pass untouched.
///
/// https://github.com/mitmproxy/mitmproxy_rs/blob/main/mitmproxy-windows/redirector/src/main2.rs
const NETWORK_FILTER: &std::ffi::CStr = c"outbound && !loopback && ((ip && remoteAddr < 224.0.0.0) || (ipv6 && remoteAddr < ff00::)) && (tcp || udp)";
/// A filter nothing matches, for the handle that only injects.
const NOTHING: &std::ffi::CStr = c"false";
/// The priority of the handles that capture; the injecting handle's is one lower, so what it injects is not captured again.
///
/// https://reqrypt.org/windivert-doc.html#divert_open
const PRIORITY: i16 = 1040;
/// The largest packet WinDivert hands over, WINDIVERT_MTU_MAX: an IPv6 header and the largest payload.
///
/// https://github.com/basil00/WinDivert/blob/master/include/windivert.h
const PACKET_MAX: usize = 40 + u16::MAX as usize;
/// The packets or events that wait in a channel between threads.
///
/// https://reqrypt.org/windivert-doc.html#divert_set_param
const QUEUE: usize = 4096;
/// How often waiting packets are checked for having waited too long, a fraction of how long they may wait.
const TICK: Duration = GRACE.checked_div(GRACE_CHECKS).unwrap();
/// How many times the waiting packets are checked within the time they may wait.
///
/// https://docs.rs/tokio/latest/tokio/time/fn.interval.html
const GRACE_CHECKS: u32 = 4;
/// The name of the thread that reads socket events.
const EVENTS_THREAD: &str = "httptap socket events";
/// The name of the thread that reads packets.
const PACKETS_THREAD: &str = "httptap packets";
/// The name of the thread that runs the stack and routes packets.
const STACK_THREAD: &str = "httptap stack";

/// A running program and the diversion of its packets.
#[derive(Debug)]
pub(crate) struct Running {
    child: Child,
    diversion: Diversion,
    watch: Arc<Watch>,
}

/// The record of whether the diversion is stopping on purpose, and of why it ended first if it did.
///
/// No capture fails silently: a thread that ends while the program runs stops the job's every process.
#[derive(Debug)]
struct Watch {
    stopping: AtomicBool,
    lost: Mutex<Option<String>>,
    job: Arc<Job>,
}

impl Watch {
    /// Records that the named thread ended while the program ran, and stops the program's every process.
    fn lose(&self, thread: &str) {
        if self.stopping.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut lost) = self.lost.lock() {
            lost.get_or_insert_with(|| format!("{thread} stopped while the program ran; httptap stopped the program so none of its traffic went uncaptured"));
        }
        self.job.terminate();
    }
}

/// The socket and network WinDivert handles with their serving threads, all stopped on drop.
#[derive(Debug)]
struct Diversion {
    socket: Arc<Handle>,
    network: Arc<Handle>,
    threads: Vec<JoinHandle<()>>,
}

/// Opens the WinDivert handles and starts the threads, then starts the program in a job whose processes are diverted.
pub(crate) fn launch(program: &Program, proxy: SocketAddr) -> std::io::Result<Running> {
    let library = divert::library()?;
    let socket = Arc::new(Handle::open(
        library,
        SOCKET_FILTER,
        divert::SOCKET,
        PRIORITY,
        divert::SNIFF | divert::RECEIVE_ONLY,
    )?);
    let network = Arc::new(Handle::open(
        library,
        NETWORK_FILTER,
        divert::NETWORK,
        PRIORITY,
        u64::MIN,
    )?);
    let inject = Handle::open(
        library,
        NOTHING,
        divert::NETWORK,
        PRIORITY - 1,
        divert::SEND_ONLY,
    )?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let job = Arc::new(Job::new()?);
    let (events, event_receiver) = mpsc::channel(QUEUE);
    let (packets, packet_receiver) = mpsc::channel(QUEUE);
    let mut diversion = Diversion {
        socket: Arc::clone(&socket),
        network: Arc::clone(&network),
        threads: Vec::new(),
    };
    let watch = Arc::new(Watch { stopping: AtomicBool::new(false), lost: Mutex::default(), job: Arc::clone(&job) });
    let reader = Arc::clone(&job);
    diversion.threads.push(spawn(EVENTS_THREAD, &watch, move || {
        read_events(&socket, &reader, &events)
    })?);
    diversion.threads.push(spawn(PACKETS_THREAD, &watch, move || {
        read_packets(&network, &packets)
    })?);
    let router = Arc::clone(&job);
    diversion.threads.push(spawn(STACK_THREAD, &watch, move || {
        runtime.block_on(route_packets(
            proxy,
            event_receiver,
            packet_receiver,
            inject,
            router,
        ));
        runtime.shutdown_background();
    })?);
    let child = job.start(program)?;
    Ok(Running { child, diversion, watch })
}

impl Running {
    /// Returns the started process's identifier.
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    /// Waits for the started process, then stops diverting.
    pub(crate) fn wait(mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait();
        self.watch.stopping.store(true, Ordering::SeqCst);
        drop(self.diversion);
        if let Some(cause) = self.watch.lost.lock().ok().and_then(|lost| lost.clone()) {
            return Err(std::io::Error::other(cause));
        }
        status
    }
}

impl Drop for Diversion {
    /// Shuts the capturing handles, which ends the threads, and waits for them.
    fn drop(&mut self) {
        self.socket.shut_down();
        self.network.shut_down();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Starts a named thread running the work; if the work ends or panics while the program runs, the program is stopped.
fn spawn(name: &str, watch: &Arc<Watch>, work: impl FnOnce() + Send + std::panic::UnwindSafe + 'static) -> std::io::Result<JoinHandle<()>> {
    let watch = Arc::clone(watch);
    let thread = name.to_owned();
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let _ = std::panic::catch_unwind(work);
            watch.lose(&thread);
        })
}

/// Reads socket events until the handle shuts, sending the fate of each flow opened or accepted.
///
/// A flow is diverted when a process in the job opened it; flows accepted from outside pass, as the proxy only connects out.
fn read_events(socket: &Handle, job: &Job, events: &mpsc::Sender<(Flow, Fate)>) {
    while let Ok((_, address)) = socket.receive(&mut []) {
        let Some((flow, process_id, opened)) = address.socket_flow() else {
            continue;
        };
        let fate = if opened && job.contains(process_id) {
            Fate::Divert
        } else {
            Fate::Pass
        };
        if events.blocking_send((flow, fate)).is_err() {
            return;
        }
    }
}

/// Reads outbound packets until the handle shuts, sending each with its address.
fn read_packets(network: &Handle, packets: &mpsc::Sender<(Vec<u8>, Address)>) {
    let mut buffer = vec![u8::MIN; PACKET_MAX];
    while let Ok((length, address)) = network.receive(&mut buffer) {
        if packets
            .blocking_send((buffer[..length].to_vec(), address))
            .is_err()
        {
            return;
        }
    }
}

/// Sorts each captured packet by its flow's fate: diverted ones go to the stack, the rest are injected again unchanged.
///
/// The stack's packets for the program are injected too. Ends when the packet handle shuts.
async fn route_packets(
    proxy: SocketAddr,
    mut events: mpsc::Receiver<(Flow, Fate)>,
    mut packets: mpsc::Receiver<(Vec<u8>, Address)>,
    inject: Handle,
    job: Arc<Job>,
) {
    let (diverted, diverted_receiver) = mpsc::channel(QUEUE);
    let (replies, mut reply_receiver) = mpsc::unbounded_channel();
    let stack = tokio::spawn(stack::serve(proxy, diverted_receiver, replies));
    let mut table = Table::new();
    let mut tick = tokio::time::interval(TICK);
    let send = |fate: Fate, (packet, address): (Vec<u8>, Address)| match fate {
        Fate::Pass => drop(inject.send(&packet, &address)),
        Fate::Divert => drop(diverted.try_send(packet)),
    };
    loop {
        tokio::select! {
            captured = packets.recv() => {
                let Some(captured) = captured else { break };
                let Some(flow) = packet::parse(&captured.0).map(|segment| Flow::outbound(&segment)) else {
                    send(Fate::Pass, captured);
                    continue;
                };
                if let Some((fate, captured)) = table.sort(flow, captured, Instant::now()) {
                    send(fate, captured);
                }
            }
            Some((flow, fate)) = events.recv() => {
                for captured in table.decide(flow, fate, Instant::now()) {
                    send(fate, captured);
                }
            }
            Some(reply) = reply_receiver.recv() => drop(inject.send(&reply, &Address::toward_program())),
            _ = tick.tick() => {
                let now = Instant::now();
                for flow in table.overdue(now) {
                    let fate = fate_by_owner(&flow, &job);
                    for captured in table.decide(flow, fate, now) {
                        send(fate, captured);
                    }
                }
            }
        }
    }
    let end = Instant::now() + GRACE;
    for flow in table.overdue(end) {
        let fate = fate_by_owner(&flow, &job);
        for captured in table.decide(flow, fate, end) {
            send(fate, captured);
        }
    }
    stack.abort();
}

/// Returns the fate of a flow no socket event named in time, from the process Windows says owns its port.
///
/// A flow whose owner Windows cannot name passes, which httptap says on stderr, as it may be the program's.
fn fate_by_owner(flow: &Flow, job: &Job) -> Fate {
    let (transport, local_port, remote) = Table::<()>::parts(flow);
    match owners::owner(transport, local_port, remote) {
        Some(process_id) if job.contains(process_id) => Fate::Divert,
        Some(_) => Fate::Pass,
        None => {
            eprintln!("httptap: Windows names no process for a flow from local port {local_port} to {remote}, so it passed uncaptured; if it was the program's, its traffic is missing from the output");
            Fate::Pass
        }
    }
}
