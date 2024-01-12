use smoltcp::phy::{Device, Medium, RawSocket, TxToken};
use smoltcp::time::Instant as SmoltcpInstant;
use std::collections::BinaryHeap;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::{self, JoinHandle};
use tracing::error;

pub struct Delayer {
    // Sender to queue packets in the delay thread
    sender: Sender<QueuedPacket>,
    // Handle on the thread used to delay packets
    pub delay_thread: JoinHandle<()>,
}
impl Delayer {
    pub fn new(interface: String) -> Self {
        let (sender, receiver) = mpsc::channel(1024);
        let delay_thread = task::spawn(async move { run_thread(receiver, interface).await });
        Self {
            sender,
            delay_thread,
        }
    }
    pub fn delay_packet(
        &self,
        payload: Vec<u8>,
        until: Instant,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<QueuedPacket>> {
        self.sender.blocking_send(QueuedPacket {
            time: until,
            payload,
        })
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct QueuedPacket {
    time: Instant,
    payload: Vec<u8>,
}

async fn run_thread(mut queue: Receiver<QueuedPacket>, interface: String) {
    // A future that resolves after a sleep time
    let sleep_fut = tokio::time::sleep(Duration::from_secs(u64::MAX));
    tokio::pin!(sleep_fut);
    // The packet that should be sent with this future
    let mut next_packet: Option<QueuedPacket> = None;
    // A queue of packets, prioritized based on smallest packet time
    let mut packet_queue: BinaryHeap<QueuedPacket> = BinaryHeap::new();
    // Raw socket used to send packets
    // Loop infinitely
    let mut end = false;
    while !end {
        end = tokio::select! {
            // If our sleep timer is up
            () = &mut sleep_fut => {
                // Send the packet corresponding to the sleep timer
                if let Some(next_packet_r) = next_packet.take() {
                    let mut socket = RawSocket::new(&interface, Medium::Ip).expect("Failed to open interface");
                    if let Some(tx_token) = socket.transmit(SmoltcpInstant::from_micros_const(0)) {
                        if let Err(_err) = tx_token.consume(
                            next_packet_r.payload.len(),
                            |tx_buf| {
                                tx_buf.copy_from_slice(&next_packet_r.payload);
                                Ok::<(),()>(())
                            }
                        ) {
                            //TODO: print error if there is one
                            error!("Error sending delayed packet");
                        }
                    }
                    if let Some(new_packet) = packet_queue.pop() {
                        // Tell the sleep future to sleep until this next new packet
                        sleep_fut.as_mut().reset(new_packet.time.into());
                        // Set the next packet to this next new packet
                        next_packet = Some(new_packet);
                    }
                }
                // The loop is not over
                false
            },
            // If we received a new packet for the queue
            new_packet_maybe = queue.recv() => {
                // If the queue was shut down properly
                if let Some(new_packet) = new_packet_maybe {
                    // Check to see if a packet is already queued
                    if let Some(next_packet_r) = next_packet.take() {
                        let next_time = next_packet_r.time;
                        // Check if the new packet should be sent sooner than our currently queued one
                        if new_packet.time < next_time {
                            // Put the packet back on the queue
                            packet_queue.push(next_packet_r);
                            // Our new next packet is this new one
                            next_packet = Some(new_packet);
                            // Update the delay future
                            sleep_fut.as_mut().reset(next_time.into());
                        }
                        else {
                            // We took the next packet so put it back
                            next_packet = Some(next_packet_r);
                            // We are still getting a new packet so put it on the heap
                            packet_queue.push(new_packet);
                        }
                    }
                    // The loop is not over
                    false
                }
                else {
                    // This means that the queue was broken which means the program is shutting
                    // down which means shut down
                    true
                }
            },
        };
        if end {
            //todo: send the rest of the packets
            break;
        }
    }
}
