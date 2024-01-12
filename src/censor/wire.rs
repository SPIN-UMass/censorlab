use super::{Censor, Direction, ForwardFramesResult, RetryBuffer};
use crate::censor::Action;
use clap::Parser;
use smoltcp::phy::{Device, Medium, RawSocket, RxToken, TxToken};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::Error as SmoltcpError;
use std::io;
use thiserror::Error;
use tracing::{error, info, span, Level};

/// Args to wire mode
#[derive(Debug, Parser)]
pub struct Args {
    /// WAN interface name  
    pub wan_interface: String,
    /// Client interface name
    pub client_interface: String,
    /// How many packets to process at most from the WAN interface before polling the client
    /// interface
    #[clap(long, default_value_t = 1)]
    pub wan_packets: usize,
    /// How many packets to process at most from the client interface before polling the WAN
    /// interface
    #[clap(long, default_value_t = 1)]
    pub client_packets: usize,
}

/// Error running in wire mode
#[derive(Debug, Error)]
pub enum WireError {
    #[error("failed to open WAN interface")]
    WanIfaceInit(io::Error),
    #[error("failed to open client interface")]
    ClientIfaceInit(io::Error),
}

/// Context for the wire censor
pub struct Context {
    pub direction: Direction,
}

impl Censor {
    /// Run the censor in wire mode
    pub fn run_wire(mut self, args: Args) -> Result<(), WireError> {
        // Initialize the interfaces
        let mut wan_interface = RawSocket::new(&args.wan_interface, Medium::Ethernet)
            .map_err(WireError::WanIfaceInit)?;
        let mut client_interface = RawSocket::new(&args.wan_interface, Medium::Ethernet)
            .map_err(WireError::ClientIfaceInit)?;
        // Initialize buffers for the interfaces that are used for retrying packet sends
        let mut wan_retry = RetryBuffer::for_interface(&wan_interface);
        let mut client_retry = RetryBuffer::for_interface(&client_interface);
        // Run the main loop
        loop {
            // Forward packets each direction
            for direction in [Direction::WanToClient, Direction::ClientToWan] {
                // Refer to the correct variables
                let (num_packets, retry) = match direction {
                    Direction::WanToClient => (args.wan_packets, &mut wan_retry),
                    Direction::ClientToWan => (args.client_packets, &mut client_retry),
                    Direction::Unknown => {
                        continue;
                    }
                };
                // Enter a span that indicates the direction we're forwarding packets
                let span = span!(Level::TRACE, "forwarding frame", direction = %direction);
                let _span = span.enter();
                // Forward the frame
                match self.forward_frame(
                    &mut wan_interface,
                    &mut client_interface,
                    direction,
                    num_packets,
                    retry,
                ) {
                    // Frames successful, do nothing
                    Ok(ForwardFramesResult::Success) => {
                        // If there was a packet that needed retry, this means there should no longer be one
                        retry.clear()
                    }
                    // Frame received but not sent, we have store the packet for next time
                    Ok(ForwardFramesResult::TxFull(size)) => {
                        info!(
                            "Failed to forward a received packet. Transmitting it next iteration"
                        );
                        retry.size = Some(size);
                    }
                    // An error occurred, continue to the other direction
                    Err(err) => {
                        error!(
                            err = tracing::field::display(&err),
                            "Error forwarding a packet"
                        );
                    }
                };
            }
        }
    }
    /// Given a source and destination interface, process the frame and perform whatever
    /// action the censor deems appropriate
    ///
    /// # Arguments
    /// * `source_interface` - Interface to poll a packet from
    /// * `dest_interface` - Interface the packet should be forwarded to
    /// * `upto_times` - How many packets (at most) to forward
    /// * `backup_buffer` - Buffer that should be used to write a send-failed packet or read from
    /// to retry it
    /// * `retry_size` - size of the packet to try sending instead of reading one. Packet will be
    /// read if none
    pub fn forward_frame<'b>(
        &mut self,
        wan_interface: &'b mut RawSocket,
        client_interface: &'b mut RawSocket,
        direction: Direction,
        upto_times: usize,
        retry: &mut RetryBuffer,
    ) -> Result<ForwardFramesResult, SmoltcpError> {
        let (source_interface, dest_interface) = match direction {
            Direction::WanToClient => (wan_interface, client_interface),
            Direction::ClientToWan => (client_interface, wan_interface),
            // TODO: handle this
            Direction::Unknown => unreachable!(),
        };
        if let Some(retry_data) = retry.get_data() {
            info!(
                buffer_size = retry_data.len(),
                "Re-sending a packet that failed to send originally"
            );
            // Try to send the packet over the dest interface
            let send_result = if let Some(dest_tx) =
                dest_interface.transmit(SmoltcpInstant::from_micros_const(0))
            {
                dest_tx.consume(retry_data.len(), |dest_tx_buf| {
                    dest_tx_buf.copy_from_slice(retry_data);
                    Ok(ForwardFramesResult::Success)
                })
            } else {
                return Ok(ForwardFramesResult::TxFull(retry_data.len()));
            };
            // Always return early instead of trying N times. if there's congestion it will
            // probably be congested again in the near future
            return match send_result {
                Err(SmoltcpError) => Ok(ForwardFramesResult::TxFull(retry_data.len())),
                other => other,
            };
        }
        // Repeat the packet generation process
        for _ in 0..upto_times {
            // Check if there is a packet to receive
            if let Some((source_rx, _source_tx)) =
                source_interface.receive(SmoltcpInstant::from_micros_const(0))
            {
                // Pray this is monotonic (it's not)
                // let now = SmoltcpInstant::from(StdInstant::now());
                // Actually, the time here is a noop, so don't bother
                let fwd_result = source_rx.consume(|mut source_rx_buf| {
                    // Make our context
                    let mut context = Context { direction };
                    // Store the length of our packet
                    let source_len = source_rx_buf.len();
                    // Process the packet
                    let mut context = (&mut context).into();
                    match self.process_frame(&mut source_rx_buf, &mut context)? {
                        // None and ignore both mean forward
                        Action::None | Action::Ignore => {
                            if let Some(dest_tx) =
                                dest_interface.transmit(SmoltcpInstant::from_micros_const(0))
                            {
                                // Forward the packet to the other interface and store any errors
                                let send_result = dest_tx.consume(source_len, |dest_tx_buf| {
                                    dest_tx_buf.copy_from_slice(source_rx_buf);
                                    Ok(())
                                });
                                // Send can fail due to a full buffer. In this case we want to do an
                                // allocation for the data, and re-send it in a future iteration of the
                                // main loop
                                match send_result {
                                    Ok(()) => Ok(ForwardFramesResult::Success),
                                    // If the send fails, we have to retry it later
                                    Err(SmoltcpError) => {
                                        // This sucks, but we need to do another copy of the input buffer
                                        retry[..source_rx_buf.len()].copy_from_slice(source_rx_buf);
                                        // Return an error indicating what happened
                                        Ok(ForwardFramesResult::TxFull(source_rx_buf.len()))
                                    }
                                    // Pass along any other errors
                                    Err(err) => Err(err),
                                }
                            } else {
                                // If we were unable to get a handle on the
                                Err(SmoltcpError)
                            }
                        }
                        // If we decide to drop the packet, we did our job
                        Action::Drop => Ok(ForwardFramesResult::Success),
                        Action::Reset { .. } => {
                            // Need to fix after the reimplementation
                            unimplemented!()
                        }
                        Action::Delay(_instant) => todo!(),
                    }
                });
                match fwd_result {
                    // If success, continue with the loop as usual
                    Ok(ForwardFramesResult::Success) => {}
                    // If we have an unsent packet, return it immediately. Retrying within the loop
                    // is unlikely to work. Also immediately return errors, so just return in a
                    // catchall
                    other => {
                        return other;
                    }
                }
            } else {
                // If there was no packet to receive, don't try again and cut our loop short
                break;
            }
        }
        // If we finished the loop just fine, return a success!
        Ok(ForwardFramesResult::Success)
    }
}
