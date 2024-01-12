use libc::{
    c_void, if_nametoindex, packet_mreq, setsockopt, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC,
    SOL_PACKET,
};
use smoltcp::phy::RawSocket;
use std::convert::TryInto;
use std::ffi::{CString, NulError};
use std::io;
use std::mem::size_of;
use std::num::TryFromIntError;
use std::os::unix::io::AsRawFd;
use thiserror::Error;

pub fn set_promiscuous_mode(
    interface_name: &str,
    raw_socket: &RawSocket,
) -> Result<(), PromiscuousModeError> {
    // Turn interface name into correct form
    let interface_name = CString::new(interface_name)?;
    // Get the interface idx
    let interface_idx = unsafe { if_nametoindex(interface_name.into_raw()) };
    if interface_idx == 0 {
        Err(io::Error::last_os_error())?;
    }
    let mreq = libc::packet_mreq {
        mr_ifindex: interface_idx.try_into()?,
        mr_type: PACKET_MR_PROMISC.try_into()?,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    let res = unsafe {
        setsockopt(
            raw_socket.as_raw_fd(),
            SOL_PACKET,
            PACKET_ADD_MEMBERSHIP,
            &mreq as *const packet_mreq as *const c_void,
            size_of::<packet_mreq>().try_into()?,
        )
    };
    if res == 0 {
        Ok(())
    } else {
        Err(PromiscuousModeError::SetSockOpt(io::Error::last_os_error()))
    }
}

#[derive(Debug, Error)]
pub enum PromiscuousModeError {
    #[error("Error converting interface name to a C type")]
    InterfaceName(#[from] NulError),
    #[error("Error getting index for the interface")]
    InterfaceIndex(#[from] io::Error),
    #[error("Error doing integer conversion")]
    Convert(#[from] TryFromIntError),
    #[error("Error doing setsockopt")]
    SetSockOpt(io::Error),
}
