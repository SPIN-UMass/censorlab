use epoll::{ControlOptions, Event, Events};
use std::io;
use std::num::TryFromIntError;
use std::os::unix::io::RawFd;
use std::time::Duration;
use thiserror::Error;

pub struct EPoll {
    fd: RawFd,
}
impl EPoll {
    pub fn new() -> Result<Self, io::Error> {
        // Create an epoll fd
        let fd = epoll::create(false)?;
        Ok(EPoll { fd })
    }
    pub fn add_fd(&mut self, fd: RawFd) -> Result<(), io::Error> {
        let events = Events::EPOLLIN | Events::EPOLLPRI;
        epoll::ctl(
            self.fd,
            ControlOptions::EPOLL_CTL_ADD,
            fd,
            Event::new(events, 0),
        )
    }
    pub fn wait(&mut self, timeout: Duration) -> Result<Vec<Event>, WaitError> {
        let mut events = vec![Event::new(Events::empty(), 0)];
        let timeout = timeout.as_millis().try_into()?;
        let result = epoll::wait(self.fd, timeout, &mut events)?;
        events.truncate(result);
        Ok(events)
    }
}

#[derive(Debug, Error)]
pub enum WaitError {
    #[error("failed to convert duration")]
    DurationInvalid(#[from] TryFromIntError),
    #[error("epoll error")]
    EPoll(#[from] io::Error),
}
