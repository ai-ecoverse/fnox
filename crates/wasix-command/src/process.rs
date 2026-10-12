//! This process's id, and signals to other processes by pid, for which std
//! has no portable API: `kill -0` to see whether a pid is still running, or
//! SIGTERM to stop a server started earlier.
//!
//! In slicc's kernel these are WASIX `proc_id` and `proc_signal`; on unix
//! they are `getpid` (std) and `kill(2)`.

use std::io;

/// A signal [`signal`] can send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signal {
    /// No signal: only checks that the process exists and may be signalled
    /// (`kill -0`).
    Probe,
    Hangup,
    Interrupt,
    Kill,
    Terminate,
}

#[cfg(all(target_os = "wasi", target_env = "p1"))]
mod sys {
    #[link(wasm_import_module = "wasix_32v1")]
    extern "C" {
        pub fn proc_id(pid: *mut u32) -> u16;
        pub fn proc_signal(pid: u32, signal: u32) -> u16;
    }
}

/// This process's id: the kernel's pid in slicc, `std::process::id()`
/// elsewhere. (std's panics on WASI.)
#[allow(unsafe_code)]
pub fn id() -> u32 {
    #[cfg(all(target_os = "wasi", target_env = "p1"))]
    {
        let mut pid = 0u32;
        // SAFETY: proc_id writes one u32.
        match unsafe { sys::proc_id(&mut pid) } {
            0 => pid,
            _ => 0,
        }
    }
    #[cfg(not(all(target_os = "wasi", target_env = "p1")))]
    {
        std::process::id()
    }
}

/// Sends `signal` to process `pid`. A pid that does not exist is an error
/// (ESRCH), so `signal(pid, Signal::Probe).is_ok()` says whether it is
/// still running.
#[allow(unsafe_code)]
pub fn signal(pid: u32, signal: Signal) -> io::Result<()> {
    #[cfg(all(target_os = "wasi", target_env = "p1"))]
    {
        // WASI signal numbers.
        let number = match signal {
            Signal::Probe => 0,
            Signal::Hangup => 1,
            Signal::Interrupt => 2,
            Signal::Kill => 9,
            Signal::Terminate => 15,
        };
        // SAFETY: plain integers.
        match unsafe { sys::proc_signal(pid, number) } {
            0 => Ok(()),
            e => Err(io::Error::from_raw_os_error(i32::from(e))),
        }
    }
    #[cfg(all(unix, not(all(target_os = "wasi", target_env = "p1"))))]
    {
        let number = match signal {
            Signal::Probe => 0,
            Signal::Hangup => libc::SIGHUP,
            Signal::Interrupt => libc::SIGINT,
            Signal::Kill => libc::SIGKILL,
            Signal::Terminate => libc::SIGTERM,
        };
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
        // SAFETY: kill(2) with plain integers.
        match unsafe { libc::kill(pid, number) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
    #[cfg(not(any(unix, all(target_os = "wasi", target_env = "p1"))))]
    {
        let _ = (pid, signal);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "signals are not supported here",
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn own_pid_probes_and_a_dead_child_does_not() {
        assert_eq!(id(), std::process::id());
        signal(id(), Signal::Probe).unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        signal(child.id(), Signal::Probe).unwrap();
        signal(child.id(), Signal::Terminate).unwrap();
        child.wait().unwrap();
        let err = signal(child.id(), Signal::Probe).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }
}
