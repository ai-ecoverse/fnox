//! `std::process` for WASI programs in slicc's kernel.
//!
//! Rust std for `wasm32-wasip1` cannot start processes. slicc's kernel
//! implements WASIX `proc_spawn3`, `proc_join`, `proc_signal` and
//! `fd_pipe`, so on WASI preview1 this crate's [`Command`] uses them:
//! arguments, environment, working directory, and stdin / stdout / stderr
//! inherited, piped, null or from a file, with `spawn`, `output`,
//! `status`, `wait`, `try_wait` and `kill`. On every other target the
//! types are std's, so code written against them needs no cfg: switch the
//! import and keep to the API both share.
//!
//! A child that is spawned and dropped without `wait` keeps running
//! (detached), as with std. [`process`] has this process's id and signals
//! to other pids (`kill -0`, SIGTERM), which std has no portable API for.

pub mod process;

#[cfg(all(target_os = "wasi", target_env = "p1"))]
mod wasix;

#[cfg(all(target_os = "wasi", target_env = "p1"))]
pub use wasix::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};

#[cfg(not(all(target_os = "wasi", target_env = "p1")))]
pub use std::process::{
    Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio,
};
