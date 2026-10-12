//! std-shaped processes over the WASIX calls of slicc's kernel.
//!
//! This module never imports `fd_fdflags_set`. The kernel then treats every
//! descriptor above 2 as close-on-exec, as Rust std opens them on unix, so
//! a child gets its three standard descriptors and nothing else, and pipe
//! ends reach EOF when their writers exit.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::wasi::ffi::OsStrExt;
use std::path::{Path, PathBuf};

mod sys {
    #[link(wasm_import_module = "wasix_32v1")]
    extern "C" {
        pub fn proc_spawn3(
            name: *const u8,
            name_len: u32,
            argv: *const *const u8,
            argc: u32,
            env: *const *const u8,
            envc: u32,
            ops: *const u8,
            op_count: u32,
            signal: u32,
            priority: u32,
            search: u32,
            path: *const u8,
            path_len: u32,
            pid: *mut u32,
        ) -> u16;
        pub fn proc_join(pid: *mut u8, flags: u32, status: *mut u8) -> u16;
        pub fn proc_signal(pid: u32, signal: u32) -> u16;
        pub fn fd_pipe(read: *mut u32, write: *mut u32) -> u16;
    }

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    extern "C" {
        pub fn poll_oneoff(subs: *const u8, events: *mut u8, nsubs: u32, nevents: *mut u32) -> u16;
    }
}

const FD_OP_SIZE: usize = 56;
const FD_OP_CLOSE: u8 = 0;
const FD_OP_DUP2: u8 = 1;
const FD_OP_OPEN: u8 = 2;
const FD_OP_CHDIR: u8 = 3;
const RIGHTS_FD_WRITE: u64 = 1 << 6;
const JOIN_NON_BLOCKING: u32 = 1;
const SIGKILL: u32 = 9;

fn cvt(errno: u16) -> io::Result<()> {
    match errno {
        0 => Ok(()),
        e => Err(io::Error::from_raw_os_error(i32::from(e))),
    }
}

fn cstr(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "nul byte found in provided data",
        )
    })
}

/// A `proc_spawn3` descriptor operation, applied in the child before it
/// starts. `path` must outlive the spawn call.
fn fd_op(cmd: u8, fd: u32, src: u32, path: &[u8], rights: u64) -> [u8; FD_OP_SIZE] {
    let mut op = [0u8; FD_OP_SIZE];
    op[0] = cmd;
    op[4..8].copy_from_slice(&fd.to_le_bytes());
    op[8..12].copy_from_slice(&src.to_le_bytes());
    op[12..16].copy_from_slice(&(path.as_ptr() as u32).to_le_bytes());
    op[16..20].copy_from_slice(&(path.len() as u32).to_le_bytes());
    op[32..40].copy_from_slice(&rights.to_le_bytes());
    op
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (mut r, mut w) = (0u32, 0u32);
    cvt(unsafe { sys::fd_pipe(&mut r, &mut w) })?;
    // SAFETY: `fd_pipe` returned two new descriptors that we now own.
    unsafe {
        Ok((
            OwnedFd::from_raw_fd(r as RawFd),
            OwnedFd::from_raw_fd(w as RawFd),
        ))
    }
}

/// How a child's stdin, stdout or stderr is set up.
pub struct Stdio(How);

enum How {
    Inherit,
    Null,
    Piped,
    Fd(OwnedFd),
}

impl Stdio {
    /// The child gets the parent's descriptor.
    pub fn inherit() -> Stdio {
        Stdio(How::Inherit)
    }

    /// The child reads nothing, and what it writes is dropped.
    pub fn null() -> Stdio {
        Stdio(How::Null)
    }

    /// A pipe to the parent: [`Child::stdin`], [`Child::stdout`] or
    /// [`Child::stderr`].
    pub fn piped() -> Stdio {
        Stdio(How::Piped)
    }
}

impl fmt::Debug for Stdio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            How::Inherit => f.write_str("Inherit"),
            How::Null => f.write_str("Null"),
            How::Piped => f.write_str("MakePipe"),
            How::Fd(fd) => write!(f, "Fd({})", fd.as_raw_fd()),
        }
    }
}

impl From<OwnedFd> for Stdio {
    fn from(fd: OwnedFd) -> Stdio {
        Stdio(How::Fd(fd))
    }
}

impl From<File> for Stdio {
    fn from(file: File) -> Stdio {
        Stdio(How::Fd(file.into()))
    }
}

/// An exit status: a code, or the signal that ended the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ExitStatus {
    code: i32,
    signal: Option<i32>,
}

impl ExitStatus {
    pub fn success(&self) -> bool {
        self.signal.is_none() && self.code == 0
    }

    /// The exit code; `None` when a signal ended the process.
    pub fn code(&self) -> Option<i32> {
        match self.signal {
            None => Some(self.code),
            Some(_) => None,
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.signal {
            None => write!(f, "exit status: {}", self.code),
            Some(sig) => write!(f, "signal: {sig}"),
        }
    }
}

/// A finished process's status and collected output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

macro_rules! pipe_end {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name {
            file: File,
        }

        impl AsRawFd for $name {
            fn as_raw_fd(&self) -> RawFd {
                self.file.as_raw_fd()
            }
        }
        impl AsFd for $name {
            fn as_fd(&self) -> BorrowedFd<'_> {
                self.file.as_fd()
            }
        }
        impl IntoRawFd for $name {
            fn into_raw_fd(self) -> RawFd {
                self.file.into_raw_fd()
            }
        }
        impl From<$name> for OwnedFd {
            fn from(end: $name) -> OwnedFd {
                end.file.into()
            }
        }
        impl From<$name> for Stdio {
            fn from(end: $name) -> Stdio {
                Stdio(How::Fd(end.file.into()))
            }
        }
    };
}

pipe_end!(ChildStdin);
pipe_end!(ChildStdout);
pipe_end!(ChildStderr);

impl Write for ChildStdin {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &ChildStdin {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.file).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for ChildStdout {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Read for ChildStderr {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

/// A builder for a child process, like `std::process::Command`.
pub struct Command {
    program: OsString,
    args: Vec<OsString>,
    env: BTreeMap<OsString, Option<OsString>>,
    env_clear: bool,
    cwd: Option<PathBuf>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.program)?;
        for arg in &self.args {
            write!(f, " {arg:?}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Default3 {
    Inherit,
    /// `output()`: stdin null, stdout and stderr piped.
    Capture,
}

impl Command {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Command {
        Command {
            program: program.as_ref().to_os_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            env_clear: false,
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Command {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, val: V) -> &mut Command {
        self.env.insert(
            key.as_ref().to_os_string(),
            Some(val.as_ref().to_os_string()),
        );
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Command
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (k, v) in vars {
            self.env(k, v);
        }
        self
    }

    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Command {
        self.env.insert(key.as_ref().to_os_string(), None);
        self
    }

    pub fn env_clear(&mut self) -> &mut Command {
        self.env.clear();
        self.env_clear = true;
        self
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Command {
        self.cwd = Some(dir.as_ref().to_path_buf());
        self
    }

    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Command {
        self.stdin = Some(cfg.into());
        self
    }

    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Command {
        self.stdout = Some(cfg.into());
        self
    }

    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Command {
        self.stderr = Some(cfg.into());
        self
    }

    pub fn get_program(&self) -> &OsStr {
        &self.program
    }

    pub fn get_args(&self) -> impl ExactSizeIterator<Item = &OsStr> {
        self.args.iter().map(OsString::as_os_str)
    }

    pub fn get_envs(&self) -> impl ExactSizeIterator<Item = (&OsStr, Option<&OsStr>)> {
        self.env.iter().map(|(k, v)| (k.as_os_str(), v.as_deref()))
    }

    pub fn get_current_dir(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    /// Starts the child with stdin, stdout and stderr inherited unless set.
    pub fn spawn(&mut self) -> io::Result<Child> {
        self.spawn_with(Default3::Inherit)
    }

    /// Runs the child to the end with stdin inherited unless set.
    pub fn status(&mut self) -> io::Result<ExitStatus> {
        self.spawn_with(Default3::Inherit)?.wait()
    }

    /// Runs the child to the end and collects its stdout and stderr; stdin
    /// is null unless set.
    pub fn output(&mut self) -> io::Result<Output> {
        self.spawn_with(Default3::Capture)?.wait_with_output()
    }

    fn environment(&self) -> BTreeMap<OsString, OsString> {
        let mut env: BTreeMap<OsString, OsString> = if self.env_clear {
            BTreeMap::new()
        } else {
            std::env::vars_os().collect()
        };
        for (k, v) in &self.env {
            match v {
                Some(v) => env.insert(k.clone(), v.clone()),
                None => env.remove(k),
            };
        }
        env
    }

    /// The program as given or, for a path that does not exist, the same
    /// path with `.wasm` when that does (Cargo's `build-script-build`), as
    /// Windows resolves `.exe`.
    fn program(&self) -> OsString {
        let program = &self.program;
        if program.as_bytes().contains(&b'/') && !Path::new(program).exists() {
            let mut with_suffix = program.clone();
            with_suffix.push(".wasm");
            if Path::new(&with_suffix).exists() {
                return with_suffix;
            }
        }
        program.clone()
    }

    fn spawn_with(&mut self, default: Default3) -> io::Result<Child> {
        let program = self.program();
        let name = program.as_bytes();
        let mut args = vec![cstr(self.program.as_bytes())?];
        for arg in &self.args {
            args.push(cstr(arg.as_bytes())?);
        }
        let argv: Vec<*const u8> = args.iter().map(|a| a.as_ptr().cast()).collect();

        let mut env = self.environment();
        let cwd = match &self.cwd {
            Some(cwd) if cwd.is_absolute() => Some(cwd.clone()),
            Some(cwd) => {
                let base = std::env::var_os("PWD")
                    .map(PathBuf::from)
                    .or_else(|| std::env::current_dir().ok())
                    .unwrap_or_else(|| PathBuf::from("/"));
                Some(base.join(cwd))
            }
            None => None,
        };
        if let Some(cwd) = &cwd {
            env.insert("PWD".into(), cwd.clone().into_os_string());
        }
        let path = env
            .get(OsStr::new("PATH"))
            .cloned()
            .or_else(|| std::env::var_os("PATH"))
            .unwrap_or_default();
        let mut env_strings = Vec::with_capacity(env.len());
        for (k, v) in &env {
            let mut entry = k.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(v.as_bytes());
            env_strings.push(cstr(&entry)?);
        }
        let envp: Vec<*const u8> = env_strings.iter().map(|e| e.as_ptr().cast()).collect();

        let cwd_bytes = cwd.as_ref().map(|c| c.as_os_str().as_bytes().to_vec());
        let mut ops: Vec<[u8; FD_OP_SIZE]> = Vec::new();
        if let Some(cwd) = &cwd_bytes {
            ops.push(fd_op(FD_OP_CHDIR, 0, 0, cwd, 0));
        }
        // Child ends stay open here until the spawn has duplicated them.
        let mut child_ends: Vec<OwnedFd> = Vec::new();
        let mut parent_ends: [Option<File>; 3] = [None, None, None];
        let defaults = match default {
            Default3::Inherit => [How::Inherit, How::Inherit, How::Inherit],
            Default3::Capture => [How::Null, How::Piped, How::Piped],
        };
        let configured = [&self.stdin, &self.stdout, &self.stderr];
        for (fd, (set, default)) in configured.into_iter().zip(&defaults).enumerate() {
            let fd = fd as u32;
            match set.as_ref().map_or(default, |s| &s.0) {
                How::Inherit => {}
                How::Null => {
                    let rights = if fd == 0 { 0 } else { RIGHTS_FD_WRITE };
                    ops.push(fd_op(FD_OP_OPEN, fd, 0, b"/dev/null", rights));
                }
                How::Piped => {
                    let (r, w) = pipe()?;
                    let (child, parent) = if fd == 0 { (r, w) } else { (w, r) };
                    ops.push(fd_op(FD_OP_DUP2, fd, child.as_raw_fd() as u32, b"", 0));
                    parent_ends[fd as usize] = Some(File::from(parent));
                    child_ends.push(child);
                }
                How::Fd(owned) => {
                    ops.push(fd_op(FD_OP_DUP2, fd, owned.as_raw_fd() as u32, b"", 0));
                }
            }
        }
        // Belt and braces for programs that also link fd_fdflags_set (and
        // so lose the implicit close-on-exec): the pipes' own descriptors
        // stay out of the child.
        let pipe_fds = child_ends
            .iter()
            .map(AsRawFd::as_raw_fd)
            .chain(parent_ends.iter().flatten().map(AsRawFd::as_raw_fd));
        for fd in pipe_fds.filter(|fd| *fd > 2).collect::<Vec<_>>() {
            ops.push(fd_op(FD_OP_CLOSE, fd as u32, 0, b"", 0));
        }

        let mut pid = 0u32;
        let errno = unsafe {
            sys::proc_spawn3(
                name.as_ptr(),
                name.len() as u32,
                argv.as_ptr(),
                argv.len() as u32,
                envp.as_ptr(),
                envp.len() as u32,
                ops.as_ptr().cast(),
                ops.len() as u32,
                0,
                0,
                u32::from(!name.contains(&b'/')),
                path.as_bytes().as_ptr(),
                path.len() as u32,
                &mut pid,
            )
        };
        drop(child_ends);
        cvt(errno)?;
        let [stdin, stdout, stderr] = parent_ends;
        Ok(Child {
            pid,
            status: None,
            stdin: stdin.map(|file| ChildStdin { file }),
            stdout: stdout.map(|file| ChildStdout { file }),
            stderr: stderr.map(|file| ChildStderr { file }),
        })
    }
}

/// A running (or finished, not yet waited for) child process.
#[derive(Debug)]
pub struct Child {
    pid: u32,
    status: Option<ExitStatus>,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
}

fn join(pid: u32, flags: u32) -> io::Result<Option<ExitStatus>> {
    // OptionPid: tag, then the pid at 4. JoinStatus: tag (0 nothing,
    // 1 exit code at 2, 2 signal at 4).
    let mut option_pid = [0u8; 8];
    option_pid[0] = 1;
    option_pid[4..8].copy_from_slice(&pid.to_le_bytes());
    let mut status = [0u8; 8];
    cvt(unsafe { sys::proc_join(option_pid.as_mut_ptr(), flags, status.as_mut_ptr()) })?;
    match status[0] {
        0 if flags & JOIN_NON_BLOCKING != 0 => Ok(None),
        1 => Ok(Some(ExitStatus {
            code: i32::from(u16::from_le_bytes([status[2], status[3]])),
            signal: None,
        })),
        2 => Ok(Some(ExitStatus {
            code: 0,
            signal: Some(i32::from(status[4])),
        })),
        _ => Err(io::Error::other("unexpected WASIX process status")),
    }
}

impl Child {
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Sends SIGKILL. A child already waited for is left alone.
    pub fn kill(&mut self) -> io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        cvt(unsafe { sys::proc_signal(self.pid, SIGKILL) })
    }

    /// Waits for the child to exit, closing its stdin first.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        drop(self.stdin.take());
        if let Some(status) = self.status {
            return Ok(status);
        }
        let status =
            join(self.pid, 0)?.ok_or_else(|| io::Error::other("the child did not exit"))?;
        self.status = Some(status);
        Ok(status)
    }

    /// The exit status if the child has exited, without waiting.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        self.status = join(self.pid, JOIN_NON_BLOCKING)?;
        Ok(self.status)
    }

    /// Closes stdin, collects stdout and stderr (both at once, so neither
    /// pipe fills up), then waits.
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        drop(self.stdin.take());
        let (stdout, stderr) = read2(self.stdout.take(), self.stderr.take())?;
        let status = self.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

fn read2(out: Option<ChildStdout>, err: Option<ChildStderr>) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    match (out, err) {
        (None, None) => {}
        (Some(mut o), None) => {
            o.read_to_end(&mut stdout)?;
        }
        (None, Some(mut e)) => {
            e.read_to_end(&mut stderr)?;
        }
        (Some(o), Some(e)) => {
            let mut ends = [(Some(o.file), &mut stdout), (Some(e.file), &mut stderr)];
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                const SUB: usize = 48;
                const EVENT: usize = 32;
                let mut subs = [0u8; SUB * 2];
                let mut n = 0usize;
                for (i, (file, _)) in ends.iter().enumerate() {
                    if let Some(file) = file {
                        let sub = &mut subs[n * SUB..(n + 1) * SUB];
                        sub[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                        sub[8] = 1; // fd_read
                        sub[16..20].copy_from_slice(&(file.as_raw_fd() as u32).to_le_bytes());
                        n += 1;
                    }
                }
                if n == 0 {
                    break;
                }
                let mut events = [0u8; EVENT * 2];
                let mut got = 0u32;
                cvt(unsafe {
                    sys::poll_oneoff(subs.as_ptr(), events.as_mut_ptr(), n as u32, &mut got)
                })?;
                for event in events.chunks_exact(EVENT).take(got as usize) {
                    let i = u64::from_le_bytes(event[0..8].try_into().unwrap()) as usize;
                    cvt(u16::from_le_bytes([event[8], event[9]]))?;
                    let (file, buf) = &mut ends[i];
                    let Some(f) = file else { continue };
                    match f.read(&mut chunk)? {
                        0 => *file = None,
                        k => buf.extend_from_slice(&chunk[..k]),
                    }
                }
            }
        }
    }
    Ok((stdout, stderr))
}
