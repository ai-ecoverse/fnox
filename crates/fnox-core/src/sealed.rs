use crate::error::{FnoxError, Result};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, RwLock};

pub const DEVICE: &str = "/dev/sealed";
pub const MAX_REQUEST: usize = 64 * 1024;
pub const MISSING: &str = "not running in seven: /dev/sealed is missing";
pub const REFUSED_IN_SEVEN: &str =
    "not available in seven: the value would be in a program (use a header rule)";
pub const AGE_UNSUPPORTED: &str = "age secrets aren't supported in seven yet (slicc-vault#2)";

pub trait Transport: Send + Sync {
    fn call(&self, request: &[u8]) -> io::Result<Vec<u8>>;
}

pub struct Device;

impl Transport for Device {
    fn call(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(DEVICE))?;
        exchange(&mut file, request)
    }
}

pub fn exchange<F: Read + Write>(file: &mut F, request: &[u8]) -> io::Result<Vec<u8>> {
    loop {
        match file.write(request) {
            Ok(n) if n == request.len() => break,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short write to /dev/sealed",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let mut reply = Vec::new();
    file.read_to_end(&mut reply)?;
    Ok(reply)
}

static TRANSPORT: RwLock<Option<Arc<dyn Transport>>> = RwLock::new(None);

#[doc(hidden)]
pub fn set_transport(transport: Option<Arc<dyn Transport>>) {
    *TRANSPORT.write().unwrap_or_else(|e| e.into_inner()) = transport;
}

fn transport() -> Arc<dyn Transport> {
    TRANSPORT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| Arc::new(Device))
}

fn errno_name(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(code) => format!("{} ({error})", errno_label(code)),
        None => error.to_string(),
    }
}

fn errno_label(code: i32) -> &'static str {
    match code {
        c if c == libc_errno::EMSGSIZE => "EMSGSIZE",
        c if c == libc_errno::EINVAL => "EINVAL",
        c if c == libc_errno::EACCES => "EACCES",
        _ => "errno",
    }
}

#[cfg(target_os = "wasi")]
mod libc_errno {
    pub const EACCES: i32 = 2;
    pub const EINVAL: i32 = 28;
    pub const EMSGSIZE: i32 = 35;
}

#[cfg(not(target_os = "wasi"))]
mod libc_errno {
    pub const EACCES: i32 = 13;
    pub const EINVAL: i32 = 22;
    #[cfg(target_os = "linux")]
    pub const EMSGSIZE: i32 = 90;
    #[cfg(not(target_os = "linux"))]
    pub const EMSGSIZE: i32 = 40;
}

pub fn call(op: &str, fields: Value) -> Result<Value> {
    let mut request = Map::new();
    request.insert("v".into(), json!(1));
    request.insert("op".into(), json!(op));
    if let Value::Object(fields) = fields {
        request.extend(fields);
    }
    let bytes = serde_json::to_vec(&Value::Object(request))
        .map_err(|e| FnoxError::Seven(format!("seven: cannot encode {op}: {e}")))?;
    if bytes.len() > MAX_REQUEST {
        return Err(FnoxError::Seven(format!(
            "seven: {op} request is larger than 64 KiB"
        )));
    }
    let reply = match transport().call(&bytes) {
        Ok(reply) => reply,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(FnoxError::Seven(MISSING.to_string()));
        }
        Err(e) => {
            return Err(FnoxError::Seven(format!(
                "seven: /dev/sealed refused {op}: {}",
                errno_name(&e)
            )));
        }
    };
    if reply.is_empty() {
        return Err(FnoxError::Seven(format!(
            "seven: /dev/sealed gave no reply to {op}"
        )));
    }
    let reply: Value = serde_json::from_slice(&reply)
        .map_err(|e| FnoxError::Seven(format!("seven: unreadable reply to {op}: {e}")))?;
    if let Some(error) = reply.get("error") {
        let code = error.get("code").and_then(Value::as_str).unwrap_or("EIO");
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("no message");
        return Err(FnoxError::Seven(format!("seven: {op}: {code}: {message}")));
    }
    if reply.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(FnoxError::Seven(format!(
            "seven: reply to {op} has an unknown protocol version"
        )));
    }
    Ok(reply)
}

fn parse<T: for<'de> Deserialize<'de>>(op: &str, reply: Value) -> Result<T> {
    serde_json::from_value(reply)
        .map_err(|e| FnoxError::Seven(format!("seven: unexpected reply to {op}: {e}")))
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub placeholder: String,
    pub state: String,
}

pub fn seal(name: &str, value: &str) -> Result<Record> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(FnoxError::Seven(
            "seven: a sealed value cannot contain CR, LF or NUL".to_string(),
        ));
    }
    parse(
        "seal",
        call("seal", json!({ "name": name, "value": value }))?,
    )
}

pub fn placeholder(name: &str) -> Result<Record> {
    parse("placeholder", call("placeholder", json!({ "name": name }))?)
}

pub fn list() -> Result<Value> {
    call("list", json!({}))
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub state: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default)]
    pub record: Option<String>,
}

pub fn request_value(name: &str, prompt: Option<&str>) -> Result<Request> {
    let mut fields = json!({ "kind": "value", "name": name });
    if let Some(prompt) = prompt {
        fields["prompt"] = json!(prompt.chars().take(200).collect::<String>());
    }
    parse("request", call("request", fields)?)
}

pub fn status(id: &str) -> Result<Request> {
    parse("status", call("status", json!({ "id": id }))?)
}

pub fn cancel(id: &str) -> Result<Request> {
    parse("cancel", call("cancel", json!({ "id": id }))?)
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Ticket {
    pub ticket: String,
    #[serde(rename = "expiresAt", default)]
    pub expires_at: Option<Value>,
    #[serde(default)]
    pub real: IndexMap<String, bool>,
}

pub fn materialize(names: &[String], path: &str, argv: &[String], cwd: &str) -> Result<Ticket> {
    parse(
        "materialize",
        call(
            "materialize",
            json!({ "names": names, "path": path, "argv": argv, "cwd": cwd }),
        )?,
    )
}

pub enum Wait {
    Done(Request),
    Ended(Request),
    Cancelled,
}

pub fn wait_for(
    id: &str,
    interval: std::time::Duration,
    timeout: std::time::Duration,
    interrupted: &dyn Fn() -> bool,
) -> Result<Wait> {
    let started = std::time::Instant::now();
    loop {
        if interrupted() {
            let _ = cancel(id);
            return Ok(Wait::Cancelled);
        }
        let current = status(id)?;
        match current.state.as_str() {
            "pending" => {}
            "done" => return Ok(Wait::Done(current)),
            _ => return Ok(Wait::Ended(current)),
        }
        if started.elapsed() >= timeout {
            let _ = cancel(id);
            return Ok(Wait::Ended(Request {
                state: "expired".to_string(),
                id: Some(id.to_string()),
                placeholder: None,
                record: None,
            }));
        }
        let step = std::time::Duration::from_millis(50);
        let mut slept = std::time::Duration::ZERO;
        while slept < interval {
            if interrupted() {
                break;
            }
            std::thread::sleep(step);
            slept += step;
        }
    }
}

#[doc(hidden)]
pub mod testing {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct Mock {
        pub requests: Mutex<Vec<Value>>,
        pub replies: Mutex<std::collections::VecDeque<io::Result<Vec<u8>>>>,
    }

    impl Mock {
        pub fn reply(&self, value: Value) {
            self.replies
                .lock()
                .unwrap()
                .push_back(Ok(serde_json::to_vec(&value).unwrap()));
        }
        pub fn fail(&self, error: io::Error) {
            self.replies.lock().unwrap().push_back(Err(error));
        }
        pub fn ops(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| r["op"].as_str().unwrap_or_default().to_string())
                .collect()
        }
    }

    impl Transport for Mock {
        fn call(&self, request: &[u8]) -> io::Result<Vec<u8>> {
            if request.len() > MAX_REQUEST {
                return Err(io::Error::from_raw_os_error(libc_errno::EMSGSIZE));
            }
            let parsed: Value = serde_json::from_slice(request)
                .map_err(|_| io::Error::from_raw_os_error(libc_errno::EINVAL))?;
            if parsed["v"] != json!(1) {
                return Err(io::Error::from_raw_os_error(libc_errno::EINVAL));
            }
            self.requests.lock().unwrap().push(parsed);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()))
        }
    }

    pub static LOCK: Mutex<()> = Mutex::new(());

    pub fn install() -> (std::sync::MutexGuard<'static, ()>, Arc<Mock>) {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mock = Arc::new(Mock::default());
        set_transport(Some(mock.clone()));
        (guard, mock)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::install;
    use super::*;

    #[test]
    fn seal_sends_one_versioned_request() {
        let (_g, mock) = install();
        mock.reply(json!({ "v": 1, "placeholder": "seven_ph_1", "state": "inert" }));
        let record = seal("API_TOKEN", "s3cret").unwrap();
        assert_eq!(record.placeholder, "seven_ph_1");
        assert_eq!(record.state, "inert");
        let sent = mock.requests.lock().unwrap()[0].clone();
        assert_eq!(
            sent,
            json!({ "v": 1, "op": "seal", "name": "API_TOKEN", "value": "s3cret" })
        );
        set_transport(None);
    }

    #[test]
    fn seal_refuses_line_breaks_without_calling_the_device() {
        let (_g, mock) = install();
        assert!(seal("A", "x\ny").is_err());
        assert!(mock.ops().is_empty());
        set_transport(None);
    }

    #[test]
    fn json_errors_carry_code_and_message() {
        let (_g, mock) = install();
        mock.reply(
            json!({ "v": 1, "error": { "code": "EEXIST", "message": "entered by the human" } }),
        );
        let err = seal("A", "x").unwrap_err().to_string();
        assert_eq!(err, "seven: seal: EEXIST: entered by the human");
        set_transport(None);
    }

    #[test]
    fn a_missing_device_is_not_running_in_seven() {
        let (_g, mock) = install();
        mock.fail(io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(placeholder("A").unwrap_err().to_string(), MISSING);
        set_transport(None);
    }

    #[test]
    fn framing_errnos_are_reported_by_name() {
        let (_g, mock) = install();
        mock.fail(io::Error::from_raw_os_error(libc_errno::EINVAL));
        let err = placeholder("A").unwrap_err().to_string();
        assert!(
            err.starts_with("seven: /dev/sealed refused placeholder: EINVAL"),
            "{err}"
        );
        set_transport(None);
    }

    #[test]
    fn oversized_requests_never_reach_the_device() {
        let (_g, mock) = install();
        let big = "x".repeat(MAX_REQUEST);
        let err = seal("A", &big).unwrap_err().to_string();
        assert!(err.contains("larger than 64 KiB"), "{err}");
        assert!(mock.ops().is_empty());
        set_transport(None);
    }

    #[test]
    fn an_empty_reply_is_an_error() {
        let (_g, _mock) = install();
        assert!(list().unwrap_err().to_string().contains("no reply"));
        set_transport(None);
    }

    #[test]
    fn replies_without_version_are_refused() {
        let (_g, mock) = install();
        mock.reply(json!({ "placeholder": "p", "state": "active" }));
        assert!(placeholder("A").is_err());
        set_transport(None);
    }

    #[test]
    fn materialize_sends_path_argv_and_cwd() {
        let (_g, mock) = install();
        mock.reply(
            json!({ "v": 1, "ticket": "t1", "expiresAt": 1, "real": { "A": true, "B": false } }),
        );
        let names = vec!["A".to_string(), "B".to_string()];
        let argv = vec!["/usr/bin/curl".to_string(), "-sS".to_string()];
        let ticket = materialize(&names, "/usr/bin/curl", &argv, "/home/demo").unwrap();
        assert_eq!(ticket.ticket, "t1");
        assert_eq!(ticket.real.get("A"), Some(&true));
        assert_eq!(ticket.real.get("B"), Some(&false));
        let sent = mock.requests.lock().unwrap()[0].clone();
        assert_eq!(sent["path"], json!("/usr/bin/curl"));
        assert_eq!(sent["argv"], json!(["/usr/bin/curl", "-sS"]));
        assert_eq!(sent["cwd"], json!("/home/demo"));
        assert_eq!(sent["names"], json!(["A", "B"]));
        set_transport(None);
    }

    #[test]
    fn wait_polls_until_done() {
        let (_g, mock) = install();
        mock.reply(json!({ "v": 1, "state": "pending" }));
        mock.reply(json!({ "v": 1, "state": "done", "placeholder": "p", "record": "inert" }));
        let never = || false;
        let out = wait_for(
            "r1",
            std::time::Duration::from_millis(1),
            std::time::Duration::from_secs(5),
            &never,
        )
        .unwrap();
        match out {
            Wait::Done(r) => assert_eq!(r.placeholder.as_deref(), Some("p")),
            _ => panic!("not done"),
        }
        assert_eq!(mock.ops(), vec!["status", "status"]);
        set_transport(None);
    }

    #[test]
    fn interruption_sends_cancel() {
        let (_g, mock) = install();
        mock.reply(json!({ "v": 1, "state": "pending" }));
        mock.reply(json!({ "v": 1, "state": "cancelled" }));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let interrupted = || calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 2;
        let out = wait_for(
            "r1",
            std::time::Duration::from_millis(500),
            std::time::Duration::from_secs(5),
            &interrupted,
        )
        .unwrap();
        assert!(matches!(out, Wait::Cancelled));
        assert_eq!(mock.ops(), vec!["status", "cancel"]);
        let sent = mock.requests.lock().unwrap()[1].clone();
        assert_eq!(sent, json!({ "v": 1, "op": "cancel", "id": "r1" }));
        set_transport(None);
    }

    #[test]
    fn a_timeout_cancels_and_reports_expired() {
        let (_g, mock) = install();
        mock.reply(json!({ "v": 1, "state": "pending" }));
        mock.reply(json!({ "v": 1, "state": "cancelled" }));
        let never = || false;
        let out = wait_for(
            "r1",
            std::time::Duration::from_millis(1),
            std::time::Duration::ZERO,
            &never,
        )
        .unwrap();
        match out {
            Wait::Ended(r) => assert_eq!(r.state, "expired"),
            _ => panic!("expected expiry"),
        }
        assert_eq!(mock.ops(), vec!["status", "cancel"]);
        set_transport(None);
    }

    struct Flaky {
        writes: Vec<io::Result<usize>>,
        reads: Vec<io::Result<Vec<u8>>>,
        written: Vec<u8>,
    }

    impl Write for Flaky {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            match self.writes.remove(0) {
                Ok(_) => {
                    self.written.extend_from_slice(buf);
                    Ok(buf.len())
                }
                Err(e) => Err(e),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for Flaky {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.reads.is_empty() {
                return Ok(0);
            }
            match self.reads.remove(0) {
                Ok(mut bytes) => {
                    let n = bytes.len().min(out.len());
                    out[..n].copy_from_slice(&bytes[..n]);
                    if n < bytes.len() {
                        self.reads.insert(0, Ok(bytes.split_off(n)));
                    }
                    Ok(n)
                }
                Err(e) => Err(e),
            }
        }
    }

    #[test]
    fn exchange_retries_interrupted_writes_and_reads() {
        let mut dev = Flaky {
            writes: vec![Err(io::Error::from(io::ErrorKind::Interrupted)), Ok(0)],
            reads: vec![
                Err(io::Error::from(io::ErrorKind::Interrupted)),
                Ok(b"{\"v\":1,".to_vec()),
                Err(io::Error::from(io::ErrorKind::Interrupted)),
                Ok(b"\"state\":\"inert\"}".to_vec()),
            ],
            written: Vec::new(),
        };
        let reply = exchange(&mut dev, b"{\"v\":1}").unwrap();
        assert_eq!(reply, b"{\"v\":1,\"state\":\"inert\"}");
        assert_eq!(dev.written, b"{\"v\":1}");
    }

    struct ShortWrite;

    impl Write for ShortWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len() / 2)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for ShortWrite {
        fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn exchange_refuses_a_short_write() {
        let err = exchange(&mut ShortWrite, b"{\"v\":1}").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
    }

    struct SlowMachineAnswer {
        flag: Arc<std::sync::atomic::AtomicBool>,
        replies: std::sync::Mutex<Vec<Value>>,
        ops: std::sync::Mutex<Vec<String>>,
    }

    impl Transport for SlowMachineAnswer {
        fn call(&self, request: &[u8]) -> io::Result<Vec<u8>> {
            let parsed: Value = serde_json::from_slice(request).unwrap();
            let op = parsed["op"].as_str().unwrap().to_string();
            if op == "status" {
                std::thread::sleep(std::time::Duration::from_millis(100));
                self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            self.ops.lock().unwrap().push(op);
            Ok(serde_json::to_vec(&self.replies.lock().unwrap().remove(0)).unwrap())
        }
    }

    #[test]
    fn interrupt_during_a_machine_wait_cancels_after_the_reply() {
        let _g = super::testing::LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let slow = Arc::new(SlowMachineAnswer {
            flag: flag.clone(),
            replies: std::sync::Mutex::new(vec![
                json!({ "v": 1, "state": "pending" }),
                json!({ "v": 1, "state": "cancelled" }),
            ]),
            ops: std::sync::Mutex::new(Vec::new()),
        });
        set_transport(Some(slow.clone()));
        let interrupted = || flag.load(std::sync::atomic::Ordering::SeqCst);
        let out = wait_for(
            "r9",
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(300),
            &interrupted,
        )
        .unwrap();
        assert!(matches!(out, Wait::Cancelled));
        assert_eq!(*slow.ops.lock().unwrap(), vec!["status", "cancel"]);
        set_transport(None);
    }
}
