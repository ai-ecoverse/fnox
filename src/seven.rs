use crate::error::{FnoxError, Result};
use fnox_core::sealed::{self, Wait};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn fnox_seven_signal(_signal: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(target_os = "wasi")]
mod sys {
    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        pub fn callback_signal(name: *const u8, len: u32);
    }

    #[link(wasm_import_module = "slicc")]
    unsafe extern "C" {
        pub fn sigaction_set(signal: u32, disposition: u32, flags: u32) -> u16;
    }
}

pub fn catch_interrupts() {
    #[cfg(target_os = "wasi")]
    unsafe {
        let name = b"fnox_seven_signal";
        sys::callback_signal(name.as_ptr(), name.len() as u32);
        sys::sigaction_set(2, 2, 0);
        sys::sigaction_set(15, 2, 0);
    }
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub fn request_value(name: &str) -> Result<String> {
    catch_interrupts();
    let request = sealed::request_value(name, Some(&format!("Value for {name}")))?;
    if request.state == "done" {
        return request
            .placeholder
            .ok_or_else(|| FnoxError::Seven("seven: request done without a placeholder".into()));
    }
    let id = request
        .id
        .ok_or_else(|| FnoxError::Seven("seven: request answered without an id".into()))?;
    eprintln!("Enter the value for {name} in seven's vault dialog (Ctrl-C cancels).");
    match sealed::wait_for(
        &id,
        Duration::from_secs(1),
        Duration::from_secs(300),
        &interrupted,
    )? {
        Wait::Done(done) => done
            .placeholder
            .ok_or_else(|| FnoxError::Seven("seven: request done without a placeholder".into())),
        Wait::Cancelled => {
            eprintln!("Cancelled.");
            std::process::exit(130);
        }
        Wait::Ended(ended) => Err(FnoxError::Seven(format!(
            "seven: the request for {name} ended: {}",
            ended.state
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_value_returns_the_placeholder_when_done() {
        let (_g, mock) = fnox_core::sealed::testing::install();
        mock.reply(serde_json::json!({ "v": 1, "state": "pending", "id": "rq1" }));
        mock.reply(
            serde_json::json!({ "v": 1, "state": "done", "placeholder": "ph", "record": "inert" }),
        );
        assert_eq!(request_value("TOKEN").unwrap(), "ph");
        let first = mock.requests.lock().unwrap()[0].clone();
        assert_eq!(first["kind"], serde_json::json!("value"));
        assert_eq!(first["name"], serde_json::json!("TOKEN"));
        assert_eq!(mock.ops(), vec!["request", "status"]);
        fnox_core::sealed::set_transport(None);
    }

    #[test]
    fn request_value_reports_a_closed_dialog() {
        let (_g, mock) = fnox_core::sealed::testing::install();
        mock.reply(serde_json::json!({ "v": 1, "state": "pending", "id": "rq2" }));
        mock.reply(serde_json::json!({ "v": 1, "state": "cancelled" }));
        let err = request_value("TOKEN").unwrap_err().to_string();
        assert_eq!(err, "seven: the request for TOKEN ended: cancelled");
        fnox_core::sealed::set_transport(None);
    }
}
