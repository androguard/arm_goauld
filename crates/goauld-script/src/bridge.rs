//! Shared host bridge (outbound `send` / `log`) for QuickJS and Symbiote backends.

use goauld_proto::{LogMsg, Message};
use parking_lot::Mutex;
use std::sync::mpsc::Sender;
use std::sync::{Arc, OnceLock};

use crate::engine::ScriptId;

pub struct HostBridge {
    pub tx: Mutex<Option<Sender<Message>>>,
    pub current_script: Mutex<ScriptId>,
}

impl HostBridge {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tx: Mutex::new(None),
            current_script: Mutex::new(0),
        })
    }

    pub fn emit_send(&self, payload_json: String, data: Option<Vec<u8>>) {
        let script_id = *self.current_script.lock();
        if let Some(tx) = self.tx.lock().as_ref() {
            let _ = tx.send(Message::Send {
                script_id,
                payload_json,
                data,
            });
        }
    }

    pub fn emit_log(&self, level: &str, message: String) {
        if let Some(tx) = self.tx.lock().as_ref() {
            let _ = tx.send(Message::Log(LogMsg {
                level: level.to_string(),
                message,
            }));
        }
    }
}

static SHARED_BRIDGE: OnceLock<Arc<HostBridge>> = OnceLock::new();

/// Process-wide bridge so the JS worker and all `ScriptEngine` instances share `send` routing.
pub fn shared_bridge() -> Arc<HostBridge> {
    SHARED_BRIDGE.get_or_init(HostBridge::new).clone()
}
