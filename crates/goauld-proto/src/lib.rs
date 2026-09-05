//! Wire protocol shared by host and agent.
//!
//! Framing (identical both directions):
//! ```text
//! [u32 LE: total_len] [u8: msg_type] [payload: total_len - 1 bytes]
//! ```
//!
//! For [`Message::Send`], the body is:
//! ```text
//! [u32 LE: json_len] [json bytes] [u32 LE: data_len] [optional raw data]
//! ```
//! where `data_len` may be 0 (and then no data bytes follow).

use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Cargo package version (`workspace.package.version`).
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Short git rev baked in at compile time (or `"unknown"`).
pub const GIT_REV: &str = env!("GOAULD_GIT_REV");
/// UTC build timestamp baked in at compile time (or `"unknown"`).
pub const BUILD_TIME: &str = env!("GOAULD_BUILD_TIME");

/// Human-readable build identity, e.g. `0.1.1 (git:a1b2c3d built:2026-09-04T09:50:00Z)`.
pub fn version_info() -> String {
    format!("{PKG_VERSION} (git:{GIT_REV} built:{BUILD_TIME})")
}

/// Message type byte on the wire.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Hello = 0x01,
    ScriptLoad = 0x02,
    ScriptUnload = 0x03,
    RpcCall = 0x04,
    RpcReply = 0x05,
    Send = 0x06,
    Log = 0x07,
    /// Host → script message (Frida `script.post` / JS `recv`).
    Post = 0x08,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::ScriptLoad),
            0x03 => Some(Self::ScriptUnload),
            0x04 => Some(Self::RpcCall),
            0x05 => Some(Self::RpcReply),
            0x06 => Some(Self::Send),
            0x07 => Some(Self::Log),
            0x08 => Some(Self::Post),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("buffer too short: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("unknown message type: 0x{0:02x}")]
    UnknownType(u8),
    #[error("invalid frame length: {0}")]
    BadLength(u32),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("send payload malformed")]
    MalformedSend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub pid: u32,
    pub package: String,
    pub sdk_int: u32,
    pub abi: String,
    /// Agent build identity (`goauld_proto::version_info()`). Empty on older agents.
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptLoad {
    pub script_id: u32,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptUnload {
    pub script_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcCall {
    pub script_id: u32,
    pub call_id: u32,
    pub fn_name: String,
    pub args_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReply {
    pub call_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendPayload {
    pub script_id: u32,
    pub payload_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogMsg {
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    ScriptLoad(ScriptLoad),
    ScriptUnload(ScriptUnload),
    RpcCall(RpcCall),
    RpcReply(RpcReply),
    /// Mirrors Frida `send(payload, data)` — optional raw byte channel after JSON.
    Send {
        script_id: u32,
        payload_json: String,
        data: Option<Vec<u8>>,
    },
    /// Host → script (Frida `script.post` → JS `recv`).
    Post {
        script_id: u32,
        payload_json: String,
        data: Option<Vec<u8>>,
    },
    Log(LogMsg),
}

impl Message {
    pub fn msg_type(&self) -> MsgType {
        match self {
            Self::Hello(_) => MsgType::Hello,
            Self::ScriptLoad(_) => MsgType::ScriptLoad,
            Self::ScriptUnload(_) => MsgType::ScriptUnload,
            Self::RpcCall(_) => MsgType::RpcCall,
            Self::RpcReply(_) => MsgType::RpcReply,
            Self::Send { .. } => MsgType::Send,
            Self::Post { .. } => MsgType::Post,
            Self::Log(_) => MsgType::Log,
        }
    }

    /// Encode a complete framed message (length prefix + type + payload).
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let payload = self.encode_payload()?;
        let total_len = 1u32
            .checked_add(payload.len() as u32)
            .ok_or(ProtoError::BadLength(u32::MAX))?;
        let mut out = Vec::with_capacity(4 + total_len as usize);
        let mut len_buf = [0u8; 4];
        LittleEndian::write_u32(&mut len_buf, total_len);
        out.extend_from_slice(&len_buf);
        out.push(self.msg_type() as u8);
        out.extend_from_slice(&payload);
        Ok(out)
    }

    fn encode_payload(&self) -> Result<Vec<u8>, ProtoError> {
        match self {
            Self::Hello(v) => Ok(serde_json::to_vec(v)?),
            Self::ScriptLoad(v) => Ok(serde_json::to_vec(v)?),
            Self::ScriptUnload(v) => Ok(serde_json::to_vec(v)?),
            Self::RpcCall(v) => Ok(serde_json::to_vec(v)?),
            Self::RpcReply(v) => Ok(serde_json::to_vec(v)?),
            Self::Log(v) => Ok(serde_json::to_vec(v)?),
            Self::Send {
                script_id,
                payload_json,
                data,
            }
            | Self::Post {
                script_id,
                payload_json,
                data,
            } => {
                let json = serde_json::to_vec(&SendPayload {
                    script_id: *script_id,
                    payload_json: payload_json.clone(),
                })?;
                let data_bytes = data.as_deref().unwrap_or(&[]);
                let mut body = Vec::with_capacity(8 + json.len() + data_bytes.len());
                let mut n = [0u8; 4];
                LittleEndian::write_u32(&mut n, json.len() as u32);
                body.extend_from_slice(&n);
                body.extend_from_slice(&json);
                LittleEndian::write_u32(&mut n, data_bytes.len() as u32);
                body.extend_from_slice(&n);
                body.extend_from_slice(data_bytes);
                Ok(body)
            }
        }
    }

    /// Decode one framed message from `buf`.
    ///
    /// `buf` must start at the length prefix. Returns the message; caller is responsible
    /// for advancing by `4 + total_len` in a stream.
    pub fn decode(buf: &[u8]) -> Result<Message, ProtoError> {
        if buf.len() < 5 {
            return Err(ProtoError::Truncated {
                need: 5,
                have: buf.len(),
            });
        }
        let total_len = LittleEndian::read_u32(&buf[0..4]);
        if total_len < 1 {
            return Err(ProtoError::BadLength(total_len));
        }
        let frame_end = 4 + total_len as usize;
        if buf.len() < frame_end {
            return Err(ProtoError::Truncated {
                need: frame_end,
                have: buf.len(),
            });
        }
        let msg_type = MsgType::from_u8(buf[4]).ok_or(ProtoError::UnknownType(buf[4]))?;
        let payload = &buf[5..frame_end];
        Self::decode_payload(msg_type, payload)
    }

    /// How many bytes a complete frame starting at `buf` needs, if the length prefix is present.
    pub fn frame_len(buf: &[u8]) -> Result<usize, ProtoError> {
        if buf.len() < 4 {
            return Err(ProtoError::Truncated {
                need: 4,
                have: buf.len(),
            });
        }
        let total_len = LittleEndian::read_u32(&buf[0..4]);
        if total_len < 1 {
            return Err(ProtoError::BadLength(total_len));
        }
        Ok(4 + total_len as usize)
    }

    fn decode_payload(msg_type: MsgType, payload: &[u8]) -> Result<Message, ProtoError> {
        match msg_type {
            MsgType::Hello => Ok(Message::Hello(serde_json::from_slice(payload)?)),
            MsgType::ScriptLoad => Ok(Message::ScriptLoad(serde_json::from_slice(payload)?)),
            MsgType::ScriptUnload => Ok(Message::ScriptUnload(serde_json::from_slice(payload)?)),
            MsgType::RpcCall => Ok(Message::RpcCall(serde_json::from_slice(payload)?)),
            MsgType::RpcReply => Ok(Message::RpcReply(serde_json::from_slice(payload)?)),
            MsgType::Log => Ok(Message::Log(serde_json::from_slice(payload)?)),
            MsgType::Send | MsgType::Post => {
                if payload.len() < 8 {
                    return Err(ProtoError::MalformedSend);
                }
                let json_len = LittleEndian::read_u32(&payload[0..4]) as usize;
                if payload.len() < 4 + json_len + 4 {
                    return Err(ProtoError::MalformedSend);
                }
                let json_bytes = &payload[4..4 + json_len];
                let data_len =
                    LittleEndian::read_u32(&payload[4 + json_len..4 + json_len + 4]) as usize;
                let data_start = 4 + json_len + 4;
                if payload.len() < data_start + data_len {
                    return Err(ProtoError::MalformedSend);
                }
                let meta: SendPayload = serde_json::from_slice(json_bytes)?;
                let data = if data_len == 0 {
                    None
                } else {
                    Some(payload[data_start..data_start + data_len].to_vec())
                };
                if msg_type == MsgType::Post {
                    Ok(Message::Post {
                        script_id: meta.script_id,
                        payload_json: meta.payload_json,
                        data,
                    })
                } else {
                    Ok(Message::Send {
                        script_id: meta.script_id,
                        payload_json: meta.payload_json,
                        data,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: Message) {
        let encoded = msg.encode().expect("encode");
        let decoded = Message::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
        assert_eq!(Message::frame_len(&encoded).unwrap(), encoded.len());
    }

    #[test]
    fn round_trip_hello() {
        round_trip(Message::Hello(Hello {
            pid: 4242,
            package: "com.example.target".into(),
            sdk_int: 34,
            abi: "arm64-v8a".into(),
            version: "0.1.1 (git:deadbeef built:test)".into(),
        }));
    }

    #[test]
    fn hello_without_version_deserializes() {
        let json = r#"{"pid":1,"package":"p","sdk_int":34,"abi":"arm64-v8a"}"#;
        let h: Hello = serde_json::from_str(json).unwrap();
        assert!(h.version.is_empty());
    }

    #[test]
    fn version_info_nonempty() {
        assert!(!super::version_info().is_empty());
        assert!(super::version_info().contains(super::PKG_VERSION));
    }

    #[test]
    fn round_trip_script_load() {
        round_trip(Message::ScriptLoad(ScriptLoad {
            script_id: 1,
            source: "send('hi');".into(),
        }));
    }

    #[test]
    fn round_trip_script_unload() {
        round_trip(Message::ScriptUnload(ScriptUnload { script_id: 7 }));
    }

    #[test]
    fn round_trip_rpc_call() {
        round_trip(Message::RpcCall(RpcCall {
            script_id: 1,
            call_id: 99,
            fn_name: "ping".into(),
            args_json: "[1,2,3]".into(),
        }));
    }

    #[test]
    fn round_trip_rpc_reply_ok() {
        round_trip(Message::RpcReply(RpcReply {
            call_id: 99,
            result_json: Some("\"pong\"".into()),
            error: None,
        }));
    }

    #[test]
    fn round_trip_rpc_reply_err() {
        round_trip(Message::RpcReply(RpcReply {
            call_id: 3,
            result_json: None,
            error: Some("boom".into()),
        }));
    }

    #[test]
    fn round_trip_send_no_data() {
        round_trip(Message::Send {
            script_id: 1,
            payload_json: "\"hi\"".into(),
            data: None,
        });
    }

    #[test]
    fn round_trip_send_with_data() {
        round_trip(Message::Send {
            script_id: 2,
            payload_json: "{\"type\":\"bytes\"}".into(),
            data: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        });
    }

    #[test]
    fn round_trip_post_with_data() {
        round_trip(Message::Post {
            script_id: 1,
            payload_json: "{\"type\":\"pong\",\"n\":3}".into(),
            data: Some(vec![1, 2, 3]),
        });
    }

    #[test]
    fn round_trip_log() {
        round_trip(Message::Log(LogMsg {
            level: "info".into(),
            message: "agent up".into(),
        }));
    }

    #[test]
    fn unknown_type_errors() {
        let mut buf = vec![0u8; 5];
        LittleEndian::write_u32(&mut buf[0..4], 1);
        buf[4] = 0xFF;
        assert!(matches!(
            Message::decode(&buf),
            Err(ProtoError::UnknownType(0xFF))
        ));
    }

    #[test]
    fn truncated_errors() {
        assert!(matches!(
            Message::decode(&[0, 0, 0]),
            Err(ProtoError::Truncated { .. })
        ));
        let msg = Message::Log(LogMsg {
            level: "w".into(),
            message: "x".into(),
        });
        let enc = msg.encode().unwrap();
        assert!(matches!(
            Message::decode(&enc[..enc.len() - 1]),
            Err(ProtoError::Truncated { .. })
        ));
    }
}
