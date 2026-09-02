use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientRequest {
    Open {
        session: Option<String>,
        persistent: bool,
    },
    Run {
        command: String,
    },
    DeleteSession {
        session: String,
    },
    Ping,
    Disconnect,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerReply {
    Hello { server_signature: String },
    Opened { session: String },
    Deleted { session: String },
    Pong,
    Output { data: String, status: i32 },
    Error { message: String },
}
