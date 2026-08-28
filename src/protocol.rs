use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientRequest {
    Open { session: Option<String> },
    Run { command: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerReply {
    Hello { server_signature: String },
    Opened { session: String },
    Output { data: String, status: i32 },
    Error { message: String },
}
