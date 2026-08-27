use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientRequest {
    Open { session: Option<String> },
    Run { command: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerReply {
    Opened { session: String },
    Output { data: String, status: i32 },
    Error { message: String },
}
