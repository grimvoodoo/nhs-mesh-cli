use chrono::Utc;
use crossterm::{
    self,
    event::{self, Event, KeyCode},
    terminal::{
        self, disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    },
    ExecutableCommand,
};
use hmac::{digest::typenum::Length, Hmac, Mac};
use log::{debug, error, info};
use ratatui::{prelude::*, widgets::*};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, Error, Response,
};
use serde_json::Value;
use sha2::Sha256;
use std::{
    collections::HashMap,
    env,
    io::{self, stdout},
};
use uuid::{self, Uuid};

const AUTH_SCHEMA_NAME: &str = "NHSMESH";
const SHARED_KEY: &str = "TestKey";

#[derive(Debug)]
pub enum MailboxError {
    ReqwestError(reqwest::Error),
    HeaderValueError(reqwest::header::InvalidHeaderValue),
    HeaderNameError(reqwest::header::InvalidHeaderName),
    ParseError(std::num::ParseIntError),
}

impl From<reqwest::Error> for MailboxError {
    fn from(error: reqwest::Error) -> Self {
        MailboxError::ReqwestError(error)
    }
}

impl From<reqwest::header::InvalidHeaderValue> for MailboxError {
    fn from(error: reqwest::header::InvalidHeaderValue) -> Self {
        MailboxError::HeaderValueError(error)
    }
}

impl From<reqwest::header::InvalidHeaderName> for MailboxError {
    fn from(error: reqwest::header::InvalidHeaderName) -> Self {
        MailboxError::HeaderNameError(error)
    }
}

pub struct Mailbox {
    url: String,
    id: String,
    password: String,
}

impl Mailbox {
    pub fn new(url: String, id: String, password: String) -> Self {
        Mailbox { url, id, password }
    }
}

// #[tokio::main]
// async fn main() -> io::Result<()> {
//     env::set_var("RUST_LOG", "info");
//     env_logger::init();
//     let sender_mailbox = Mailbox::new(
//         "https://localhost:8700".to_string(),
//         env::var("MESH_SENDER_MAILBOX_ID").unwrap_or("X26ABC1".to_string()),
//         env::var("SENDER_MESH_PASSWORD").unwrap_or("password".to_string()),
//     );
//     let reciever_mailbox = Mailbox::new(
//         "https://localhost:8700".to_string(),
//         env::var("MESH_RECEIVER_MAILBOX_ID").unwrap_or("X26ABC2".to_string()),
//         env::var("RECIEVER_MESH_PASSWORD").unwrap_or("password".to_string()),
//     );
//     let client = reqwest::Client::builder()
//         .danger_accept_invalid_certs(true)
//         .build()
//         .expect("Failed to build client");

//     enable_raw_mode()?;
//     stdout().execute(EnterAlternateScreen)?;
//     let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

//     let mut should_quit = false;

//     while !should_quit {
//         terminal.draw(ui)?;
//         should_quit = handle_events().await?;
//     }

//     disable_raw_mode()?;
//     stdout().execute(LeaveAlternateScreen)?;
//     Ok(())
// }

// async fn handle_events() -> io::Result<bool> {
//     if event::poll(std::time::Duration::from_millis(50))? {
//         if let Event::Key(key) = event::read()? {
//             if key.kind == event::KeyEventKind::Press && key.code == KeyCode::Char('q') {
//                 return Ok(true);
//             }
//         }
//     }
//     Ok(false)
// }

// fn ui(frame: &mut Frame) {
//     let main_layout = Layout::new(
//         Direction::Vertical,
//         [
//             Constraint::Length(1),
//             Constraint::Min(0),
//             Constraint::Length(1),
//         ],
//     )
//     .split(frame.size());
//     frame.render_widget(
//         Block::new().borders(Borders::TOP).title("Title Bar"),
//         main_layout[0],
//     );
//     frame.render_widget(
//         Block::new().borders(Borders::TOP).title("Status Bar"),
//         main_layout[2],
//     );

//     let inner_layout = Layout::new(
//         Direction::Horizontal,
//         [Constraint::Percentage(50), Constraint::Percentage(50)],
//     )
//     .split(main_layout[1]);
//     frame.render_widget(
//         Block::default().borders(Borders::ALL).title("Left"),
//         inner_layout[0],
//     );
//     frame.render_widget(
//         Block::default().borders(Borders::ALL).title("Right"),
//         inner_layout[1],
//     );
// }

// fn ui(frame: &mut Frame) {
//     frame.render_widget(
//         Paragraph::new("Welcome to the NHS MESH Mailbox Interface. Please make a selection from the options below")
//             .block(Block::default().title("Greetings").borders(Borders::ALL)),
//         frame.size(),
//     )
// }

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let sender_mailbox = Mailbox::new(
        "https://localhost:8700".to_string(),
        env::var("MESH_SENDER_MAILBOX_ID").unwrap_or("X26ABC1".to_string()),
        env::var("SENDER_MESH_PASSWORD").unwrap_or("password".to_string()),
    );
    let reciever_mailbox = Mailbox::new(
        "https://localhost:8700".to_string(),
        env::var("MESH_RECEIVER_MAILBOX_ID").unwrap_or("X26ABC2".to_string()),
        env::var("RECIEVER_MESH_PASSWORD").unwrap_or("password".to_string()),
    );
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to build client");
    info!("\n\n Performing healthcheck on mesh url");
    match health_check(&client, &sender_mailbox).await {
        Ok(json) => info!("Sender mailbox healthy: {:?}", json["status"]),
        Err(e) => error!("Error: {:?}", e),
    }
    match health_check(&client, &reciever_mailbox).await {
        Ok(json) => info!("Reciever mailbox healthy: {:?}", json["status"]),
        Err(e) => error!("Error: {:?}", e),
    }
    info!("\n\n Performing handshake on mailboxes");
    match handshake(&client, &sender_mailbox).await {
        Ok(json) => info!("Success {:?}", json),
        Err(e) => error!("Failure: {:?}", e),
    }
    match handshake(&client, &reciever_mailbox).await {
        Ok(json) => info!("Success {:?}", json),
        Err(e) => error!("Failure: {:?}", e),
    }
    info!("\n\n Getting message count on mailboxes");
    match get_message_count(&client, &sender_mailbox).await {
        Ok(json) => info!("Success {:?}", json),
        Err(e) => error!("Failure: {:?}", e),
    }
    match get_message_count(&client, &reciever_mailbox).await {
        Ok(json) => info!("Success {:?}", json),
        Err(e) => error!("Failure: {:?}", e),
    }
}

async fn generate_token(mailbox: &Mailbox) -> String {
    let nonce = Uuid::new_v4().to_string();
    let nonce_count = 0;

    let timestamp = Utc::now().format("%Y%m%d%H%M").to_string();
    let hmac_msg = format!(
        "{}:{}:{}:{}:{}",
        mailbox.id, nonce, nonce_count, mailbox.password, timestamp
    );

    debug!("{:?}", hmac_msg);

    let mut mac =
        Hmac::<Sha256>::new_from_slice(SHARED_KEY.as_bytes()).expect("can work with any size");
    mac.update(hmac_msg.as_bytes());

    let hash_code = hex::encode(mac.finalize().into_bytes());

    format!(
        "{} {}:{}:{}:{}:{}",
        AUTH_SCHEMA_NAME, mailbox.id, nonce, nonce_count, timestamp, hash_code
    )
}

async fn generate_headers(mailbox: &Mailbox) -> Result<HashMap<String, String>, MailboxError> {
    let token = generate_token(mailbox).await;
    let mut headers = HashMap::new();
    headers.insert(
        "accept".to_string(),
        "application/vnd.mesh.v2+json".to_string(),
    );
    headers.insert("authorization".to_string(), token);
    headers.insert(
        "mex-clientversion".to_string(),
        "ApiDocs==0.0.1".to_string(),
    );
    headers.insert("mex-osarchitecture".to_string(), "x86_64".to_string());
    headers.insert("mex-osname".to_string(), "Linux".to_string());
    headers.insert(
        "mex-osversion".to_string(),
        "#44~18.04.2-Ubuntu".to_string(),
    );
    // headers.insert("Content-Type".to_string(), "application/json".to_string());
    debug!("{:?}", headers);
    Ok(headers)
}

async fn health_check(client: &Client, mailbox: &Mailbox) -> Result<Value, Error> {
    let response = client.get(format!("{}/health", mailbox.url)).send().await?;

    if response.status().is_success() {
        let json_body: Value = response.json().await?;
        Ok(json_body)
    } else {
        error!("Failed API call with status: {:?}", response.status());
        Err(response.error_for_status().unwrap_err())
    }
}

async fn handshake(client: &Client, mailbox: &Mailbox) -> Result<Response, MailboxError> {
    let url = format!("{}/messageexchange/{}", mailbox.url, mailbox.id);
    let headers = generate_headers(mailbox).await?;
    let mut header_map = HeaderMap::new();
    for (key, value) in headers {
        header_map.insert(
            key.parse::<reqwest::header::HeaderName>()?,
            HeaderValue::from_str(&value)?,
        );
    }

    let response = client.get(url).headers(header_map).send().await?;

    debug!("Raw response is: {:?}", response);

    if response.status().is_success() {
        Ok(response)
    } else {
        Err(MailboxError::ReqwestError(
            response.error_for_status().unwrap_err(),
        ))
    }
}

async fn get_message_count(client: &Client, mailbox: &Mailbox) -> Result<Response, MailboxError> {
    let url = format!("{}/messageexchange/{}/inbox", mailbox.url, mailbox.id);
    let headers = generate_headers(mailbox).await?;
    let mut header_map = HeaderMap::new();
    for (key, value) in headers {
        header_map.insert(
            key.parse::<reqwest::header::HeaderName>().unwrap(),
            HeaderValue::from_str(&value)?,
        );
    }

    let response = client.get(url).headers(header_map).send().await?;

    debug!("Raw response is: {:?}", response);

    if response.status().is_success() {
        Ok(response)
    } else {
        Err(MailboxError::ReqwestError(
            response.error_for_status().unwrap_err(),
        ))
    }
}
