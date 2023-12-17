use chrono::Utc;
use env_logger::fmt::Timestamp;
use hmac::{Hmac, Mac};
use log::{debug, error, info};
use rand::{random, rngs::OsRng, Rng, RngCore};
use reqwest::{
    header::{HeaderMap, HeaderValue, DATE},
    Client, Error,
};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    collections::HashMap,
    env,
    fmt::format,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Mailbox {
    url: String,
    id: String,
    password: String,
    shared_key: String,
}

impl Mailbox {
    pub fn new(url: String, id: String, password: String, shared_key: String) -> Self {
        Mailbox {
            url,
            id,
            password,
            shared_key,
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    env_logger::init();
    let mailbox = Mailbox::new(
        "https://kube-controller-1:30443".to_string(),
        "X26ABC1".to_string(),
        "password".to_string(),
        "TestKey".to_string(),
    );
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to build client");
    info!("Performing healthcheck on mesh url");
    match health_check(&client, &mailbox).await {
        Ok(json) => info!("Success: {:?}", json),
        Err(e) => error!("Error: {:?}", e),
    }
    match handshake(&client, &mailbox).await {
        Ok(json) => info!("Success {:?}", json),
        Err(e) => error!("Failure: {:?}", e),
    }
}

async fn create_hmac_sha256_hex(
    mailbox: &Mailbox,
    message: String,
) -> Result<String, Box<dyn std::error::Error>> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(mailbox.shared_key.as_bytes())?;
    mac.update(&message.into_bytes());

    let result = mac.finalize();
    let result_bytes = result.into_bytes();
    Ok(hex::encode(result_bytes))
}

async fn generate_token(mailbox: &Mailbox) -> Result<String, Box<dyn std::error::Error>> {
    let since_the_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time is running backwards!");
    let random_number = rand::thread_rng().gen_range(0..1000);
    let nonce = format!("{}{}", since_the_epoch.as_secs(), random_number);
    let timestamp_formatted = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let timestamp = timestamp_formatted.get(0..12).unwrap();
    let auth_schema_name = "NHSMESH ".to_string();
    let hmac_msg = format!("{}{}{}{}", &mailbox.id, nonce, mailbox.password, &timestamp);
    let mut hmac: String = Default::default();
    match create_hmac_sha256_hex(&mailbox, hmac_msg).await {
        Ok(hmac_hex) => {
            hmac = hmac_hex;
        }
        Err(e) => error!("Failure: {:?}", e),
    }
    let token = format!(
        "{}{}{}{}{}",
        auth_schema_name, &mailbox.id, nonce, timestamp, hmac
    );
    Ok(token)
}

async fn generate_headers(
    mailbox: &Mailbox,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let token = generate_token(mailbox).await?;
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
    headers.insert("Content-Type".to_string(), "application/json".to_string());

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

async fn handshake(client: &Client, mailbox: &Mailbox) -> Result<Value, Error> {
    let url = format!("{}/messageexchange/X26ABC1", mailbox.url);
    let headers = generate_headers(mailbox).await.unwrap();
    let mut header_map = HeaderMap::new();
    for (key, value) in headers {
        header_map.insert(
            key.parse::<reqwest::header::HeaderName>().unwrap(),
            HeaderValue::from_str(&value).unwrap(),
        );
    }

    let response = client.get(url).headers(header_map).send().await?;

    if response.status().is_success() {
        let json_body = response.json().await?;
        Ok(json_body)
    } else {
        Err(response.error_for_status().unwrap_err())
    }
}
