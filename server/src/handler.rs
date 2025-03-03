use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply::json, ws::Message, Reply};

use crate::{ws, Client, Clients, Result};

#[derive(Deserialize, Debug)]
pub struct RegisterRequest {
    public: String,
}

#[derive(Deserialize, Debug)]
pub struct RegisterRequest2 {
    public: String,
    signature: String,
}

#[derive(Serialize, Debug)]
pub struct RegisterResponse {
    rand_number: String,
}

#[derive(Serialize, Debug)]
pub struct RegisterResponse2 {
    url: String,
}

#[derive(Deserialize, Debug)]
pub struct Event {
    message: String,
}

pub async fn publish_handler(body: Event, clients: Clients) -> Result<impl Reply> {
    clients
        .read()
        .await
        .iter()
        .for_each(|(_, client)| {
            if let Some(sender) = &client.sender {
                let _ = sender.send(Ok(Message::text(body.message.clone())));
            }
        });

    Ok(StatusCode::OK)
}

pub async fn register_handler(body: RegisterRequest, clients: Clients, client_addr: Option<SocketAddr>) -> Result<impl Reply> {
    println!("client address: {:?}", client_addr);
    let pk = body.public;
    let rand_number = crypto::big_rand();
    register_client(pk.clone(), rand_number.clone(), clients).await;
    Ok(json(&RegisterResponse {
        rand_number,
    }))
}

async fn register_client(public: String, rand_number: String, clients: Clients) {
    clients.write().await.insert(
        public,
        Client {
            rand_number,
            sender: None,
        },
    );
}

pub async fn register_handler2(body: RegisterRequest2, clients: Clients, socket_addr: SocketAddr) -> Result<impl Reply> {
    let signature = body.signature;
    let public = &body.public;
    let rand_number = clients.read().await.get(public).cloned().unwrap().rand_number;
    if crypto::verify(&signature, public, &rand_number) {
        match socket_addr {
            SocketAddr::V4(addr) => Ok(json(&RegisterResponse2 {
                url: format!("wss://{}:{}/ws/{}", addr.ip(), addr.port(), &public),
            })),
            SocketAddr::V6(addr) => Ok(json(&RegisterResponse2 {
                url: format!("wss://[{}]:{}/ws/{}", addr.ip(), addr.port(), &public)
            }))
        }
    }
    else {
        Err(warp::reject())
    }
}

pub async fn unregister_handler(public: String, clients: Clients) -> Result<impl Reply> {
    clients.write().await.remove(&public);
    Ok(StatusCode::OK)
}

pub async fn ws_handler(ws: warp::ws::Ws, public: String, clients: Clients, db_url: String) -> Result<impl Reply> {
    let client = clients.read().await.get(&public).cloned();
    match client {
        Some(c) => Ok(ws.on_upgrade(move |socket| ws::client_connection(socket, public, clients, c, db_url))),
        None => Err(warp::reject::not_found()),
    }
}

pub async fn health_handler() -> Result<impl Reply> {
    Ok(StatusCode::OK)
}
