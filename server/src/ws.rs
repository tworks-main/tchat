use std::str;
use futures_util::{FutureExt, StreamExt};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use warp::ws::{Message, WebSocket};
use warp::Error;
use sqlx::{SqlitePool, FromRow};

use crate::{Client, Clients};

#[derive(Serialize, Deserialize, Debug)]
pub struct Msg {
    public: String,
    message: String,
}

#[derive(Clone, FromRow, Debug)]
struct Content {
    message: String
}

pub async fn client_connection(ws: WebSocket, public_sender: String, clients: Clients, mut client: Client, db_url: String) {
    let (client_ws_sender, mut client_ws_receiver) = ws.split();
    let (client_sender, client_receiver) = mpsc::unbounded_channel();

    let client_receiver = UnboundedReceiverStream::new(client_receiver);
    tokio::task::spawn(client_receiver.forward(client_ws_sender).map(|result| {
        if let Err(e) = result {
            eprintln!("error sending websocket msg: {}", e);
        }
    }));

    client.sender = Some(client_sender);
    clients.write().await.insert(public_sender.clone(), client.clone());

    println!("connected ----------- {}", public_sender);

    send_offline_msgs(&public_sender, &client.sender, &db_url).await;

    while let Some(result) = client_ws_receiver.next().await {
        let msg = match result {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("error receiving ws message from pk: {}: {}", public_sender.clone(), e);
                break;
            }
        };
        if msg.is_close() {
            clients.write().await.remove(&public_sender);
            println!("disconnected -------- {}", public_sender);
            return;
        }
        client_msg(&public_sender, msg, &clients, &db_url).await;
    }

    clients.write().await.remove(&public_sender);
    println!("disconnected -------- {}", public_sender);
}

async fn send_offline_msgs(public_sender: &str, client_sender: &std::option::Option<UnboundedSender<Result<Message, Error>>>, db_url: &str) {
    let db = SqlitePool::connect(db_url).await.unwrap();
    let sql = format!(r#"SELECT name FROM sqlite_master WHERE type='table' AND name='x{}'"#, &public_sender);
    let result = sqlx::query(&sql).fetch_optional(&db).await;
    if let Ok(Some(_)) = result {
        let sql = format!(r#"SELECT * FROM x{};"#, &public_sender);
        let vec = sqlx::query_as::<_, Content>(&sql).fetch_all(&db).await.unwrap();
        if let Some(sender) = &client_sender {
            for msg in vec.iter() {
                let _ = sender.send(Ok(Message::binary((msg.message).as_bytes())));
            }
            let sql = format!(r#"DROP TABLE x{}"#, &public_sender);
            let _ = sqlx::query(&sql).execute(&db).await;
            println!("sent offline msgs to {}", &public_sender);
        }
    }
}

async fn client_msg(public_sender: &str, msg: Message, clients: &Clients, db_url: &str) {
    println!("received message from {}", public_sender);
    let msg_in: Msg = match serde_json::from_slice(msg.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error while parsing message request: {}", e);
            return;
        }
    };
    let msg_out = Msg {
        public: String::from(public_sender),
        message: msg_in.message    
    };
    let json = serde_json::to_string(&msg_out).unwrap();

    clients
        .read()
        .await
        .iter()
        .filter(|(a, _)| **a == msg_in.public)
        .for_each(|(_, client)| {
            if let Some(sender) = &client.sender {
                let _ = sender.send(Ok(Message::binary(json.as_bytes())));
                println!("sent message to ----- {}", msg_in.public);
            }
        });

    if clients.read().await.iter().filter(|(a, _)| **a == msg_in.public).collect::<Vec<(&String, &Client)>>().is_empty() {
        let db = SqlitePool::connect(db_url).await.unwrap();
        let sql = format!(r#"CREATE TABLE IF NOT EXISTS x{} (message TEXT);"#, &msg_in.public);
        let _ = sqlx::query(&sql).execute(&db).await;
        //let result = sqlx::query(&sql).execute(&db).await;
        //match &result {
        //    Ok(res) => println!("{}: {:?}", &msg_in.public, res),
        //    Err(err) => println!("{}",&err.to_string()),
        //}
        let sql = format!(r#"INSERT INTO x{} (message) VALUES (?)"#, &msg_in.public);
        let result = sqlx::query(&sql).bind(&json).execute(&db).await;
        if result.is_ok() {
            println!("saved message to ---- {}", msg_in.public);
        }
    }
}
