use dioxus::signals::Writable;
use dioxus_signals::SyncSignal;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tokio::time::{self, Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use tokio_tungstenite::tungstenite::protocol::{Message, CloseFrame};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Error;
use tokio_tungstenite::WebSocketStream;
use sqlx::migrate::MigrateDatabase;
use sqlx::{Sqlite, SqlitePool};
use chrono::{DateTime, Local};
use crypto::Scalar;

pub mod ws_proxy;
pub mod tor_proxy;

use crate::{ConnectToServer, Public, Content, MsgOut, ChangeChat, ChangeContacts, Contact, ContactChoice};
use crate::components::config::{Network, Ip, Port, Server};

const PROXY_ADDR: &str = "127.0.0.1:9050";
const PROXY: &str = "socks5://127.0.0.1:9050"; 

#[derive(Deserialize)]
struct Response {
    rand_number: String,
}

#[derive(Deserialize)]
struct Response2 {
    url: String,
}

#[derive(Serialize, Deserialize)]
struct Msg {
    public: String,
    message: String
}

pub async fn connection(
    data_dir: &str,
    network: Network,
    server: Server,
    public: &str,
    secret: Scalar, 
    mut connect_to_server: SyncSignal<ConnectToServer>,
    send_msg: SyncSignal<bool>,
    msg_out: SyncSignal<MsgOut>,
    shared_secrets: SyncSignal<HashMap<String, [u8; 32]>>,
    contacts: SyncSignal<Vec<Contact>>,
    change_contacts: SyncSignal<ChangeContacts>,
    contact_choice: SyncSignal<ContactChoice>,
    change_chat: SyncSignal<ChangeChat> 
)
{
    let db_url = format!("{}/client.db", data_dir);
    if !Sqlite::database_exists(&db_url).await.unwrap_or(false) {
        println!("creating database {}", &db_url);
        match Sqlite::create_database(&db_url).await {
            Ok(_) => println!("create db success"),
            Err(error) => panic!("error: {}", error),
        }
    } else {
        println!("database already exists");
    }

    let sql = (r#"CREATE TABLE IF NOT EXISTS contacts (public TEXT NOT NULL);"#).to_string();
    let db = SqlitePool::connect(&db_url).await.unwrap();
    let _ = sqlx::query(&sql).execute(&db).await;
    //let result = sqlx::query(&sql).execute(&db).await;
    //match &result {
    //    Ok(res) => println!("contacts: {:?}", res),
    //    Err(err) => println!("{}", &err.to_string()),
    //}
    let mut map = HashMap::new();
    map.insert("public", &public);
    let server_address = match server {
        Server::V4(Ip(ip), Port(port)) => format!("https://{}:{}", ip, port),    
        Server::V6(Ip(ip), Port(port)) => format!("https://[{}]:{}", ip, port)
    };
    let cert_raw = std::fs::read(format!("{}/tls/cert.pem", &data_dir)).unwrap();
    let cert = reqwest::Certificate::from_pem(&cert_raw).unwrap();  
    let client = match network {
        Network::Tor => {
            let proxy = reqwest::Proxy::all(PROXY).unwrap();
            reqwest::ClientBuilder::new().proxy(proxy).add_root_certificate(cert.clone()).use_native_tls().build().unwrap() 
        },
        Network::Clearnet => {
            reqwest::ClientBuilder::new().add_root_certificate(cert).use_native_tls().build().unwrap()
        }
    };
    let response = client
        .post(format!("{}/register", &server_address))
        .json(&map)
        .send()
        .await
        .unwrap()
        .json::<Response>()
        .await
        .unwrap();

    let signature: String = crypto::sign(&secret, public, &response.rand_number);

    let mut map2 = HashMap::new();
    map2.insert("public", public);
    map2.insert("signature", &signature);

    let response2 = client
        .post(format!("{}/register2", &server_address))
        .json(&map2)
        .send()
        .await
        .unwrap()
        .json::<Response2>()
        .await
        .unwrap();

    let ws_url: &str = &response2.url;
    let cert = native_tls::Certificate::from_pem(&cert_raw).unwrap();
    let mut builder = native_tls::TlsConnector::builder();
    builder.add_root_certificate(cert);
    let connector = builder.build().unwrap();
    match network {
        Network::Tor => {
            let tcp_stream = ws_proxy::connect_async(ws_url).await.unwrap_or_else(|e| panic!("failed to create proxy stream: {}", e));
            match tokio_tungstenite::client_async_tls_with_config(ws_url, tcp_stream, None, Some(Connector::NativeTls(connector))).await {
                Ok((ws_stream, _)) => {
                    println!("websocket handshake has been successfully completed");
                    let (write, read) = ws_stream.split();
                    let write_msgs = send_msgs(
                        write,
                        &db_url,
                        secret,
                        send_msg,
                        msg_out,
                        shared_secrets,
                        contacts,
                        change_contacts,
                        contact_choice,
                        change_chat
                    );
                    let read_msgs = receive_msgs(
                        read,
                        &db_url,
                        secret,
                        shared_secrets,
                        contacts,
                        change_contacts,
                        contact_choice,
                        change_chat
                    );

                    connect_to_server.set(ConnectToServer(true));
                    futures_util::pin_mut!(write_msgs, read_msgs);
                    futures_util::future::select(write_msgs, read_msgs).await;
                },
                Err(e) => {
                    match e {
                        tokio_tungstenite::tungstenite::Error::Http(re) => {
                            println!("{}", String::from_utf8_lossy(re.into_body().unwrap().as_slice()));
                        },
                        _ => println!("{:?}", e),
                    }
                }
            }
        },
        Network::Clearnet => {
            let (ws_stream, _) = connect_async_tls_with_config(ws_url, None, false, Some(Connector::NativeTls(connector))).await.expect("failed to connect");
            println!("websocket handshake has been successfully completed");
            let (write, read) = ws_stream.split();
            let write_msgs = send_msgs(
                write,
                &db_url,
                secret,
                send_msg,
                msg_out,
                shared_secrets,
                contacts,
                change_contacts,
                contact_choice,
                change_chat
            );
            let read_msgs = receive_msgs(
                read,
                &db_url,
                secret,
                shared_secrets,
                contacts,
                change_contacts,
                contact_choice,
                change_chat
            ); 

            connect_to_server.set(ConnectToServer(true));
            futures_util::pin_mut!(write_msgs, read_msgs);
            futures_util::future::select(write_msgs, read_msgs).await;
        }
    };
}

async fn send_msgs<S>(
    mut write: SplitSink<WebSocketStream<S>, Message>,
    db_url: &str,
    secret: Scalar,
    mut send_msg: SyncSignal<bool>,
    msg_out: SyncSignal<MsgOut>,
    mut shared_secrets: SyncSignal<HashMap<String, [u8; 32]>>,
    contacts: SyncSignal<Vec<Contact>>,
    mut change_contacts: SyncSignal<ChangeContacts>,
    mut contact_choice: SyncSignal<ContactChoice>,
    mut change_chat: SyncSignal<ChangeChat>, 
)
where S: AsyncRead + AsyncWrite + Unpin,
{ 
    let mut interval = time::interval(Duration::from_millis(150));
    loop {
        interval.tick().await;
        if send_msg() {
            match msg_out() {
                MsgOut::Chat(Public(public), Content(content)) => {
                    let date_time: DateTime<Local> = Local::now();
                    let time = format!("{}", date_time.format("%d/%m/%Y %H:%M"));
                    let db = SqlitePool::connect(db_url).await.unwrap();
                    let sql = format!(r#"INSERT INTO x{} (kind, message, time) VALUES (?,?,?)"#, &public);
                    let _ = sqlx::query(&sql)
                        .bind(1)
                        .bind(&content)
                        .bind(&time)
                        .execute(&db).await;
                    change_chat.set(ChangeChat(true));
                    send(&mut write, secret, &public, &content, &mut shared_secrets).await;
                },
                MsgOut::AddContact(Public(public), Content(content)) => {
                    let date_time: DateTime<Local> = Local::now();
                    let time = format!("{}", date_time.format("%d/%m/%Y %H:%M"));
                    let db = SqlitePool::connect(db_url).await.unwrap();
                    if !contacts().iter().any(|x| x.public == public) {
                        let sql = format!(r#"CREATE TABLE IF NOT EXISTS x{} (kind INTEGER NOT NULL, message TEXT, time TEXT);"#, &public);
                        let _ = sqlx::query(&sql).execute(&db).await;
                        //match &result {
                        //    Ok(res) => println!("{}: {:?}", &public, res),
                        //    Err(err) => println!("{}",&err.to_string()),
                        //}
                        let sql = (r#"INSERT INTO contacts (public) VALUES (?)"#).to_string();
                        let _ = sqlx::query(&sql).bind(&public).execute(&db).await;
                        //println!("insert into contacts {:?}", result.unwrap());
                        change_contacts.set(ChangeContacts(true));
                    }
                    let sql = format!(r#"INSERT INTO x{} (kind, message, time) VALUES (?,?,?)"#, &public);
                    let _ = sqlx::query(&sql)
                        .bind(1)
                        .bind(&content)
                        .bind(&time)
                        .execute(&db).await;
                    send(&mut write, secret, &public, &content, &mut shared_secrets).await;
                    contact_choice.set(ContactChoice::Public(public));
                    change_chat.set(ChangeChat(true));
                },
                MsgOut::Close => {
                    write.send(Message::Close(Some(
                        CloseFrame {
                            code: CloseCode::Normal,
                            reason: "close connection".into()
                        }))).await.unwrap();
                    write.flush().await.unwrap();
                    time::sleep(Duration::from_millis(100)).await;
                    std::process::exit(0);
                }
            }
            send_msg.set(false);
        }
    }
}

async fn send<S>(
    write: &mut SplitSink<WebSocketStream<S>, Message>,
    secret: Scalar,
    public: &str,
    message: &str,
    shared_secrets: &mut SyncSignal<HashMap<String, [u8; 32]>>
)
where S: AsyncRead + AsyncWrite + Unpin,
{
    if !shared_secrets().contains_key(public) {
        shared_secrets.write().insert(public.to_string(), crypto::shared_secret(&secret, public));
    }        
    let shared_secret = *shared_secrets().get(public).unwrap();
    let encrypted_msg: String = crypto::encrypt(message, shared_secret);
    let msg_out = Msg {
        public: public.to_string(),
        message: encrypted_msg
    };
    let json = serde_json::to_string(&msg_out).unwrap();

    write.send(Message::Binary(json.as_bytes().to_vec().into())).await.unwrap();
}

async fn on_msg_in_event(
    message: Result<Message, Error>,
    db_url: &str,
    secret: Scalar,
    mut shared_secrets: SyncSignal<HashMap<String, [u8; 32]>>,
    contacts: SyncSignal<Vec<Contact>>,
    mut change_contacts: SyncSignal<ChangeContacts>,
    contact_choice: SyncSignal<ContactChoice>,
    mut change_chat: SyncSignal<ChangeChat>
) 
{
    let msg_in = message.unwrap();
    let msg_in = msg_in.into_text().unwrap();
    let msg_in: Msg = match serde_json::from_str(&msg_in) {
        Ok(v) => v,
        Err(_) => {
            return;
        }
    };
    println!("received message from {}", msg_in.public);
    if !shared_secrets().contains_key(&msg_in.public) {
        shared_secrets.write().insert(msg_in.public.clone(), crypto::shared_secret(&secret, &msg_in.public));
    }        
    let shared_secret = *shared_secrets().get(&msg_in.public).unwrap();
    let decrypted_msg: String = crypto::decrypt(&msg_in.message, shared_secret);
    let date_time: DateTime<Local> = Local::now();
    let time = format!("{}", date_time.format("%d/%m/%Y %H:%M"));
    let db = SqlitePool::connect(db_url).await.unwrap();
    if !contacts().iter().any(|x| x.public == msg_in.public) {
        let sql = format!(r#"CREATE TABLE IF NOT EXISTS x{} (kind INTEGER NOT NULL, message TEXT, time TEXT);"#, &msg_in.public);
        let _ = sqlx::query(&sql).execute(&db).await;
        //match &result {
        //    Ok(res) => println!("{}: {:?}", &msg_in.public, res),
        //    Err(err) => println!("{}",&err.to_string()),
        //}
        let sql = (r#"INSERT INTO contacts (public) VALUES (?)"#).to_string();
        let _ = sqlx::query(&sql).bind(&msg_in.public).execute(&db).await;
        //println!("{:?}", result.unwrap());
        change_contacts.set(ChangeContacts(true));
    }

    let sql = format!(r#"INSERT INTO x{} (kind, message, time) VALUES (?,?,?)"#, &msg_in.public);
    let _ = sqlx::query(&sql)
        .bind(0)
        .bind(&decrypted_msg)
        .bind(&time)
        .execute(&db).await;
    if contact_choice() == ContactChoice::Public(msg_in.public.clone()) {
        change_chat.set(ChangeChat(true));
    }
}
async fn receive_msgs<S>(
    read: SplitStream<WebSocketStream<S>>,
    db_url: &str,
    secret: Scalar,
    shared_secrets: SyncSignal<HashMap<String,[u8; 32]>>,
    contacts: SyncSignal<Vec<Contact>>,
    change_contacts: SyncSignal<ChangeContacts>,
    contact_choice: SyncSignal<ContactChoice>,
    change_chat: SyncSignal<ChangeChat>
) 
where S: AsyncRead + AsyncWrite + Unpin,
{
    let read_future = read.for_each(|message| async move {
        on_msg_in_event(
            message,
            db_url,
            secret,
            shared_secrets,
            contacts,
            change_contacts,
            contact_choice,
            change_chat
        ).await;
    });
    read_future.await;
}
