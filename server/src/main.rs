use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Write;
use std::sync::Arc;
use std::fs::{self, File};
use std::path::Path;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc, RwLock};
use warp::{ws::Message, Filter, Rejection};
use sqlx::{migrate::MigrateDatabase, Sqlite};

mod handler;
mod ws;

type Result<T> = std::result::Result<T, Rejection>;
type Clients = Arc<RwLock<HashMap<String, Client>>>;

#[derive(PartialEq, Clone, Serialize, Deserialize)]
struct Ip(#[serde(rename = "ip")] String);

#[derive(PartialEq, Clone, Serialize, Deserialize)]
struct Port(#[serde(rename = "port")] u16);

#[derive(PartialEq, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "args")]
enum Socket {
    V4(Ip, Port),
    V6(Ip, Port)
}

fn check_ip(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok() || ip.parse::<Ipv6Addr>().is_ok()
}

fn read_config(config_path: &str) -> Option<Socket> {
    if !Path::new(config_path).exists() { return None } 
    let content = fs::read_to_string(config_path).unwrap();
    Some(toml::from_str(&content).unwrap())
}

fn write_config(socket: &Socket, config_path: &str) {
    let mut file = File::create(config_path).unwrap();
    let toml_string = toml::to_string(socket).unwrap();
    let _ = file.write_all(toml_string.as_bytes());        
}

#[derive(Debug, Clone)]
pub struct Client {
    pub rand_number: String,
    pub sender: Option<mpsc::UnboundedSender<std::result::Result<Message, warp::Error>>>,
}

#[tokio::main]
async fn main() {
    let home_path = std::env::home_dir().unwrap();
    let home_path = home_path.to_str().unwrap();
    let _ = std::fs::create_dir(format!("{}/.config/tchat", home_path));
    let db_url = format!("sqlite://{}/.config/tchat/server.db", home_path);
    if !Sqlite::database_exists(&db_url).await.unwrap_or(false) {
        println!("creating database {}", &db_url);
        match Sqlite::create_database(&db_url).await {
            Ok(_) => println!("create db success"),
            Err(error) => panic!("error: {}", error),
        }
    } else {
        println!("database already exists");
    }   
    let config_path = format!("{}/.config/tchat/server.toml", home_path);
    let socket = match read_config(&config_path) {
        None => {
            let ip = loop {
                println!("type your ip address:");
                let mut ip = String::new();
                std::io::stdin().read_line(&mut ip).expect("failed to read line");
                let ip = ip.trim();
                if check_ip(ip) {
                    break ip.to_string()
                } else {
                    println!("no valid ip address");
                    continue
                }
            };
            let port = loop {
                println!("type port:");
                let mut port = String::new();
                std::io::stdin().read_line(&mut port).expect("failed to read line");
                let port = port.trim();
                match port.parse::<u16>() {
                    Ok(v) => break v,
                    Err(_) => {
                        println!("no valid port");
                        continue
                    } 
                }
            };
            let socket = if ip.parse::<Ipv4Addr>().is_ok() {
                Socket::V4(Ip(ip), Port(port))
            } else {
                Socket::V6(Ip(ip), Port(port))
            };

            write_config(&socket, &config_path);
            socket
        },
        Some(socket) => { socket }
    };   
    
    let socket_run = match socket {
        Socket::V4(_, Port(port)) => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port),
        Socket::V6(_, Port(port)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), port),
    };

    let socket_addr = match socket {
        Socket::V4(Ip(ip), Port(port)) => SocketAddr::new(IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap()), port),
        Socket::V6(Ip(ip), Port(port)) => SocketAddr::new(IpAddr::V6(ip.parse::<Ipv6Addr>().unwrap()), port),       
    };
    
    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    let health_route = warp::path!("health").and_then(handler::health_handler);

    let register = warp::path("register");
    let register_routes = register
        .and(warp::post())
        .and(warp::body::json())
        .and(with_clients(clients.clone()))
        .and(warp::addr::remote())
        .and_then(handler::register_handler)
        .or(register
            .and(warp::delete())
            .and(warp::path::param())
            .and(with_clients(clients.clone()))
            .and_then(handler::unregister_handler));

    let register2 = warp::path("register2");
    let register_routes2 = register2
        .and(warp::post())
        .and(warp::body::json())
        .and(with_clients(clients.clone()))
        .and(warp::any().map(move || socket_addr))
        .and_then(handler::register_handler2)
        .or(register2
            .and(warp::delete())
            .and(warp::path::param())
            .and(with_clients(clients.clone()))
            .and_then(handler::unregister_handler));

    let publish = warp::path!("publish")
        .and(warp::body::json())
        .and(with_clients(clients.clone()))
        .and_then(handler::publish_handler);

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(warp::path::param())
        .and(with_clients(clients.clone()))
        .and(warp::any().map(move || db_url.clone()))
        .and_then(handler::ws_handler);

    let routes = health_route
        .or(register_routes)
        .or(register_routes2)
        .or(ws_route)
        .or(publish)
        .with(warp::cors().allow_any_origin());

    let (_, fut) = warp::serve(routes)
        .tls()
        .cert_path(format!("{}/.config/tchat/tls/cert.pem", home_path))
        .key_path(format!("{}/.config/tchat/tls/key.pem", home_path))
        .bind_with_graceful_shutdown(socket_run, async move {
            tokio::signal::ctrl_c().await.expect("failed to listen to shutdown signal");
            println!("ctrl-c received - shutdown server");
        });
    fut.await;
}

fn with_clients(clients: Clients) -> impl Filter<Extract = (Clients,), Error = Infallible> + Clone {
    warp::any().map(move || clients.clone())
}
