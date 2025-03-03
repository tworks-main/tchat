use dioxus::prelude::*;
use dioxus_router::prelude::*;
use dioxus_clipboard::hooks::use_clipboard;
use serde::{Serialize, Deserialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use crypto;

use crate::{Route, SetUpProxy, ConnectToServer, MsgOut, Contact, ContactChoice, ChangeContacts, ChangeChat, Keys};
use crate::{DATA_DIR, KEYS, COPY};
use crate::ws_conn;

const MIN_PASSWD_LEN: usize = 8;

#[derive(PartialEq, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "args")]
pub enum Network {
    Tor,
    Clearnet
}

#[derive(PartialEq, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "args")]
enum Secret {
    Clear(String),
    Encrypted([String; 2])
}

#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct Ip(#[serde(rename = "ip")] pub String);

#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct Port(#[serde(rename = "port")] pub u16);

#[derive(PartialEq, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "args")]
pub enum Server {
    V4(Ip, Port),
    V6(Ip, Port)
}
#[derive(PartialEq, Clone, Serialize, Deserialize)]
struct Config {
    network: Option<Network>,
    server: Option<Server>,
    secret: Option<Secret>
}

impl Config {
    fn write_config(&self) {
        let path = format!("{}/client.toml", DATA_DIR);
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("cannot open file");
        let toml_string = toml::to_string(self).unwrap();
        let _ = file.write(toml_string.as_bytes());        
    }
    fn read_config() -> Self {
        let path = format!("{}/client.toml", DATA_DIR);
        let _ = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .expect("cannot open file");
        let content = fs::read_to_string(&path).unwrap();
        toml::from_str(&content).unwrap()
    }
}

#[derive(PartialEq, Clone)]
enum SecretChoice {
    Generate,
    Enter
}

#[derive(PartialEq, Clone)]
enum EncryptSecret {
    No,
    Yes
}

fn check_u16(port: &str) -> bool {
    port.parse::<u16>().is_ok()
    
}

fn check_ip_address(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok() || ip.parse::<Ipv6Addr>().is_ok()
}

#[derive(Props, Clone, PartialEq)]
struct ChoiceProps {
    oninput_no_encryption: EventHandler<FormEvent>,
    oninput_encryption: EventHandler<FormEvent>

}

#[allow(non_snake_case)]
fn EncryptSecretChoice(props: ChoiceProps) -> Element { 
    rsx!(
        label {
            class: "radio_container",
            input {
                r#type: "radio",
                checked: true,
                name: "radio",
                oninput: move |evt| props.oninput_no_encryption.call(evt)
            }, 
            span {
                class: "checkmark"
            },
            "no secret key encryption"
        },       
        label {
            class: "radio_container",
            input {
                r#type: "radio",
                name: "radio",
                oninput: move |evt| props.oninput_encryption.call(evt)
            }, 
            span {
                class: "checkmark"
            },
            "secret key encryption"
        }
    )
}

#[derive(Props, Clone, PartialEq)]
struct StartProps {
    network: Network,
    server: Server,
    onclick: EventHandler<MouseEvent>,
}

#[allow(non_snake_case)]
fn Start(props: StartProps) -> Element {
    rsx!(
        div {
            class: "text",
            match props.network {
                Network::Tor => "you are connecting via tor network to",
                Network::Clearnet => "you are connectiong via clearnet to"
            }
        },
        div {
            class: "text",
            match props.server {
                Server::V4(Ip(ip), Port(port)) => format!("ip v4: {}, port: {}", ip, port),
                Server::V6(Ip(ip), Port(port)) => format!("ip v6: {}, port: {}", ip, port)
            }
        },
        button {
            class: "button",
            onclick: move |evt| {
                props.onclick.call(evt);
            },
            "start private messaging"
        }
    )
}

#[derive(Props, Clone, PartialEq)]
struct SetPasswordProps {
    passwd: String,
    passwd_control: String,
    oninput_passwd: EventHandler<FormEvent>,
    oninput_passwd_control: EventHandler<FormEvent>,
    network: Network,
    server: Server,
    onclick: EventHandler<MouseEvent>
}

#[allow(non_snake_case)]
fn SetPassword(props: SetPasswordProps) -> Element {
    rsx!(
        div { class: "text", "enter a password" },
        div { class: "passwd_container",
            input {
                class: "passwd",
                r#type: "password",    
                value: "{props.passwd}",
                oninput: move |evt| props.oninput_passwd.call(evt) 
            }
        },
        div { class: "text", "reenter password" },
        div { class: "passwd_container",
            input {
                class: "passwd",
                r#type: "password",
                value: "{props.passwd_control}",
                oninput: move |evt| props.oninput_passwd_control.call(evt)
            }
        },
        if props.passwd != props.passwd_control {
            div { class: "error", "passwords do not match" } 
        }
        if props.passwd.len() < MIN_PASSWD_LEN {
            div { class: "error", "password needs at least {MIN_PASSWD_LEN} characters" }
        }
        if props.passwd == props.passwd_control && props.passwd.len() >= MIN_PASSWD_LEN  {
            Start {
                network: props.network,
                server: props.server,
                onclick: props.onclick
            }
        }
    )
}

#[derive(PartialEq, Clone, Debug, Default, Props)]
pub struct ConnectProps {
    onmounted_connect: EventHandler<MountedEvent>, 
    onmounted_to_chat: EventHandler<MountedEvent>
}

#[allow(non_snake_case)]
fn ConnectServer(props: ConnectProps) -> Element {
    let connect_to_server: SyncSignal<ConnectToServer> = use_context();
    rsx!(
        if connect_to_server() == ConnectToServer(true) {
            div { onmounted: move |evt| props.onmounted_to_chat.call(evt) } 
        } else {
            div {
                class: "text",
                onmounted: move |evt| props.onmounted_connect.call(evt),
                "connecting to server ..."
            }
        }
    )
}

#[allow(non_snake_case)]
pub fn Connect(props: ConnectProps) -> Element {
    let network: SyncSignal<Network> = use_context();
    let set_up_proxy: SyncSignal<SetUpProxy> = use_context();
    match network() {
        Network::Tor => { 
            rsx!(
                if set_up_proxy() == SetUpProxy(true) {
                    ConnectServer { onmounted_connect: props.onmounted_connect, onmounted_to_chat: props.onmounted_to_chat }
                } else {
                    div{ class: "text", "setting up tor proxy on port 9050 ..." }
                }
            )
        },
        Network::Clearnet => {
            rsx!(
                ConnectServer { onmounted_connect: props.onmounted_connect, onmounted_to_chat: props.onmounted_to_chat }
            )
        }
    }
}

#[component]
pub fn Configuration() -> Element {
    let navigator = use_navigator();
    let mut clipboard = use_clipboard();
    let mut network: SyncSignal<Network> = use_context();
    let set_up_proxy: SyncSignal<SetUpProxy> = use_context();
    let connect_to_server: SyncSignal<ConnectToServer> = use_context();
    let send_msg: SyncSignal<bool> = use_context(); 
    let msg_out: SyncSignal<MsgOut> = use_context();
    let shared_secrets: SyncSignal<HashMap::<String, [u8; 32]>> = use_context();
    let contacts: SyncSignal<Vec<Contact>> = use_context();
    let change_contacts: SyncSignal<ChangeContacts> = use_context();
    let contact_choice: SyncSignal<ContactChoice> = use_context();
    let change_chat: SyncSignal<ChangeChat> = use_context();
    let config = use_signal(Config::read_config);
    let mut network_config = use_signal(|| config().network);
    let mut network_choice = use_signal(|| Network::Tor);
    let mut network_is_new = use_signal(|| false);
    let mut server = use_signal(|| config().server);
    let mut ip = use_signal(String::new);
    let mut port = use_signal(String::new);
    let mut check_ip = use_signal(|| false);
    let mut check_port = use_signal(|| false);
    let mut server_is_new = use_signal(|| false);
    let mut passwd = use_signal(String::new);
    let mut check_passwd = use_signal(|| true);
    let mut chosen = use_signal(|| false);
    let mut secret_choice = use_signal(|| SecretChoice::Generate);
    let secret_scalar = use_signal(crypto::generate_secret);
    let mnemonic = use_signal(|| crypto::scalar_to_mnemonic(&secret_scalar()));
    let mut encrypt_secret = use_signal(|| EncryptSecret::No);
    let mut passwd_control = use_signal(String::new);
    let mut secret_mnemonic = use_signal(String::new);
    let mut check_mnemonic = use_signal(|| false);
    let mut start_clicked = use_signal(|| false);
    let no_encryption = move |_| {
        encrypt_secret.set(EncryptSecret::No); 
        passwd.set(String::new());
        passwd_control.set(String::new());
    };
    let encryption = move |_| { encrypt_secret.set(EncryptSecret::Yes); };
    let to_chat = move |_| { navigator.push(Route::Chat {}); };
    rsx!(
        match network_config() {
            None => {
                rsx!(
                    label {
                        class: "radio_container",
                        input {
                            r#type: "radio",
                            checked: true,
                            name: "radio",
                            oninput: move |_| network_choice.set(Network::Tor) 
                        }, 
                        span {
                            class: "checkmark"
                        },
                        "connection over tor network"
                    },       
                    label {
                        class: "radio_container",
                        input {
                            r#type: "radio",
                            name: "radio",
                            oninput: move |_| network_choice.set(Network::Clearnet)
                        }, 
                        span {
                            class: "checkmark"
                        },
                        "connection over clearnet"
                    },
                    button {
                        class: "button",
                        onclick: move |_| {
                            network_is_new.set(true);
                            network_config.set(Some(network_choice()));
                        },
                        "save"
                    }
                )
            },
            Some(_) => {
                match server() {
                    None => {
                        rsx!(
                            div {
                                class: "ip_container",
                                div {
                                    class: "text",
                                    "type server ip address"
                                },
                                span {
                                    input {
                                        class: "ip",
                                        value: "{ip}",
                                        oninput: move |event| {
                                            ip.set(event.value().clone());
                                            check_ip.set(check_ip_address(&ip()));
                                        }
                                    },
                                },
                                if !check_ip() {
                                    span {
                                        class: "error",
                                        "invalid ip"
                                    }
                                }
                            },
                            div {
                                div {
                                    class: "text",
                                    "type server port"
                                    }
                                span {
                                    input {
                                        class: "port",
                                        value: "{port}",
                                        oninput: move |event| {
                                            port.set(event.value().clone());
                                            check_port.set(check_u16(&port()));
                                        }
                                    },
                                }
                                if !check_port() {
                                    span {
                                        class: "error",
                                        "invalid port"
                                    }
                                }
                                
                            },
                            if check_ip() && check_port() {
                                div {
                                    button {
                                        class: "button",
                                        onclick: move |_| {
                                            let server_new = if ip().parse::<Ipv4Addr>().is_ok() {
                                                Server::V4(Ip(ip()), Port(port().parse::<u16>().unwrap())) 
                                            } else {
                                                Server::V6(Ip(ip()), Port(port().parse::<u16>().unwrap()))
                                            };
                                            server_is_new.set(true);
                                            server.set(Some(server_new));
                                        },
                                        "save"
                                    },
                                }
                            }
                        )
                    },
                    Some(_) => {
                        match config().secret {
                            Some(Secret::Clear(secret)) => {
                                let start = move |_| {
                                    start_clicked.set(true);
                                    network.set(network_config().unwrap());
                                    let data_dir = DATA_DIR();
                                    if let Network::Tor = network() {
                                        spawn_forever(async move {
                                            tokio::spawn(async move {
                                                ws_conn::tor_proxy::run_tor_proxy(&data_dir, set_up_proxy).await;
                                            });
                                        });
                                    }  
                                };
                                let connect = move |_| {
                                    if network_is_new() || server_is_new() {
                                        let config_new = Config {
                                            network: if network_is_new() { network_config() } else { None },
                                            server: if server_is_new() { server() } else { None },
                                            secret: None
                                        };
                                        config_new.write_config();
                                    }
                                    let data_dir = DATA_DIR();
                                    let server = server().unwrap();
                                    let secret_scalar = crypto::secret_hex_to_scalar(&secret);
                                    *KEYS.write() = Keys::from_scalar(&secret_scalar);                                   
                                    let public = KEYS().public;
                                    let secret_scalar = crypto::secret_hex_to_scalar(&secret);
                                    spawn_forever(async move {
                                        tokio::spawn(async move {
                                            ws_conn::connection(
                                                &data_dir,
                                                network(),
                                                server,
                                                &public,
                                                secret_scalar,
                                                connect_to_server,
                                                send_msg,
                                                msg_out,
                                                shared_secrets,
                                                contacts,
                                                change_contacts,
                                                contact_choice,
                                                change_chat
                                            ).await;
                                        });
                                    });
                                }; 
                                if start_clicked() {
                                    return rsx!(Connect{ onmounted_connect: connect, onmounted_to_chat: to_chat }) 
                                }
                                rsx!(
                                    Start {
                                        network: network_config().unwrap(),
                                        server: server.unwrap(),
                                        onclick: start
                                    }
                                )
                            },
                            Some(Secret::Encrypted([encrypt_secret, hashed_passwd])) => {
                                let start = move |_| {
                                    if crypto::check_passwd(&passwd(), &hashed_passwd) {
                                        start_clicked.set(true);
                                        network.set(network_config().unwrap());
                                        if network_is_new() || server_is_new() {
                                            let config_new = Config {
                                                network: if network_is_new() { network_config() } else { None },
                                                server: if server_is_new() { server() } else { None },
                                                secret: None
                                            };
                                            config_new.write_config();
                                        }
                                        let data_dir = DATA_DIR();
                                        if let Network::Tor = network() {
                                            spawn_forever(async move {
                                                tokio::spawn(async move {
                                                    ws_conn::tor_proxy::run_tor_proxy(&data_dir, set_up_proxy).await;
                                                });
                                            });
                                        }
                                    } else {
                                        check_passwd.set(false);
                                        passwd.set(String::new());
                                    }
                                };
                                let connect = move |_| {
                                    let data_dir = DATA_DIR();
                                    let server = server().unwrap();
                                    let secret_scalar = crypto::decrypt_secret(&encrypt_secret, &passwd());
                                    *KEYS.write() = Keys::from_scalar(&secret_scalar);                                   
                                    let public = KEYS().public;
                                    spawn_forever(async move {
                                        tokio::spawn(async move {
                                            ws_conn::connection(
                                                &data_dir,
                                                network(),
                                                server,
                                                &public,
                                                secret_scalar,
                                                connect_to_server,
                                                send_msg,
                                                msg_out,
                                                shared_secrets,
                                                contacts,
                                                change_contacts,
                                                contact_choice,
                                                change_chat
                                            ).await;
                                        });
                                    });
                                };
                                if start_clicked() {
                                    return rsx!(Connect{ onmounted_connect: connect, onmounted_to_chat: to_chat }) 
                                }
                                rsx!(
                                    div { class: "text", "enter password" },
                                    div { class: "passwd_container",
                                        input {
                                            class: "passwd",
                                            r#type: "password",    
                                            value: "{passwd}",
                                            oninput: move |event| passwd.set(event.value().clone()) 
                                        }
                                    },           
                                    if !check_passwd() {
                                        div {class: "error", "false password"}
                                    }
                                    Start {
                                        network: network_config().unwrap(),
                                        server: server().unwrap(),
                                        onclick: start
                                    }
                                )
                            },
                            None => {
                                if !chosen() {
                                    rsx!(
                                        label {
                                            class: "radio_container",
                                            input {
                                                r#type: "radio",
                                                checked: true,
                                                name: "radio",
                                                oninput: move |_| secret_choice.set(SecretChoice::Generate) 
                                            }, 
                                            span {
                                                class: "checkmark"
                                            },
                                            "generate new secret key"
                                        },       
                                        label {
                                            class: "radio_container",
                                            input {
                                                r#type: "radio",
                                                name: "radio",
                                                oninput: move |_| secret_choice.set(SecretChoice::Enter)
                                            }, 
                                            span {
                                                class: "checkmark"
                                            },
                                            "restore secret key from seed"
                                        },
                                        div {
                                            button {
                                                class: "button",
                                                onclick: move |_| match secret_choice() {
                                                    SecretChoice::Generate => {
                                                        chosen.set(true);
                                                    },
                                                    SecretChoice::Enter => {
                                                        chosen.set(true);
                                                    }
                                                }, 
                                                match secret_choice() {
                                                    SecretChoice::Generate => "generate secret key",
                                                    SecretChoice::Enter => "restore secret key"
                                                }
                                            }
                                        }
                                    )
                                } else {
                                    match secret_choice() {
                                        SecretChoice::Generate => {
                                            rsx!(
                                                div {
                                                    class: "text",
                                                    "your secret phrase"
                                                },
                                                div {
                                                    class: "key_container",
                                                    div {
                                                        class: "key",
                                                        "{mnemonic()}"
                                                    }
                                                    button { 
                                                        class: "copy",
                                                        onclick: move |_| {
                                                            let _ = clipboard.set(mnemonic());
                                                        },
                                                        img { src: COPY, draggable: "false", alt: "copy" },
                                                    }
                                                },
                                                EncryptSecretChoice{ oninput_no_encryption: no_encryption, oninput_encryption: encryption }
                                                div {
                                                    match encrypt_secret() {
                                                        EncryptSecret::No => {
                                                            let start = move |_| {
                                                                start_clicked.set(true);
                                                                network.set(network_config().unwrap());
                                                                let data_dir = DATA_DIR();
                                                                if let Network::Tor = network() {
                                                                    spawn_forever(async move {
                                                                        tokio::spawn(async move {
                                                                            ws_conn::tor_proxy::run_tor_proxy(&data_dir, set_up_proxy).await;
                                                                        });
                                                                    });
                                                                }
                                                            };
                                                            let connect = move |_| {
                                                                let secret_scalar = secret_scalar();
                                                                let secret = crypto::scalar_to_hex(&secret_scalar);
                                                                let config_new = Config {
                                                                    network: if network_is_new() { network_config() } else { None },
                                                                    server: if server_is_new() { server() } else { None },
                                                                    secret: Some(Secret::Clear(secret))
                                                                };
                                                                config_new.write_config();
                                                                let data_dir = DATA_DIR();
                                                                let server = server().unwrap();
                                                                *KEYS.write() = Keys::from_scalar(&secret_scalar);
                                                                let public = KEYS().public;
                                                                spawn_forever(async move {
                                                                    tokio::spawn(async move {
                                                                        ws_conn::connection(
                                                                            &data_dir,
                                                                            network(),
                                                                            server,
                                                                            &public,
                                                                            secret_scalar,
                                                                            connect_to_server,
                                                                            send_msg,
                                                                            msg_out,
                                                                            shared_secrets,
                                                                            contacts,
                                                                            change_contacts,
                                                                            contact_choice,
                                                                            change_chat
                                                                        ).await;
                                                                    });
                                                                });
                                                            };
                                                            if start_clicked() {
                                                                return rsx!(Connect{ onmounted_connect: connect, onmounted_to_chat: to_chat }) 
                                                            }
                                                            rsx!(
                                                                Start {
                                                                    network: network_config().unwrap(),
                                                                    server: server().unwrap(),
                                                                    onclick: start
                                                                }
                                                            )               
                                                        },
                                                        EncryptSecret::Yes => {
                                                            let oninput_passwd = move |event: FormEvent| {
                                                                passwd.set(event.value().clone());
                                                            };
                                                            let oninput_passwd_control = move |event: FormEvent| {
                                                                passwd_control.set(event.value().clone());
                                                            };
                                                            let start = move |_| {
                                                                start_clicked.set(true);
                                                                network.set(network_config().unwrap());
                                                                let data_dir = DATA_DIR();
                                                                if let Network::Tor = network() {
                                                                    spawn_forever(async move {
                                                                        tokio::spawn(async move {
                                                                            ws_conn::tor_proxy::run_tor_proxy(&data_dir, set_up_proxy).await;
                                                                        });
                                                                    });
                                                                }
                                                            };
                                                            let connect = move |_| {
                                                                let secret_scalar = secret_scalar();
                                                                let config_new = Config {                                                            
                                                                    network: if network_is_new() { network_config() } else { None },
                                                                    server: if server_is_new() { server() } else { None },
                                                                    secret: Some(Secret::Encrypted(crypto::encrypt_secret(&secret_scalar, &passwd())))
                                                                };
                                                                config_new.write_config();
                                                                let data_dir = DATA_DIR();
                                                                let server = server().unwrap();
                                                                *KEYS.write() = Keys::from_scalar(&secret_scalar);
                                                                let public = KEYS().public;
                                                                spawn_forever(async move {
                                                                    tokio::spawn(async move {
                                                                        ws_conn::connection(
                                                                            &data_dir,
                                                                            network(),
                                                                            server,
                                                                            &public,
                                                                            secret_scalar,
                                                                            connect_to_server,
                                                                            send_msg,
                                                                            msg_out,
                                                                            shared_secrets,
                                                                            contacts,
                                                                            change_contacts,
                                                                            contact_choice,
                                                                            change_chat
                                                                        ).await;
                                                                    });
                                                                });
                                                            };
                                                            if start_clicked() {
                                                                return rsx!(Connect{ onmounted_connect: connect, onmounted_to_chat: to_chat }) 
                                                            }
                                                            rsx!(
                                                                SetPassword {
                                                                    passwd: passwd(),
                                                                    passwd_control: passwd_control(),
                                                                    oninput_passwd,
                                                                    oninput_passwd_control,
                                                                    network: network_config().unwrap(),
                                                                    server: server().unwrap(),
                                                                    onclick: start
                                                                }
                                                            )
                                                        }
                                                    }
                                                }            
                                            )
                                        },
                                        SecretChoice::Enter => {
                                            rsx!(
                                                div {
                                                    class: "text",
                                                    "your secret key"
                                                },
                                                textarea {
                                                    class: "secret_field",
                                                    value: "{secret_mnemonic}",
                                                    oninput: move |event| {
                                                        secret_mnemonic.set(event.value().clone());
                                                        check_mnemonic.set(crypto::check_mnemonic(&secret_mnemonic()));
                                                    }
                                                }
                                                if check_mnemonic() {
                                                    div {
                                                        EncryptSecretChoice{ oninput_no_encryption: no_encryption, oninput_encryption: encryption }
                                                        div {
                                                            match encrypt_secret() {
                                                                EncryptSecret::No => {
                                                                    let start = move |_| {
                                                                        start_clicked.set(true);
                                                                        network.set(network_config().unwrap());
                                                                        let data_dir = DATA_DIR();
                                                                        if let Network::Tor = network() {
                                                                            spawn_forever(async move {
                                                                                tokio::spawn(async move {
                                                                                    ws_conn::tor_proxy::run_tor_proxy(&data_dir, set_up_proxy).await;
                                                                                });
                                                                            });
                                                                        }
                                                                    };
                                                                    let connect = move |_| {
                                                                        let secret_mnemonic = secret_mnemonic();
                                                                        let secret_scalar = crypto::mnemonic_to_scalar(&secret_mnemonic);
                                                                        let config_new = Config {
                                                                            network: if network_is_new() { network_config() } else { None },
                                                                            server: if server_is_new() { server() } else { None },
                                                                            secret: Some(Secret::Clear(crypto::scalar_to_hex(&secret_scalar)))
                                                                        };
                                                                        config_new.write_config();
                                                                        let data_dir = DATA_DIR();
                                                                        let server = server().unwrap();
                                                                        *KEYS.write() = Keys::from_mnemonic(secret_mnemonic);
                                                                        let public = KEYS().public;
                                                                        spawn_forever(async move {
                                                                            tokio::spawn(async move {
                                                                                ws_conn::connection(
                                                                                    &data_dir,
                                                                                    network(),
                                                                                    server,
                                                                                    &public,
                                                                                    secret_scalar,
                                                                                    connect_to_server,
                                                                                    send_msg,
                                                                                    msg_out,
                                                                                    shared_secrets,
                                                                                    contacts,
                                                                                    change_contacts,
                                                                                    contact_choice,
                                                                                    change_chat
                                                                                ).await;
                                                                            });
                                                                        });
                                                                    };
                                                                    if start_clicked() {
                                                                        return rsx!(Connect{ onmounted_connect: connect, onmounted_to_chat: to_chat }) 
                                                                    }
                                                                    rsx!(
                                                                        Start {
                                                                            network: network_config().unwrap(),
                                                                            server: server().unwrap(),
                                                                            onclick: start
                                                                        }
                                                                    )               
                                                                },
                                                                EncryptSecret::Yes => {
                                                                    let oninput_passwd = move |event: FormEvent| {
                                                                        passwd.set(event.value().clone());
                                                                    };
                                                                    let oninput_passwd_control = move |event: FormEvent| {
                                                                        passwd_control.set(event.value().clone());
                                                                    };
                                                                    let start = move |_| {
                                                                        start_clicked.set(true);
                                                                        network.set(network_config().unwrap());
                                                                        let data_dir = DATA_DIR();
                                                                        if let Network::Tor = network() {
                                                                            spawn_forever(async move {
                                                                                tokio::spawn(async move {
                                                                                    ws_conn::tor_proxy::run_tor_proxy(&data_dir, set_up_proxy).await;
                                                                                });
                                                                            });
                                                                        }
                                                                    };
                                                                    let connect = move |_| {
                                                                        let secret_mnemonic = secret_mnemonic();
                                                                        let secret_scalar = crypto::mnemonic_to_scalar(&secret_mnemonic);
                                                                        let config_new = Config {
                                                                            network: if network_is_new() { network_config() } else { None },
                                                                            server: if server_is_new() { server() } else { None },
                                                                            secret: Some(Secret::Encrypted(crypto::encrypt_secret(&secret_scalar, &passwd())))
                                                                        };
                                                                        config_new.write_config();
                                                                        let data_dir = DATA_DIR();
                                                                        let server = server().unwrap();
                                                                        *KEYS.write() = Keys::from_mnemonic(secret_mnemonic);
                                                                        let public = KEYS().public;
                                                                        spawn_forever(async move {
                                                                            tokio::spawn(async move {
                                                                                ws_conn::connection(
                                                                                    &data_dir,
                                                                                    network(),
                                                                                    server,
                                                                                    &public,
                                                                                    secret_scalar,
                                                                                    connect_to_server,
                                                                                    send_msg,
                                                                                    msg_out,
                                                                                    shared_secrets,
                                                                                    contacts,
                                                                                    change_contacts,
                                                                                    contact_choice,
                                                                                    change_chat
                                                                                ).await;
                                                                            });
                                                                        });
                                                                    };
                                                                    if start_clicked() {
                                                                        return rsx!(Connect{ onmounted_connect: connect, onmounted_to_chat: to_chat }) 
                                                                    }
                                                                    rsx!(
                                                                        SetPassword {
                                                                            passwd: passwd(),
                                                                            passwd_control: passwd_control(),
                                                                            oninput_passwd,
                                                                            oninput_passwd_control,
                                                                            network: network_config().unwrap(),
                                                                            server: server().unwrap(),
                                                                            onclick: start
                                                                        }
                                                                    )
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else {
                                                   div { class: "error", "invalid seed" }
                                                }
                                            )
                                        }
                                    } 
                                }
                            }
                        }
                    }
                }
            }
        }
    )
}
