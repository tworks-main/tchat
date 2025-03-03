use dioxus::logger::tracing::Level;
use dioxus::prelude::*;
use dioxus_router::prelude::*;
use dioxus::desktop::{use_window, Config, LogicalSize, WindowBuilder};
use sqlx::FromRow;
use std::{env, fs};
use std::collections::HashMap;
use crypto::{self, Keys};
use components::chat::Chat;
use components::config::{Configuration, Network};
use components::key::{Key, KeyChoice};

mod components;
mod ws_conn;

const STYLE: &str = include_str!("../src/style/style.css");
const COPY: &str = include_str!("../src/style/copy");

static DATA_DIR: GlobalSignal<String> = Signal::global(|| {
    let home_dir = env::home_dir().unwrap();
    let home_dir = home_dir.to_str().unwrap();
    let path = format!("{}/.config/tchat", home_dir);
    let _ = fs::create_dir(&path);
    path
});
static DB_URL: GlobalSignal<String> = Signal::global(|| format!("{}/client.db", DATA_DIR));
static KEYS: GlobalSignal<Keys> = Signal::global(Keys::empty);
static KEY_CHOICE: GlobalSignal<KeyChoice> = Signal::global(|| KeyChoice::Public);

#[rustfmt::skip]
#[derive(Clone, Debug, PartialEq, Routable)]
enum Route {
    #[route("/")]
    Configuration {},

    #[route("/contacts")]
    Chat {},

    #[route("/key")]
    Key {}
}

#[derive(PartialEq, Clone)]
struct SetUpProxy(bool);

#[derive(PartialEq, Clone)]
struct ConnectToServer(bool);

#[derive(PartialEq, Clone)]
struct Public(String);

#[derive(PartialEq, Clone)]
struct Content(String);

#[derive(PartialEq, Clone)]
enum MsgOut {
    Chat(Public, Content),
    AddContact(Public, Content),
    Close,
}

#[derive(Clone, FromRow, Debug, PartialEq)]
struct Contact {
    pub public: String
}

#[derive(PartialEq, Clone)]
struct ChangeContacts(bool);

#[derive(PartialEq, Clone)]
enum ContactChoice {
    None,
    Add,
    Public(String),
}

#[derive(PartialEq, Clone)]
struct ChangeChat(bool);

#[component]
fn App() -> Element {
    use_context_provider(|| SyncSignal::new_maybe_sync(Network::Tor));
    use_context_provider(|| SyncSignal::new_maybe_sync(SetUpProxy(false)));
    use_context_provider(|| SyncSignal::new_maybe_sync(ConnectToServer(false)));
    use_context_provider(|| SyncSignal::new_maybe_sync(false));
    use_context_provider(|| SyncSignal::new_maybe_sync(MsgOut::Close));
    use_context_provider(|| SyncSignal::new_maybe_sync(HashMap::<String, [u8; 32]>::new()));
    use_context_provider(|| SyncSignal::new_maybe_sync(Vec::<Contact>::new()));
    use_context_provider(|| SyncSignal::new_maybe_sync(ChangeContacts(true)));
    use_context_provider(|| SyncSignal::new_maybe_sync(ContactChoice::None));
    use_context_provider(|| SyncSignal::new_maybe_sync(ChangeChat(true)));
    let connect_to_server: SyncSignal<ConnectToServer> = use_context();
    let mut msg_out: SyncSignal<MsgOut> = use_context();
    let mut send_msg: SyncSignal<bool> = use_context();
    let window = use_window();
    rsx!(style{ { STYLE } },
        div {
            class: "title_bar",
            span {
                class: "drag_area",
                onmousedown: move |_| {
                    window.drag();
                }
            }
            button {
                class: "close_button",
                onclick: move |_| {
                    if connect_to_server() == ConnectToServer(true) { 
                        msg_out.set(MsgOut::Close);
                        send_msg.set(true);
                    } else {
                        std::process::exit(0);
                    }
                },
                "X" 
            },
        }
        Router::<Route> {}
    )
}

fn main() {
    dioxus::logger::init(Level::ERROR).expect("logger failed to init");
    LaunchBuilder::desktop()
        .with_cfg(Config::new()
            .with_menu(None)
            .with_disable_context_menu(true)
            .with_window(WindowBuilder::new()
                .with_decorations(false)
                .with_resizable(false)
                .with_title("tchat")
                .with_closable(false)
                .with_inner_size(LogicalSize::new(1100.0, 700.0))))
                //.with_min_inner_size(LogicalSize::new(600.0, 400.0))))
        .launch(App);
}
