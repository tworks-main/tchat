use dioxus::prelude::*;
use dioxus_router::prelude::*;
use dioxus_clipboard::hooks::use_clipboard;
use crate::Route;
use crate::{KEY_CHOICE, KEYS, COPY};

#[derive(Clone)]
pub enum KeyChoice {
    Seed,
    Public
}

#[component]
pub fn Key() -> Element {
    let navigator = use_navigator();
    let mut clipboard = use_clipboard();
    let key = use_signal(|| match KEY_CHOICE() {
        KeyChoice::Seed => KEYS().seed,
        KeyChoice::Public => KEYS().public
    });
    rsx!(
        div {
            class: "text",
            match KEY_CHOICE() {
                KeyChoice::Seed => "your recovery seed",
                KeyChoice::Public => "your public key"
            }
        },
        div {
            class: "key_container",
            div {
                class: "key",
                {key()}
            },
            button { 
                class: "copy",
                onclick: move |_| {
                    let _ = clipboard.set(key());
                },
                img { src: COPY, draggable: "false", alt: "copy" },
            }
        }
        a {
            class: "link",
            onclick: move |_| {
                navigator.push(Route::Chat {});
            },
            "back"
        }
    )
}
