use dioxus::prelude::*;
use dioxus_router::prelude::*;
use dioxus_clipboard::hooks::use_clipboard;
use serde::Deserialize;
use sqlx::{SqlitePool, FromRow};

use crate::{ChangeChat, ChangeContacts, Contact, ContactChoice, Content, KeyChoice, MsgOut, Public, Route};
use crate::{DB_URL, KEY_CHOICE, COPY};

#[derive(PartialEq, Deserialize)]
enum Kind {
    In,
    Out,
}

#[derive(PartialEq, Deserialize)]
struct Msg {
    kind: Kind,
    public: String,
    message: String,
}

#[derive(Clone, FromRow, Debug)]
struct MsgDbTable {
    kind: u8,
    message: String,
    time: String
}

#[component]
pub fn Chat() -> Element {
    let navigator = use_navigator();
    let mut contact_choice: SyncSignal<ContactChoice> = use_context();
    let mut contacts: SyncSignal<Vec<Contact>> = use_context();
    let mut clipboard = use_clipboard();
    let change_contacts: SyncSignal<ChangeContacts> = use_context();
    let mut msg_out: SyncSignal<MsgOut> = use_context();
    let mut send_msg: SyncSignal<bool> = use_context();
    let _ = use_resource(move || async move {
        change_contacts();
        let db = SqlitePool::connect(&DB_URL()).await.unwrap();
        let sql = (r#"SELECT * FROM contacts;"#).to_string();
        let vec = sqlx::query_as::<_, Contact>(&sql).fetch_all(&db).await.unwrap_or_default();
        contacts.set(vec);
    });
    let mut message = use_signal(String::new);
    let change_chat: SyncSignal<ChangeChat> = use_context();
    let mut chat_vec = use_signal_sync(Vec::new);
    let _ = use_resource(move || async move {
        change_chat();
        if let ContactChoice::Public(public) = contact_choice() {
            let db = SqlitePool::connect(&DB_URL()).await.unwrap();
            let sql = format!(r#"SELECT * FROM x{};"#, &public);
            let vec = sqlx::query_as::<_, MsgDbTable>(&sql).fetch_all(&db).await.unwrap_or_default();
            chat_vec.set(vec);           
        }
    });
    let mut check_public = use_signal(|| false);
    let mut message_add = use_signal(String::new);
    let mut public_add = use_signal(String::new);
    rsx!(
        div {
            class: "row",
            div {
                class: "column_left",
                div {
                    class: "contacts",
                    {
                    contacts()
                        .iter()
                        .map(|i| 
                            rsx!(
                                div {
                                    class: "contact_container",
                                    button {
                                        class: "contact",
                                        class: if contact_choice() == ContactChoice::Public(i.public.clone()) { "contact_active" },
                                        onclick: {
                                            let public = i.public.clone();
                                            move |_| contact_choice.set(ContactChoice::Public(public.clone()))
                                        },
                                        "{i.public}" 
                                    },
                                    if contact_choice() == ContactChoice::Public(i.public.clone()) {
                                        button { 
                                            class: "copy",
                                            onclick: {
                                                let public = i.public.clone();
                                                move |_| { let _ = clipboard.set(public.clone()); }
                                            },
                                            img { src: COPY, draggable: "false", alt: "copy" },
                                        }
                                    }
                                }
                            )
                        )
                    } 
                },
                div {
                    class: "fixed",
                    button {
                        class: "add_chat_button",
                        onclick: move |_| {
                            contact_choice.set(ContactChoice::Add);
                        },
                        "add new chat"
                    },
                    a {
                        class: "link",
                        onclick: move |_| {
                            *KEY_CHOICE.write() = KeyChoice::Public;
                            navigator.push(Route::Key {});
                        },
                        "public key"
                    },
                    span {
                        class: "mid",
                        "|"
                    },
                    a {
                        class: "link",
                        onclick: move |_| {
                            *KEY_CHOICE.write() = KeyChoice::Seed;
                            navigator.push(Route::Key {});
                        },
                        "recovery seed"
                    }
                }
            }    
            div {
                class: "column_right",
                match contact_choice() {
                    ContactChoice::None => {
                        rsx!(div { class: "text", "choose a contact or add a new chat" })
                    }, 
                    ContactChoice::Public(public) => {
                        rsx!(div { 
                            class: "chat",
                            {
                                chat_vec()
                                    .iter()
                                    .rev()
                                    .map(|i: &MsgDbTable| match i.kind {
                                        0 => {
                                            rsx!(
                                                div {
                                                    class: "msg_in_container",
                                                    pre { class: "msg_in", {i.message.clone()} }
                                                    div { class: "time", {i.time.clone()} }
                                                }
                                            )
                                        },
                                        _ => {
                                            rsx!(
                                                div {
                                                    class: "msg_out_container",
                                                    pre { class: "msg_out", {i.message.clone()} }
                                                    div { class: "time", {i.time.clone()} }
                                                }
                                            )
                                        } 
                                    }
                                )
                            }
                        }
                        div {
                            class: "chat_element",
                            textarea {
                                placeholder: "your message...",
                                value: "{message}",
                                oninput: move |event| {
                                    message.set(event.value().clone());
                                }
                            }
                            button {
                                onclick: move |_| {
                                    if !message().is_empty() {
                                        msg_out.set(MsgOut::Chat(Public(public.clone()), Content(message())));
                                        send_msg.set(true);
                                        message.set(String::new());
                                    }
                                },
                                ">>"
                            },
                        })
                    },
                    ContactChoice::Add => {
                        rsx!(
                            div {class: "text", "public key of the receiver"},
                            textarea {
                                class: "text_field",
                                value: "",
                                oninput: move |event| {
                                    public_add.set(event.value().clone());
                                    check_public.set(crypto::check_public(&public_add()));
                                }
                            },
                            if check_public() {
                                div {
                                    div {class: "text", "your message"},
                                    textarea {
                                        class: "text_field",
                                        oninput: move |event| {
                                            message_add.set(event.value().clone())
                                        }
                                    },
                                    button {
                                        class: "button",
                                        onclick: move |_| {
                                            if !message_add().is_empty() {
                                                msg_out.set(MsgOut::AddContact(Public(public_add()), Content(message_add())));
                                                send_msg.set(true);
                                            }
                                        },
                                        "send"
                                    }
                                }
                            } else {
                                div { class: "error", "invalid public key" }
                            }
                        )  
                    }
                }
            }
        }
    )
}
