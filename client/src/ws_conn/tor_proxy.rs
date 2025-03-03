//use anyhow::Result;
use dioxus_signals::{SyncSignal, Writable};

use crate::SetUpProxy;

pub async fn run_tor_proxy(data_dir: &str, mut set_up_proxy: SyncSignal<SetUpProxy>) {
    let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
    let path_state = format!("{}/tor/state/", data_dir);
    let path_cache = format!("{}/tor/cache", data_dir);
    let path_state = std::path::Path::new(&path_state);
    let path_cache = std::path::Path::new(&path_cache);
    let config = arti_client::config::TorClientConfigBuilder::from_directories(path_state, path_cache); 
    let config = config.build().unwrap();
    let tor_client = arti_client::TorClient::create_bootstrapped(config).await.unwrap();
    let port: u16 = 9050;
    let listen = tor_config::Listen::new_localhost(port);
    set_up_proxy.set(SetUpProxy(true));
    println!("run tor proxy");
    arti::socks::run_socks_proxy(runtime, tor_client, listen).await.unwrap();
}
