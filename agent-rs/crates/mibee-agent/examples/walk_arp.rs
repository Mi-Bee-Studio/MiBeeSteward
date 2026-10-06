//! Walk a router's SNMP ARP table with the agent's own walker and print
//! sorted `ip=<ip> mac=<mac>` lines — the Rust side of the difftest/walkclient
//! (gosnmp) byte-diff parity check.
//!
//! Usage: walk_arp <router[:port]> [community]

use std::time::Duration;

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let router = argv.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
    let addr = mibee_agent::engine::probes::snmp_arp::router_addr(&router)
        .unwrap_or_else(|| panic!("bad router {router}"));
    let mut i = 1;
    let v3 = if argv.get(i).map(String::as_str) == Some("v3") {
        // walk_arp <router> v3 <user> <authpass> <privpass>
        i += 1;
        let user = argv.get(i).cloned().expect("v3 needs <user> <authpass> <privpass>");
        i += 1;
        let auth = argv.get(i).cloned().expect("authpass");
        i += 1;
        let privp = argv.get(i).cloned().expect("privpass");
        i += 1;
        Some(mibee_agent::engine::probes::SnmpV3Credential {
            username: user,
            security_level: "authPriv".into(),
            auth_protocol: "SHA".into(),
            auth_passphrase: auth,
            priv_protocol: "AES".into(),
            priv_passphrase: privp,
        })
    } else {
        None
    };
    let community = argv.get(i).cloned().unwrap_or_else(|| "public".to_string());
    match mibee_agent::engine::probes::snmp_arp::walk_router_arp_table(
        addr,
        &community,
        Duration::from_secs(4),
        v3.as_ref(),
    )
    .await
    {
        Ok(table) => {
            let mut keys: Vec<_> = table.keys().collect();
            keys.sort();
            for k in keys {
                println!("ip={k} mac={}", table[k]);
            }
        }
        Err(e) => {
            eprintln!("walk failed: {e}");
            std::process::exit(1);
        }
    }
}
