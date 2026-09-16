//! The one live run of the whole transport stack, TLS included: three
//! reads against a Mesh endpoint through `MeshClient<UreqTransport>`, read
//! only, no submit path at all (a probe that can broadcast is a footgun).
//!
//! Run by hand; nothing in the board touches the network. Its output for
//! `api.mochimo.org` at the block it ran is the transport's only TLS evidence
//! until a session runs it again; nothing in this repository records it.
//!
//!     cargo run -p mochimo-crypto --features mesh-https --example mesh_probe -- \
//!         https://api.mochimo.org 0x9f810c2447a76e93b17ebff96c0b29952e4355f1
//!
//! Prints what the endpoint answered and which class of failure it hit;
//! exits non-zero on any failure so a script can read it.

use std::process::ExitCode;

use mochimo_crypto::mesh::http::UreqTransport;
use mochimo_crypto::mesh::{hex, MeshClient};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(base), Some(tag_hex)) = (args.next(), args.next()) else {
        eprintln!("usage: mesh_probe <base-url> <0x-prefixed 20-byte tag>");
        return ExitCode::from(2);
    };
    let tag = match hex::decode_prefixed::<20>(&tag_hex, "tag") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tag: {e}");
            return ExitCode::from(2);
        }
    };
    let transport = match UreqTransport::new(&base) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("transport: {e}");
            return ExitCode::from(1);
        }
    };
    println!("mesh_probe: {} (mesh-https {})", transport.base(), if cfg!(feature = "mesh-https") { "on" } else { "off" });
    let client = MeshClient::new(transport);
    let mut failed = false;

    match client.network_status() {
        Ok(tip) => println!("  /network/status: block {} hash 0x{}", tip.index, hex::encode(&tip.hash)),
        Err(e) => {
            failed = true;
            println!("  /network/status: FAILED: {e}");
        }
    }
    match client.resolve_tag(&tag) {
        Ok(entry) => println!(
            "  /call tag_resolve: address 0x{} balance {} nanoMCM",
            hex::encode(&entry.address),
            entry.balance
        ),
        Err(e) => {
            failed = true;
            println!("  /call tag_resolve: FAILED: {e}");
        }
    }
    match client.balance(&tag) {
        Ok(at) => println!(
            "  /account/balance: {} nanoMCM at block {} hash 0x{}",
            at.balance,
            at.tip.index,
            hex::encode(&at.tip.hash)
        ),
        Err(e) => {
            failed = true;
            println!("  /account/balance: FAILED: {e}");
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
