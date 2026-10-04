use std::env;
use std::path::PathBuf;

use nightfall_node_kit::{run_checks, NodeKitConfig};

fn main() {
    let mut datadir = default_datadir();
    let mut network = "mainnet".to_string();
    let mut rpc_bind: Option<String> = None;
    let mut json = false;
    let mut strict = false;
    let mut fail_on_warn = false;

    let mut args = env::args().skip(1).peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--datadir" => {
                let Some(value) = args.next() else {
                    eprintln!("missing value for --datadir");
                    std::process::exit(64);
                };
                datadir = PathBuf::from(value);
            }
            "--network" => {
                let Some(value) = args.next() else {
                    eprintln!("missing value for --network");
                    std::process::exit(64);
                };
                network = value;
            }
            "--rpc-bind" => {
                let Some(value) = args.next() else {
                    eprintln!("missing value for --rpc-bind");
                    std::process::exit(64);
                };
                rpc_bind = Some(value);
            }
            "--json" => json = true,
            "--strict" => strict = true,
            "--fail-on-warn" => fail_on_warn = true,
            "-h" | "--help" => {
                print_help();
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                std::process::exit(64);
            }
        }
    }

    let config = NodeKitConfig {
        datadir,
        network,
        rpc_bind,
        strict,
    };

    let report = run_checks(&config);

    if json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.to_text());
    }

    let exit_code = report.exit_code(fail_on_warn);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

fn default_datadir() -> PathBuf {
    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join("nightfall-mainnet");
    }

    PathBuf::from("nightfall-mainnet")
}

fn print_help() {
    println!(
        "nightfall-node-kit\n\
         \n\
         Usage:\n\
           nightfall-node-kit [--datadir PATH] [--network mainnet|testnet|devnet] [--rpc-bind ADDR] [--json] [--strict] [--fail-on-warn]\n\
         \n\
         This tool is read-only. It does not read seed contents, does not mutate the datadir, and does not change consensus behavior."
    );
}
