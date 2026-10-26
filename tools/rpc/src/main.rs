//! Command line client for the observer's NATS request/reply interface.
//!
//! Every subcommand maps onto one method in `observer/docs/rpc.md`; `call`
//! sends any method with a raw payload for the ones added later. The reply is
//! pretty-printed, and an `{"error": ...}` reply is reported on stderr with a
//! non-zero exit so the command is safe to use from scripts.

use std::process::ExitCode;
use std::time::Duration;

use common::{
    anyhow::{Context, Result, bail},
    async_nats,
    clap::{Parser, Subcommand},
    serde_json::{self, Value, json},
    tokio,
};

/// Call the p2p-observer RPC over NATS
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// The NATS server the observer is connected to
    #[arg(
        short = 'a',
        long,
        default_value = "nats://localhost:4222",
        env = "P2P_OBSERVER_NATS_URL"
    )]
    nats_url: String,

    /// The network of the observer instance to talk to, as spelled in its config
    #[arg(short, long, env = "P2P_OBSERVER_NETWORK")]
    network: String,

    /// Seconds to wait for a reply
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// Print the reply exactly as received instead of pretty-printed JSON
    #[arg(long)]
    raw: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// The address book
    #[command(subcommand)]
    Addresses(Addresses),
    /// The header tree
    #[command(subcommand)]
    Headertree(Headertree),
    /// The ban list
    #[command(subcommand)]
    Banlist(Banlist),
    /// Call any method with a raw JSON payload
    Call {
        /// The method, e.g. `addresses.info`
        method: String,
        /// The JSON payload; empty by default
        #[arg(default_value = "")]
        payload: String,
    },
}

#[derive(Subcommand, Debug)]
enum Addresses {
    /// Counts per class, plus how many attempts are in flight
    Info,
    /// Add addresses to dial, as the operator
    Add {
        /// Addresses as `ip:port`
        #[arg(required = true)]
        addrs: Vec<String>,
    },
    /// Everything stored about one address; `null` if it is unknown
    Inspect {
        /// The address as `ip:port`
        addr: String,
    },
    /// The addresses due to be dialled soonest
    Due {
        /// How many to list; the observer defaults to 20
        #[arg(short, long)]
        limit: Option<usize>,
    },
}

#[derive(Subcommand, Debug)]
enum Headertree {
    /// Chain tips of the header tree
    Tips,
}

#[derive(Subcommand, Debug)]
enum Banlist {
    /// Ban IP networks and Tor or I2P hosts, so they are never dialled
    Add {
        /// A note kept with the entry
        #[arg(long)]
        comment: Option<String>,
        /// A CIDR network; a bare IP means /32 or /128. Repeatable
        #[arg(long = "net")]
        nets: Vec<String>,
        /// An exact host, for Tor and I2P. Repeatable
        #[arg(long = "host")]
        hosts: Vec<String>,
    },
    /// All ban entries
    List,
}

/// One request: the method name and the JSON payload it is sent with.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    method: String,
    payload: String,
}

fn request(command: &Command) -> Result<Request> {
    let (method, payload) = match command {
        Command::Addresses(Addresses::Info) => ("addresses.info", String::new()),
        Command::Addresses(Addresses::Add { addrs }) => ("addresses.add", json!(addrs).to_string()),
        Command::Addresses(Addresses::Inspect { addr }) => {
            ("addresses.inspect", json!(addr).to_string())
        }
        Command::Addresses(Addresses::Due { limit }) => (
            "addresses.due",
            limit.map(|l| l.to_string()).unwrap_or_default(),
        ),
        Command::Headertree(Headertree::Tips) => ("headertree.tips", String::new()),
        Command::Banlist(Banlist::Add {
            comment,
            nets,
            hosts,
        }) => {
            if nets.is_empty() && hosts.is_empty() {
                bail!("nothing to ban: give at least one --net or --host");
            }
            let mut entry = json!({ "nets": nets, "hosts": hosts });
            if let Some(comment) = comment {
                entry["comment"] = Value::String(comment.clone());
            }
            ("banlist.add", json!([entry]).to_string())
        }
        Command::Banlist(Banlist::List) => ("banlist.list", String::new()),
        Command::Call { method, payload } => {
            return Ok(Request {
                method: method.clone(),
                payload: payload.clone(),
            });
        }
    };
    Ok(Request {
        method: method.to_owned(),
        payload,
    })
}

/// What a reply means to the exit status.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    /// Pretty-printed JSON, or the text as is when it is not JSON.
    Ok(String),
    /// The observer answered `{"error": ...}`.
    Error(String),
}

fn interpret(text: &str) -> Reply {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => {
            if let Some(error) = value.get("error").and_then(Value::as_str) {
                return Reply::Error(error.to_owned());
            }
            Reply::Ok(serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_owned()))
        }
        Err(_) => Reply::Ok(text.to_owned()),
    }
}

async fn call(cli: &Cli, req: &Request) -> Result<String> {
    let nats = async_nats::connect(&cli.nats_url)
        .await
        .with_context(|| format!("connecting to {}", cli.nats_url))?;
    let subject = format!("p2p-observer.{}.rpc.{}", cli.network, req.method);
    let reply = tokio::time::timeout(
        Duration::from_secs(cli.timeout),
        nats.request(subject.clone(), req.payload.clone().into()),
    )
    .await
    .with_context(|| {
        format!(
            "no reply on {subject} within {}s: is an observer for {} running?",
            cli.timeout, cli.network
        )
    })?
    .with_context(|| format!("request on {subject}"))?;
    Ok(String::from_utf8_lossy(&reply.payload).into_owned())
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let req = match request(&cli.command) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let text = match call(&cli, &req).await {
        Ok(text) => text,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    if cli.raw {
        println!("{text}");
        return ExitCode::SUCCESS;
    }
    match interpret(&text) {
        Reply::Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Reply::Error(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(["rpc", "--network", "signet"].iter().chain(args)).unwrap()
    }

    fn req(args: &[&str]) -> Request {
        request(&parse(args).command).unwrap()
    }

    #[test]
    fn test_requests_match_the_rpc_doc() {
        assert_eq!(
            req(&["addresses", "info"]),
            Request {
                method: "addresses.info".into(),
                payload: String::new()
            }
        );
        assert_eq!(
            req(&["addresses", "add", "1.2.3.4:8333", "nonsense"]).payload,
            r#"["1.2.3.4:8333","nonsense"]"#
        );
        // A JSON string, quotes included, as the observer expects.
        assert_eq!(
            req(&["addresses", "inspect", "1.2.3.4:38333"]).payload,
            r#""1.2.3.4:38333""#
        );
        assert_eq!(req(&["addresses", "due"]).payload, "");
        assert_eq!(req(&["addresses", "due", "--limit", "5"]).payload, "5");
        assert_eq!(req(&["headertree", "tips"]).method, "headertree.tips");
        assert_eq!(req(&["banlist", "list"]).method, "banlist.list");
    }

    #[test]
    fn test_banlist_add_builds_one_entry() {
        let r = req(&[
            "banlist",
            "add",
            "--comment",
            "spammy node",
            "--net",
            "1.2.3.4/32",
            "--net",
            "10.0.0.0/8",
            "--host",
            "abc.onion:8333",
        ]);
        assert_eq!(r.method, "banlist.add");
        let v: Value = serde_json::from_str(&r.payload).unwrap();
        assert_eq!(v[0]["comment"], "spammy node");
        assert_eq!(v[0]["nets"], json!(["1.2.3.4/32", "10.0.0.0/8"]));
        assert_eq!(v[0]["hosts"], json!(["abc.onion:8333"]));

        // No comment given: none sent, so the observer's default applies.
        let v: Value =
            serde_json::from_str(&req(&["banlist", "add", "--net", "1.2.3.4"]).payload).unwrap();
        assert!(v[0].get("comment").is_none());
    }

    #[test]
    fn test_banlist_add_needs_something_to_ban() {
        let cli = parse(&["banlist", "add", "--comment", "x"]);
        assert!(request(&cli.command).is_err());
    }

    #[test]
    fn test_call_passes_the_payload_through() {
        assert_eq!(
            req(&["call", "addresses.due", "3"]),
            Request {
                method: "addresses.due".into(),
                payload: "3".into()
            }
        );
        assert_eq!(req(&["call", "headertree.tips"]).payload, "");
    }

    #[test]
    fn test_replies() {
        assert_eq!(
            interpret(r#"{"error":"unknown method: x"}"#),
            Reply::Error("unknown method: x".into())
        );
        assert_eq!(interpret("null"), Reply::Ok("null".into()));
        assert_eq!(
            interpret(r#"{"b":1,"a":2}"#),
            Reply::Ok("{\n  \"a\": 2,\n  \"b\": 1\n}".into())
        );
        // Not JSON at all is printed as received rather than hidden.
        assert_eq!(interpret("plain"), Reply::Ok("plain".into()));
    }

    #[test]
    fn test_network_is_required() {
        assert!(Cli::try_parse_from(["rpc", "addresses", "info"]).is_err());
    }
}
