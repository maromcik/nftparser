mod error;

use crate::error::AppError;
use crate::error::AppError::ProcessError;
use clap::Parser;
use regex::Regex;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short = 'p', long, value_name = "PATTERN")]
    pattern: Option<String>,

    #[clap(short = 'a', long, value_name = "ACTION")]
    action: Option<String>,

    #[clap(last = true, value_name = "COMMAND", required=true, num_args(1..), value_delimiter = ' ')]
    command: Vec<String>,
}

#[derive(Debug, Default)]
pub struct LogEntry {
    pub iif: Option<String>,     // IN
    pub oif: Option<String>,     // OUT
    pub src_ip: Option<IpAddr>,  // SRC
    pub dst_ip: Option<IpAddr>,  // DST
    pub src_mac: Option<String>, // MACSRC
    pub dst_mac: Option<String>, // MACDST
    pub src_port: Option<u16>,   // SPT
    pub dst_port: Option<u16>,   // DPT
    pub proto: Option<String>,   // PROTO
    pub uid: Option<u32>,        // UID
    pub gid: Option<u32>,        // GID
}

impl std::hash::Hash for LogEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.iif.hash(state);
        self.oif.hash(state);
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
        self.proto.hash(state);
    }
}

impl PartialEq for LogEntry {
    fn eq(&self, other: &Self) -> bool {
        self.iif == other.iif
            && self.oif == other.oif
            && self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
            && self.proto == other.proto
    }
}

impl Eq for LogEntry {}

impl LogEntry {
    pub fn to_nftables_rule(&self, action: &Option<String>) -> String {
        let mut parts = Vec::new();

        if let Some(iif) = &self.iif {
            parts.push(format!("iifname \"{}\"", iif));
        }

        if let Some(oif) = &self.oif {
            parts.push(format!("oifname \"{}\"", oif));
        }

        if let Some(src_ip) = &self.src_ip {
            match src_ip {
                IpAddr::V4(_) => parts.push(format!("ip saddr {}", src_ip)),
                IpAddr::V6(_) => parts.push(format!("ip6 saddr {}", src_ip)),
            }
        }

        if let Some(dst_ip) = &self.dst_ip {
            match dst_ip {
                IpAddr::V4(_) => parts.push(format!("ip daddr {}", dst_ip)),
                IpAddr::V6(_) => parts.push(format!("ip6 daddr {}", dst_ip)),
            }
        }

        if let (Some(proto), Some(src_port)) = (&self.proto, &self.src_port) {
            parts.push(format!("{} sport {}", proto.to_lowercase(), src_port));
        }

        if let (Some(proto), Some(dst_port)) = (&self.proto, &self.dst_port) {
            parts.push(format!("{} dport {}", proto.to_lowercase(), dst_port));
        } else if let Some(proto) = &self.proto {
            parts.push(format!("meta l4proto {}", proto.to_lowercase()));
        }

        if let Some(uid) = &self.uid {
            parts.push(format!("meta skuid {}", uid));
        }

        if let Some(gid) = &self.gid {
            parts.push(format!("meta skgid {}", gid));
        }
        parts.push("counter".to_string());
        if let Some(action) = action {
            parts.push(action.clone());
        }
        parts.join(" ")
    }
}

fn parse_log_line(line: &str) -> Result<Option<LogEntry>, AppError> {
    type FieldSetter = Box<dyn Fn(&regex::Captures, &mut LogEntry)>;

    let patterns: Vec<(&str, FieldSetter)> = vec![
        (
            r"IN=([^\s]+)",
            Box::new(|cap: &regex::Captures, entry: &mut LogEntry| {
                entry.iif = Some(cap[1].to_string());
            }),
        ),
        (
            r" OUT=([^\s]+)",
            Box::new(|cap: &regex::Captures, entry: &mut LogEntry| {
                entry.oif = Some(cap[1].to_string());
            }),
        ),
        (
            r" SRC=([^\s]+)",
            Box::new(|cap: &regex::Captures, entry: &mut LogEntry| {
                if let Ok(ip) = cap[1].parse::<IpAddr>() {
                    entry.src_ip = Some(ip);
                }
            }),
        ),
        (
            r" DST=([^\s]+)",
            Box::new(|cap: &regex::Captures, entry: &mut LogEntry| {
                if let Ok(ip) = cap[1].parse::<IpAddr>() {
                    entry.dst_ip = Some(ip);
                }
            }),
        ),
        (
            r" SPT=(\d+)",
            Box::new(|cap: &regex::Captures, entry: &mut LogEntry| {
                if let Ok(port) = cap[1].parse::<u16>() {
                    entry.src_port = Some(port);
                }
            }),
        ),
        (
            r" DPT=(\d+)",
            Box::new(|cap: &regex::Captures, entry: &mut LogEntry| {
                if let Ok(port) = cap[1].parse::<u16>() {
                    entry.dst_port = Some(port);
                }
            }),
        ),
        (
            r" PROTO=([^\s]+)",
            Box::new(|cap: &regex::Captures, entry: &mut LogEntry| {
                entry.proto = Some(cap[1].to_string());
            }),
        ),
    ];

    let mut entry = LogEntry {
        iif: None,
        oif: None,
        src_ip: None,
        dst_ip: None,
        src_mac: None,
        dst_mac: None,
        src_port: None,
        dst_port: None,
        proto: None,
        uid: None,
        gid: None,
    };

    for (pattern, setter) in patterns {
        let re = Regex::new(pattern)?;
        if let Some(caps) = re.captures(line) {
            setter(&caps, &mut entry);
        }
    }

    if entry.iif.is_some()
        || entry.oif.is_some()
        || entry.src_ip.is_some()
        || entry.dst_ip.is_some()
        || entry.src_port.is_some()
        || entry.dst_port.is_some()
    {
        Ok(Some(entry))
    } else {
        Ok(None)
    }
}

fn output_rules(rules: &HashSet<LogEntry>, action: Option<String>) {
    for rule in rules {
        println!("{}", rule.to_nftables_rule(&action));
    }
}

fn main() -> Result<(), error::AppError> {
    let cli = Cli::parse();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let mut aggregated_rules: HashSet<LogEntry> = HashSet::new();

    println!("Press Ctrl+C to exit and output aggregated rules...\n");
    println!("Running command: {:?}", cli.command);
    let (program, args) = cli
        .command
        .split_first()
        .ok_or_else(|| ProcessError("No command provided".to_string()))?;
    let mut child = Command::new(program)
        .args(args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::IOError("Failed to capture stdout".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::IOError("Failed to capture stdout".to_string()))?;
    let reader = BufReader::new(stdout).chain(BufReader::new(stderr));

    let regex = Regex::new(cli.pattern.as_deref().unwrap_or(".*"))?;

    for line in reader.lines() {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match line {
            Ok(line) => {
                if regex.is_match(&line) {
                    if let Some(entry) = parse_log_line(&line)? {
                        aggregated_rules.insert(entry);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error the reading command output: {}", e);
                break;
            }
        }
    }

    println!(
        "\n\n=== Aggregated Rules ({} unique) ===\n",
        aggregated_rules.len()
    );
    output_rules(&aggregated_rules, cli.action);
    Ok(())
}
