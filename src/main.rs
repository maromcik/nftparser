mod error;

use crate::error::AppError;
use crate::error::AppError::ProcessError;
use clap::{Parser, ValueEnum};
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

    #[clap(
        short = 'u',
        long,
        value_name = "UNIQUE_BY_FIELDS",
        value_delimiter = ','
    )]
    unique: Vec<Field>,

    #[clap(last = true, value_name = "COMMAND", required=true, num_args(1..), value_delimiter = ' ')]
    command: Vec<String>,

    #[arg(short = 'c', action = clap::ArgAction::SetTrue)]
    pub conntrack: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Hash)]
enum Field {
    Iif,
    Oif,
    Saddr,
    Daddr,
    Sport,
    Dport,
    Proto,
}

#[derive(Debug, Default)]
struct LogEntry {
    iif: Option<String>,    // IN
    oif: Option<String>,    // OUT
    src_ip: Option<IpAddr>, // SRC
    dst_ip: Option<IpAddr>, // DST
    src_port: Option<u16>,  // SPT
    dst_port: Option<u16>,  // DPT
    proto: Option<String>,  // PROTO
}

impl LogEntry {
    fn key(&self, fields: &HashSet<Field>) -> LogKey {
        if fields.is_empty() {
            return LogKey::from(self);
        };
        LogKey {
            iif: if fields.contains(&Field::Iif) {
                self.iif.clone()
            } else {
                None
            },
            oif: if fields.contains(&Field::Oif) {
                self.oif.clone()
            } else {
                None
            },
            src_ip: if fields.contains(&Field::Saddr) {
                self.src_ip
            } else {
                None
            },
            dst_ip: if fields.contains(&Field::Daddr) {
                self.dst_ip
            } else {
                None
            },
            src_port: if fields.contains(&Field::Sport) {
                self.src_port
            } else {
                None
            },
            dst_port: if fields.contains(&Field::Dport) {
                self.dst_port
            } else {
                None
            },
            proto: if fields.contains(&Field::Proto) {
                self.proto.clone()
            } else {
                None
            },
        }
    }
}

#[derive(Debug, Default, Hash, Eq, PartialEq, Clone)]
struct LogKey {
    iif: Option<String>,    // IN
    oif: Option<String>,    // OUT
    src_ip: Option<IpAddr>, // SRC
    dst_ip: Option<IpAddr>, // DST
    src_port: Option<u16>,  // SPT
    dst_port: Option<u16>,  // DPT
    proto: Option<String>,  // PROTO
}

impl From<&LogEntry> for LogKey {
    fn from(entry: &LogEntry) -> Self {
        LogKey {
            iif: entry.iif.clone(),
            oif: entry.oif.clone(),
            src_ip: entry.src_ip,
            dst_ip: entry.dst_ip,
            src_port: entry.src_port,
            dst_port: entry.dst_port,
            proto: entry.proto.clone(),
        }
    }
}

impl LogEntry {
    pub fn to_nftables_rule(
        &self,
        action: &Option<String>,
        fields: &HashSet<Field>,
        conntrack: bool,
    ) -> String {
        let mut parts = Vec::new();

        if let Some(iif) = &self.iif
            && (fields.contains(&Field::Iif) || fields.is_empty())
        {
            parts.push(format!("iifname \"{}\"", iif));
        }

        if let Some(oif) = &self.oif
            && (fields.contains(&Field::Oif) || fields.is_empty())
        {
            parts.push(format!("oifname \"{}\"", oif));
        }

        if let Some(src_ip) = &self.src_ip
            && (fields.contains(&Field::Saddr) || fields.is_empty())
        {
            if conntrack {
                parts.push("ct original".to_string());
            }
            match src_ip {
                IpAddr::V4(_) => parts.push(format!("ip saddr {}", src_ip)),
                IpAddr::V6(_) => parts.push(format!("ip6 saddr {}", src_ip)),
            }
        }

        if let Some(dst_ip) = &self.dst_ip
            && (fields.contains(&Field::Daddr) || fields.is_empty())
        {
            if conntrack {
                parts.push("ct original".to_string());
            }
            match dst_ip {
                IpAddr::V4(_) => parts.push(format!("ip daddr {}", dst_ip)),
                IpAddr::V6(_) => parts.push(format!("ip6 daddr {}", dst_ip)),
            }
        }

        if let (Some(proto), Some(src_port)) = (&self.proto, &self.src_port)
            && (fields.contains(&Field::Sport) || fields.is_empty())
        {
            if conntrack {
                parts.push(format!(
                    "meta l4proto {} ct original proto-src {}",
                    proto.to_lowercase(),
                    src_port
                ));
            } else {
                parts.push(format!("{} sport {}", proto.to_lowercase(), src_port));
            }
        }

        if let (Some(proto), Some(dst_port)) = (&self.proto, &self.dst_port)
            && (fields.contains(&Field::Dport) || fields.is_empty())
        {
            if conntrack {
                parts.push(format!(
                    "meta l4proto {} ct original proto-dst {}",
                    proto.to_lowercase(),
                    dst_port
                ));
            } else {
                parts.push(format!("{} dport {}", proto.to_lowercase(), dst_port));
            }
        } else if let Some(proto) = &self.proto
            && (fields.contains(&Field::Proto) || fields.is_empty())
        {
            parts.push(format!("meta l4proto {}", proto.to_lowercase()));
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
        src_port: None,
        dst_port: None,
        proto: None,
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

fn output_rules(
    rules: &Vec<LogEntry>,
    action: &Option<String>,
    fields: &HashSet<Field>,
    conntrack: bool,
) {
    for rule in rules {
        println!("{}", rule.to_nftables_rule(action, fields, conntrack));
    }
}

fn main() -> Result<(), error::AppError> {
    let cli = Cli::parse();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let mut seen: HashSet<LogKey> = HashSet::new();
    let mut unique_entries: Vec<LogEntry> = Vec::new();

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
    let unique_fields: HashSet<Field> = HashSet::from_iter(cli.unique);
    for line in reader.lines() {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match line {
            Ok(line) => {
                if !regex.is_match(&line) {
                    continue;
                }
                println!("{}", line);
                if let Some(entry) = parse_log_line(&line)? {
                    let key = entry.key(&unique_fields);
                    if seen.insert(key) {
                        unique_entries.push(entry);
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
        "\n\n========Aggregated Rules ({} unique)========\n",
        unique_entries.len()
    );
    output_rules(&unique_entries, &cli.action, &unique_fields, false);
    if cli.conntrack {
        println!("\n\n========CONNTRACK========\n",);
        output_rules(&unique_entries, &cli.action, &unique_fields, true);
    }

    Ok(())
}
