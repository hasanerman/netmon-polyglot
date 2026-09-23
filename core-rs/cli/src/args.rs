use std::fmt;
use std::path::PathBuf;

use netcore_engine::synth::Scenario;

pub const DEFAULT_GEN_PACKETS: usize = 100_000;
pub const DEFAULT_SEED: u64 = 7;
pub const DEFAULT_TOP: usize = 10;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Gen {
        scenario: Scenario,
        out: PathBuf,
        packets: usize,
        seed: u64,
    },
    Replay {
        file: PathBuf,
        top: usize,
        rules: RulesChoice,
    },
    Help,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RulesChoice {
    Builtin,
    File(PathBuf),
    Off,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ArgError(pub String);

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub const USAGE: &str = "\
usage:
  netmon gen <mixed|portscan|dnstunnel|flood> <out.pcap> [--packets N] [--seed S]
  netmon replay <file.pcap> [--top N] [--rules rules.yaml | --no-rules]
  netmon help";

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Command, ArgError> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        None | Some("help" | "-h" | "--help") => Ok(Command::Help),
        Some("gen") => parse_gen(args),
        Some("replay") => parse_replay(args),
        Some(other) => Err(ArgError(format!("unknown command '{other}'"))),
    }
}

fn parse_gen(mut args: impl Iterator<Item = String>) -> Result<Command, ArgError> {
    let name = args.next().ok_or_else(|| ArgError("gen: missing scenario".into()))?;
    let scenario =
        Scenario::from_name(&name).ok_or_else(|| ArgError(format!("gen: unknown scenario '{name}'")))?;
    let out = PathBuf::from(args.next().ok_or_else(|| ArgError("gen: missing output path".into()))?);
    let mut packets = DEFAULT_GEN_PACKETS;
    let mut seed = DEFAULT_SEED;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--packets" => packets = number(&flag, args.next())?,
            "--seed" => seed = number(&flag, args.next())?,
            _ => return Err(ArgError(format!("gen: unknown option '{flag}'"))),
        }
    }
    Ok(Command::Gen {
        scenario,
        out,
        packets,
        seed,
    })
}

fn parse_replay(mut args: impl Iterator<Item = String>) -> Result<Command, ArgError> {
    let file = PathBuf::from(args.next().ok_or_else(|| ArgError("replay: missing pcap path".into()))?);
    let mut top = DEFAULT_TOP;
    let mut rules = RulesChoice::Builtin;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--top" => top = number(&flag, args.next())?,
            "--no-rules" => rules = RulesChoice::Off,
            "--rules" => {
                let path = args.next().ok_or_else(|| ArgError("--rules: missing path".into()))?;
                rules = RulesChoice::File(PathBuf::from(path));
            }
            _ => return Err(ArgError(format!("replay: unknown option '{flag}'"))),
        }
    }
    Ok(Command::Replay { file, top, rules })
}

fn number<T: std::str::FromStr>(flag: &str, value: Option<String>) -> Result<T, ArgError> {
    let value = value.ok_or_else(|| ArgError(format!("{flag}: missing value")))?;
    value
        .parse()
        .map_err(|_| ArgError(format!("{flag}: '{value}' is not a valid number")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(line: &str) -> Result<Command, ArgError> {
        parse(line.split_whitespace().map(String::from))
    }

    #[test]
    fn empty_is_help() {
        assert_eq!(run(""), Ok(Command::Help));
    }

    #[test]
    fn gen_with_options() {
        assert_eq!(
            run("gen portscan out.pcap --packets 500 --seed 3"),
            Ok(Command::Gen {
                scenario: Scenario::PortScan,
                out: PathBuf::from("out.pcap"),
                packets: 500,
                seed: 3,
            })
        );
    }

    #[test]
    fn replay_defaults() {
        assert_eq!(
            run("replay a.pcap"),
            Ok(Command::Replay {
                file: PathBuf::from("a.pcap"),
                top: DEFAULT_TOP,
                rules: RulesChoice::Builtin,
            })
        );
    }

    #[test]
    fn replay_rule_options() {
        let Ok(Command::Replay { rules, .. }) = run("replay a.pcap --rules r.yaml") else { panic!() };
        assert_eq!(rules, RulesChoice::File(PathBuf::from("r.yaml")));
        let Ok(Command::Replay { rules, .. }) = run("replay a.pcap --no-rules") else { panic!() };
        assert_eq!(rules, RulesChoice::Off);
        assert!(run("replay a.pcap --rules").is_err());
    }

    #[test]
    fn rejects_bad_number() {
        assert!(run("replay a.pcap --top ten").is_err());
    }

    #[test]
    fn rejects_unknown_scenario() {
        assert!(run("gen ddos out.pcap").is_err());
    }
}
