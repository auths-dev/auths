// CLI is the presentation boundary — printing and exit are expected here.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]
use anyhow::Result;
use clap::{CommandFactory, Parser};

use auths_cli::cli::{AuthsCli, RootCommand};
use auths_cli::commands::executable::ExecutableCommand;

use auths_cli::factories::{build_config, init_audit_sinks};
use auths_cli::ux::format::set_json_mode;

fn main() {
    if let Err(err) = run() {
        auths_cli::errors::renderer::render_error(&err, auths_cli::ux::format::is_json_mode());
        std::process::exit(1);
    }
}

/// Maps auditable commands to their action name. Returns `None` for commands
/// that don't emit audit events.
fn audit_action(command: &RootCommand) -> Option<&'static str> {
    match command {
        RootCommand::Init(_) => Some("identity_created"),
        RootCommand::Reset(_) => Some("identity_reset"),
        RootCommand::Pair(_) => Some("device_paired"),
        RootCommand::Device(_) => Some("device_command"),
        RootCommand::Verify(_) => Some("commit_verified"),
        RootCommand::SignCommit(_) => Some("commit_signed"),
        RootCommand::Signers(_) => Some("signers_command"),
        _ => None,
    }
}

fn run() -> Result<()> {
    env_logger::init();

    let _telemetry = init_audit_sinks();

    // Intercept top-level help/--help-all BEFORE clap parsing so we can
    // print grouped output while letting clap handle subcommand help normally
    // (e.g. `auths init --help` still works via clap).
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let has_help = raw_args.iter().any(|a| a == "--help" || a == "-h");
    let has_help_all = raw_args.iter().any(|a| a == "--help-all");
    let first_non_flag = raw_args.iter().find(|a| !a.starts_with('-'));

    if has_help_all {
        print_grouped_help(true)?;
        return Ok(());
    }
    if has_help && first_non_flag.is_none() {
        print_grouped_help(false)?;
        return Ok(());
    }

    // Intercept --version + --json before clap (clap prints plain text and exits)
    let has_version = raw_args.iter().any(|a| a == "--version" || a == "-V");
    let has_json = raw_args.iter().any(|a| a == "--json" || a == "-j");
    if has_version && has_json {
        println!(
            "{}",
            serde_json::json!({ "name": "auths", "version": env!("CARGO_PKG_VERSION") })
        );
        return Ok(());
    }

    let cli = AuthsCli::parse();

    if cli.json {
        set_json_mode(true);
    }

    let ctx = build_config(&cli)?;

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            print_grouped_help(false)?;
            return Ok(());
        }
    };

    let action = audit_action(&command);

    let result = match command {
        // Primary
        RootCommand::Init(cmd) => cmd.execute(&ctx),
        RootCommand::Demo(cmd) => cmd.execute(&ctx),
        RootCommand::Sign(cmd) => cmd.execute(&ctx),
        RootCommand::Verify(cmd) => cmd.execute(&ctx),
        RootCommand::Publish(cmd) => cmd.execute(&ctx),
        RootCommand::Artifact(cmd) => cmd.execute(&ctx),
        RootCommand::Status(cmd) => cmd.execute(&ctx),
        RootCommand::Whoami(cmd) => cmd.execute(&ctx),
        // Setup & Troubleshooting
        RootCommand::Pair(cmd) => cmd.execute(&ctx),
        RootCommand::Trust(cmd) => cmd.execute(&ctx),
        RootCommand::Doctor(cmd) => cmd.execute(&ctx),
        RootCommand::Tutorial(cmd) => cmd.execute(&ctx),
        // Utilities
        RootCommand::Config(cmd) => cmd.execute(&ctx),
        RootCommand::Completions(cmd) => cmd.execute(&ctx),
        // Advanced
        RootCommand::Reset(cmd) => cmd.execute(&ctx),
        RootCommand::SignCommit(cmd) => cmd.execute(&ctx),
        RootCommand::Signers(cmd) => cmd.execute(&ctx),
        RootCommand::Error(cmd) => cmd.execute(&ctx),
        RootCommand::Id(cmd) => cmd.execute(&ctx),
        RootCommand::Device(cmd) => cmd.execute(&ctx),
        RootCommand::Key(cmd) => cmd.execute(&ctx),
        RootCommand::Approval(cmd) => cmd.execute(&ctx),
        RootCommand::Policy(cmd) => cmd.execute(&ctx),
        RootCommand::Git(cmd) => cmd.execute(&ctx),
        RootCommand::Namespace(cmd) => cmd.execute(&ctx),
        RootCommand::Org(cmd) => cmd.execute(&ctx),
        RootCommand::Audit(cmd) => cmd.execute(&ctx),
        RootCommand::Auth(cmd) => cmd.execute(&ctx),
        // Internal
        RootCommand::Emergency(cmd) => cmd.execute(&ctx),
        RootCommand::Agent(cmd) => cmd.execute(&ctx),
        RootCommand::Witness(cmd) => cmd.execute(&ctx),
        RootCommand::Scim(cmd) => cmd.execute(&ctx),
        RootCommand::Commit(cmd) => cmd.execute(&ctx),
        RootCommand::Debug(cmd) => cmd.execute(&ctx),
        RootCommand::Log(cmd) => cmd.execute(&ctx),
        RootCommand::Account(cmd) => cmd.execute(&ctx),
        RootCommand::MultiSig(cmd) => cmd.execute(&ctx),
    };

    if let Some(action) = action {
        let status = if result.is_ok() { "success" } else { "failed" };
        #[allow(clippy::disallowed_methods)]
        let now = chrono::Utc::now().timestamp();
        let event = auths_telemetry::build_audit_event("unknown", action, status, now);
        auths_telemetry::emit_telemetry(&event);
    }

    result
}

/// Command group definition for grouped help output.
struct CommandGroup {
    heading: &'static str,
    commands: &'static [&'static str],
}

/// The primary commands shown in default help.
const HELP_GROUPS: &[CommandGroup] = &[
    CommandGroup {
        heading: "Primary",
        commands: &["init", "sign", "verify", "status", "whoami"],
    },
    CommandGroup {
        heading: "Setup & Troubleshooting",
        commands: &["pair", "trust", "doctor", "tutorial", "demo"],
    },
    CommandGroup {
        heading: "CI/CD",
        commands: &["ci"],
    },
    CommandGroup {
        heading: "Utilities",
        commands: &["config", "completions"],
    },
];

fn print_grouped_help(show_all: bool) -> Result<()> {
    let cmd = AuthsCli::command();

    // ANSI codes matching cli_styles()
    const BLUE_BOLD: &str = "\x1b[1;34m";
    const CYAN_BOLD: &str = "\x1b[1;36m";
    const GREEN_BOLD: &str = "\x1b[1;32m";
    const RESET: &str = "\x1b[0m";

    // Header
    println!("{GREEN_BOLD}auths \u{2014} cryptographic identity for developers and agents{RESET}");
    println!();
    println!("{BLUE_BOLD}Usage:{RESET} auths [OPTIONS] [COMMAND]");

    // Collect subcommand metadata
    let subcommands: Vec<(&str, String, bool)> = cmd
        .get_subcommands()
        .map(|s| {
            let name = s.get_name();
            let about = s.get_about().map(|a| a.to_string()).unwrap_or_default();
            let hidden = s.is_hide_set();
            (name, about, hidden)
        })
        .collect();

    // Print primary groups
    for group in HELP_GROUPS {
        println!();
        println!("{BLUE_BOLD}{}:{RESET}", group.heading);
        for &cmd_name in group.commands {
            if let Some((_, about, _)) = subcommands.iter().find(|(n, _, _)| *n == cmd_name) {
                println!("  {CYAN_BOLD}{:<13}{RESET}{}", cmd_name, about);
            }
        }
    }

    // If --help-all, show advanced and internal groups
    if show_all {
        // Collect all names in primary groups
        let primary_names: Vec<&str> = HELP_GROUPS
            .iter()
            .flat_map(|g| g.commands.iter().copied())
            .collect();

        // Internal commands (always hidden, even in --help-all context)
        let internal = [
            "emergency",
            "agent",
            "witness",
            "scim",
            "commit",
            "debug",
            "log",
            "account",
        ];

        // Advanced = hidden but not internal
        let advanced: Vec<&(&str, String, bool)> = subcommands
            .iter()
            .filter(|(name, _, _)| !primary_names.contains(name) && !internal.contains(name))
            .collect();

        if !advanced.is_empty() {
            println!();
            println!("{BLUE_BOLD}Advanced:{RESET}");
            for (name, about, _) in &advanced {
                println!("  {CYAN_BOLD}{:<13}{RESET}{}", name, about);
            }
        }

        // Internal
        let internal_cmds: Vec<&(&str, String, bool)> = subcommands
            .iter()
            .filter(|(name, _, _)| internal.contains(name))
            .collect();

        if !internal_cmds.is_empty() {
            println!();
            println!("{BLUE_BOLD}Internal:{RESET}");
            for (name, about, _) in &internal_cmds {
                println!("  {CYAN_BOLD}{:<13}{RESET}{}", name, about);
            }
        }
    }

    // Options
    println!();
    println!("{BLUE_BOLD}Options:{RESET}");
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        let long = arg.get_long().map(|l| format!("--{l}"));
        let short = arg.get_short().map(|s| format!("-{s}"));
        let about = arg.get_help().map(|h| h.to_string()).unwrap_or_default();

        // Only show value placeholder for args that take a value (not bool flags)
        let takes_value = !matches!(
            arg.get_action(),
            clap::ArgAction::SetTrue
                | clap::ArgAction::SetFalse
                | clap::ArgAction::Count
                | clap::ArgAction::Version
                | clap::ArgAction::Help
                | clap::ArgAction::HelpShort
                | clap::ArgAction::HelpLong
        );
        let value_hint = if takes_value {
            arg.get_value_names()
                .unwrap_or_default()
                .iter()
                .map(|v| format!(" <{v}>"))
                .collect::<String>()
        } else {
            String::new()
        };

        // Build the flag string and pad to consistent width
        let flag_str = match (short, long) {
            (Some(s), Some(l)) => format!("  {s}, {l}{value_hint}"),
            (None, Some(l)) => format!("      {l}{value_hint}"),
            (Some(s), None) => format!("  {s}{value_hint}"),
            (None, None) => continue,
        };
        println!("{CYAN_BOLD}{:<23}{RESET} {about}", flag_str);
    }
    // Help and version flags (clap adds these separately, not in get_arguments)
    println!("{CYAN_BOLD}{:<23}{RESET} Print help", "  -h, --help");
    println!("{CYAN_BOLD}{:<23}{RESET} Print version", "  -V, --version");

    // Examples
    if !show_all {
        println!();
        println!("{BLUE_BOLD}Examples:{RESET}");
        println!(
            "  {CYAN_BOLD}auths init{RESET}                    Set up your cryptographic identity"
        );
        println!(
            "  {CYAN_BOLD}auths demo{RESET}                    Try sign + verify in 30 seconds"
        );
        println!("  {CYAN_BOLD}auths sign release.tar.gz{RESET}     Sign an artifact");
        println!(
            "  {CYAN_BOLD}auths verify release.tar.gz{RESET}   Verify a signed artifact (auto-finds .auths.json)"
        );
    }

    // Footer
    println!();
    println!("Run 'auths <command> --help' for details on any command.");
    if !show_all {
        println!("Run 'auths --help-all' for all commands including advanced ones.");
    }

    Ok(())
}
