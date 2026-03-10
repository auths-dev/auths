// CLI is the presentation boundary — Utc::now(), env::var, and printing are expected here.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::disallowed_methods,
    clippy::exit
)]
use anyhow::Result;
use clap::Parser;

use auths_cli::cli::{AuthsCli, RootCommand};
use auths_cli::commands::executable::ExecutableCommand;
use auths_cli::config::OutputFormat;
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
        RootCommand::Pair(_) => Some("device_paired"),
        RootCommand::Device(_) => Some("device_command"),
        RootCommand::Verify(_) => Some("commit_verified"),
        RootCommand::Signers(_) => Some("signers_command"),
        _ => None,
    }
}

fn run() -> Result<()> {
    env_logger::init();

    let _telemetry = init_audit_sinks();

    let cli = AuthsCli::parse();

    if cli.help_all {
        use clap::CommandFactory;
        let mut cmd = AuthsCli::command();
        let sub_names: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();
        for name in &sub_names {
            if let Some(sub) = cmd.find_subcommand_mut(name) {
                *sub = sub.clone().hide(false);
            }
        }
        cmd.print_help()?;
        return Ok(());
    }

    let is_json = cli.json || matches!(cli.format, OutputFormat::Json);
    if is_json {
        set_json_mode(true);
    }

    let ctx = build_config(&cli)?;

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            use clap::CommandFactory;
            AuthsCli::command().print_help()?;
            return Ok(());
        }
    };

    let action = audit_action(&command);

    let result = match command {
        RootCommand::Init(cmd) => cmd.execute(&ctx),
        RootCommand::Sign(cmd) => cmd.execute(&ctx),
        RootCommand::Verify(cmd) => cmd.execute(&ctx),
        RootCommand::Status(cmd) => cmd.execute(&ctx),
        RootCommand::Whoami(cmd) => cmd.execute(&ctx),
        RootCommand::Tutorial(cmd) => cmd.execute(&ctx),
        RootCommand::Doctor(cmd) => cmd.execute(&ctx),
        RootCommand::Signers(cmd) => cmd.execute(&ctx),
        RootCommand::Pair(cmd) => cmd.execute(&ctx),
        RootCommand::Completions(cmd) => cmd.execute(&ctx),
        RootCommand::Emergency(cmd) => cmd.execute(&ctx),
        RootCommand::Id(cmd) => cmd.execute(&ctx),
        RootCommand::Device(cmd) => cmd.execute(&ctx),
        RootCommand::Key(cmd) => cmd.execute(&ctx),
        RootCommand::Approval(cmd) => cmd.execute(&ctx),
        RootCommand::Artifact(cmd) => cmd.execute(&ctx),
        RootCommand::Policy(cmd) => cmd.execute(&ctx),
        RootCommand::Git(cmd) => cmd.execute(&ctx),
        RootCommand::Trust(cmd) => cmd.execute(&ctx),
        RootCommand::Org(cmd) => cmd.execute(&ctx),
        RootCommand::Audit(cmd) => cmd.execute(&ctx),
        RootCommand::Agent(cmd) => cmd.execute(&ctx),
        RootCommand::Witness(cmd) => cmd.execute(&ctx),
        RootCommand::Scim(cmd) => cmd.execute(&ctx),
        RootCommand::Config(cmd) => cmd.execute(&ctx),
        RootCommand::Commit(cmd) => cmd.execute(&ctx),
        RootCommand::Debug(cmd) => cmd.execute(&ctx),
    };

    if let Some(action) = action {
        let status = if result.is_ok() { "success" } else { "failed" };
        let now = chrono::Utc::now().timestamp();
        let event = auths_telemetry::build_audit_event("unknown", action, status, now);
        auths_telemetry::emit_telemetry(&event);
    }

    result
}
