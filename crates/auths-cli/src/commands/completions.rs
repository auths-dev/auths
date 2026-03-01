//! Shell completion generation.

use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use std::io;

/// Generate shell completions for auths.
#[derive(Parser, Debug, Clone)]
#[command(name = "completions", about = "Generate shell completions")]
pub struct CompletionsCommand {
    /// The shell to generate completions for.
    #[arg(value_enum)]
    pub shell: Shell,
}

/// Generate shell completions and print to stdout.
///
/// # Usage
///
/// ```bash
/// # Bash
/// auths completions bash > ~/.local/share/bash-completion/completions/auths
///
/// # Zsh
/// auths completions zsh > ~/.zfunc/_auths
///
/// # Fish
/// auths completions fish > ~/.config/fish/completions/auths.fish
///
/// # PowerShell
/// auths completions powershell > auths.ps1
/// ```
pub fn handle_completions<C: CommandFactory>(cmd: CompletionsCommand) -> Result<()> {
    let mut command = C::command();
    let name = command.get_name().to_string();
    generate(cmd.shell, &mut command, name, &mut io::stdout());
    Ok(())
}

impl crate::commands::executable::ExecutableCommand for CompletionsCommand {
    fn execute(&self, _ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_completions::<crate::cli::AuthsCli>(self.clone())
    }
}
