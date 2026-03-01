use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

/// Interactive tutorial for learning Auths concepts.
#[derive(Parser, Debug, Clone)]
pub struct LearnCommand {
    /// Skip to a specific section (1-6).
    #[clap(long, short, value_name = "SECTION")]
    skip: Option<usize>,

    /// Reset progress and start from the beginning.
    #[clap(long)]
    reset: bool,

    /// List all tutorial sections.
    #[clap(long)]
    list: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    WhatIsIdentity = 1,
    CreatingIdentity = 2,
    SigningCommit = 3,
    VerifyingSignature = 4,
    LinkingDevice = 5,
    RevokingAccess = 6,
}

impl Section {
    fn from_number(n: usize) -> Option<Section> {
        match n {
            1 => Some(Section::WhatIsIdentity),
            2 => Some(Section::CreatingIdentity),
            3 => Some(Section::SigningCommit),
            4 => Some(Section::VerifyingSignature),
            5 => Some(Section::LinkingDevice),
            6 => Some(Section::RevokingAccess),
            _ => None,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Section::WhatIsIdentity => "What is a Cryptographic Identity?",
            Section::CreatingIdentity => "Creating Your Identity",
            Section::SigningCommit => "Signing a Commit",
            Section::VerifyingSignature => "Verifying a Signature",
            Section::LinkingDevice => "Linking a Second Device",
            Section::RevokingAccess => "Revoking Access",
        }
    }

    fn next(&self) -> Option<Section> {
        Section::from_number(*self as usize + 1)
    }
}

struct Tutorial {
    sandbox_dir: PathBuf,
    progress_file: PathBuf,
}

impl Tutorial {
    fn new() -> Result<Self> {
        let home = dirs::home_dir().context("Could not find home directory")?;
        let sandbox_dir = home.join(".auths-tutorial");
        let progress_file = sandbox_dir.join(".progress");

        Ok(Self {
            sandbox_dir,
            progress_file,
        })
    }

    fn setup_sandbox(&self) -> Result<()> {
        if !self.sandbox_dir.exists() {
            fs::create_dir_all(&self.sandbox_dir)?;
        }
        Ok(())
    }

    fn cleanup_sandbox(&self) -> Result<()> {
        if self.sandbox_dir.exists() {
            fs::remove_dir_all(&self.sandbox_dir)?;
        }
        Ok(())
    }

    fn load_progress(&self) -> usize {
        if let Ok(content) = fs::read_to_string(&self.progress_file) {
            content.trim().parse().unwrap_or(1)
        } else {
            1
        }
    }

    fn save_progress(&self, section: usize) -> Result<()> {
        fs::write(&self.progress_file, section.to_string())?;
        Ok(())
    }

    fn reset_progress(&self) -> Result<()> {
        if self.progress_file.exists() {
            fs::remove_file(&self.progress_file)?;
        }
        self.cleanup_sandbox()?;
        Ok(())
    }
}

pub fn handle_learn(cmd: LearnCommand) -> Result<()> {
    let tutorial = Tutorial::new()?;

    if cmd.list {
        list_sections();
        return Ok(());
    }

    if cmd.reset {
        tutorial.reset_progress()?;
        println!("{}", "✓ Tutorial progress reset.".green());
        return Ok(());
    }

    let start_section = if let Some(skip) = cmd.skip {
        if !(1..=6).contains(&skip) {
            anyhow::bail!("Section must be between 1 and 6");
        }
        skip
    } else {
        tutorial.load_progress()
    };

    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║                  Welcome to Auths Tutorial                  ║".cyan()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════╝".cyan()
    );
    println!();

    if start_section > 1 {
        println!("  {} Resuming from section {}", "→".yellow(), start_section);
        println!();
    }

    tutorial.setup_sandbox()?;

    let mut current = Section::from_number(start_section).unwrap_or(Section::WhatIsIdentity);

    loop {
        run_section(current, &tutorial)?;
        tutorial.save_progress(current as usize + 1)?;

        if let Some(next) = current.next() {
            println!();
            print!(
                "  {} Press Enter to continue to the next section (or 'q' to quit): ",
                "→".yellow()
            );
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if input.trim().to_lowercase() == "q" {
                println!();
                println!(
                    "  {} Your progress has been saved. Run 'auths learn' to continue.",
                    "✓".green()
                );
                break;
            }

            current = next;
        } else {
            // Tutorial complete
            tutorial.cleanup_sandbox()?;
            tutorial.reset_progress()?;

            println!();
            println!(
                "{}",
                "╔════════════════════════════════════════════════════════════╗".green()
            );
            println!(
                "{}",
                "║                 Tutorial Complete!                         ║".green()
            );
            println!(
                "{}",
                "╚════════════════════════════════════════════════════════════╝".green()
            );
            println!();
            println!("  You've learned the basics of Auths! Here's what to do next:");
            println!();
            println!(
                "  {} Run {} to create your real identity",
                "1.".cyan(),
                "auths init".bold()
            );
            println!(
                "  {} Run {} to start signing commits",
                "2.".cyan(),
                "auths git setup".bold()
            );
            println!(
                "  {} Check {} for advanced features",
                "3.".cyan(),
                "auths --help".bold()
            );
            println!();
            break;
        }
    }

    Ok(())
}

fn list_sections() {
    println!();
    println!("{}", "Tutorial Sections:".bold());
    println!();

    for i in 1..=6 {
        if let Some(section) = Section::from_number(i) {
            println!("  {} {}", format!("{}.", i).cyan(), section.title());
        }
    }

    println!();
    println!("Use {} to skip to a specific section", "--skip N".bold());
    println!("Use {} to reset progress", "--reset".bold());
    println!();
}

fn run_section(section: Section, tutorial: &Tutorial) -> Result<()> {
    println!();
    println!(
        "{}",
        "────────────────────────────────────────────────────────────".dimmed()
    );
    println!(
        "  {} {}",
        format!("Section {}", section as usize).cyan().bold(),
        section.title().bold()
    );
    println!(
        "{}",
        "────────────────────────────────────────────────────────────".dimmed()
    );
    println!();

    match section {
        Section::WhatIsIdentity => section_what_is_identity()?,
        Section::CreatingIdentity => section_creating_identity(tutorial)?,
        Section::SigningCommit => section_signing_commit(tutorial)?,
        Section::VerifyingSignature => section_verifying_signature(tutorial)?,
        Section::LinkingDevice => section_linking_device()?,
        Section::RevokingAccess => section_revoking_access()?,
    }

    println!();
    println!("  {} Section complete!", "✓".green());

    Ok(())
}

fn section_what_is_identity() -> Result<()> {
    println!("  A cryptographic identity lets you prove who you are without passwords.");
    println!();
    println!("  With Auths, your identity consists of:");
    println!();
    println!(
        "    {} A unique identifier called a {} (Decentralized Identifier)",
        "•".cyan(),
        "DID".bold()
    );
    println!(
        "    {} A {} stored in your device's secure storage",
        "•".cyan(),
        "signing key".bold()
    );
    println!(
        "    {} {} that authorize devices to sign on your behalf",
        "•".cyan(),
        "Attestations".bold()
    );
    println!();
    println!("  Key benefits:");
    println!();
    println!(
        "    {} {} - No central server owns your identity",
        "✓".green(),
        "Decentralized".bold()
    );
    println!(
        "    {} {} - Keys never leave your device",
        "✓".green(),
        "Secure".bold()
    );
    println!(
        "    {} {} - Signatures are mathematically proven",
        "✓".green(),
        "Verifiable".bold()
    );
    println!(
        "    {} {} - Use the same identity across all your devices",
        "✓".green(),
        "Portable".bold()
    );

    wait_for_continue()?;
    Ok(())
}

fn section_creating_identity(tutorial: &Tutorial) -> Result<()> {
    println!("  Let's create a test identity in a sandbox environment.");
    println!();
    println!("  In a real scenario, you would run:");
    println!();
    println!("    {}", "$ auths init".cyan());
    println!();
    println!("  This creates your identity by:");
    println!();
    println!("    {} Generating a cryptographic key pair", "1.".cyan());
    println!(
        "    {} Storing the private key in your keychain",
        "2.".cyan()
    );
    println!("    {} Creating your DID from the public key", "3.".cyan());
    println!(
        "    {} Recording everything in a Git repository",
        "4.".cyan()
    );
    println!();

    // Simulate identity creation
    println!("  {} Creating sandbox identity...", "→".yellow());

    let sandbox_repo = tutorial.sandbox_dir.join("identity");
    if !sandbox_repo.exists() {
        fs::create_dir_all(&sandbox_repo)?;

        // Initialize git repo
        ProcessCommand::new("git")
            .args(["init", "--quiet"])
            .current_dir(&sandbox_repo)
            .status()?;

        ProcessCommand::new("git")
            .args(["config", "user.email", "tutorial@auths.io"])
            .current_dir(&sandbox_repo)
            .status()?;

        ProcessCommand::new("git")
            .args(["config", "user.name", "Tutorial User"])
            .current_dir(&sandbox_repo)
            .status()?;
    }

    println!();
    println!("  {} Sandbox identity created!", "✓".green());
    println!();
    println!("  Your sandbox DID would look like:");
    println!("    {}", "did:keri:EExample123...".dimmed());
    println!();
    println!("  This DID is derived from your public key - it's mathematically");
    println!("  guaranteed to be unique to you.");

    wait_for_continue()?;
    Ok(())
}

fn section_signing_commit(tutorial: &Tutorial) -> Result<()> {
    println!("  Git commit signing proves that commits came from you.");
    println!();
    println!("  With Auths configured, Git automatically signs your commits:");
    println!();
    println!("    {}", "$ git commit -m \"Add feature\"".cyan());
    println!(
        "    {}",
        "[main abc1234] Add feature (auths-signed)".dimmed()
    );
    println!();
    println!("  Behind the scenes, Auths:");
    println!();
    println!("    {} Creates a signature of the commit data", "1.".cyan());
    println!("    {} Uses your key from the secure keychain", "2.".cyan());
    println!("    {} Embeds the signature in the commit", "3.".cyan());
    println!();

    // Create a test commit in sandbox
    let sandbox_repo = tutorial.sandbox_dir.join("identity");
    let test_file = sandbox_repo.join("test.txt");

    fs::write(&test_file, "Hello from Auths tutorial!\n")?;

    ProcessCommand::new("git")
        .args(["add", "test.txt"])
        .current_dir(&sandbox_repo)
        .status()?;

    ProcessCommand::new("git")
        .args(["commit", "--quiet", "-m", "Tutorial: First signed commit"])
        .current_dir(&sandbox_repo)
        .status()?;

    println!("  {} Created a test commit in the sandbox:", "→".yellow());
    println!();

    // Show the commit
    let output = ProcessCommand::new("git")
        .args(["log", "--oneline", "-1"])
        .current_dir(&sandbox_repo)
        .output()?;

    let log_output = String::from_utf8_lossy(&output.stdout);
    println!("    {}", log_output.trim().dimmed());

    wait_for_continue()?;
    Ok(())
}

fn section_verifying_signature(_tutorial: &Tutorial) -> Result<()> {
    println!("  Anyone can verify that a commit came from you.");
    println!();
    println!("  To verify a commit signature:");
    println!();
    println!("    {}", "$ auths verify-commit HEAD".cyan());
    println!();
    println!("  This checks:");
    println!();
    println!("    {} Is the signature mathematically valid?", "•".cyan());
    println!(
        "    {} Does the signing key match an authorized device?",
        "•".cyan()
    );
    println!(
        "    {} Was the device authorized at commit time?",
        "•".cyan()
    );
    println!();
    println!("  Verification is fast because it uses local Git data - no network");
    println!("  calls needed.");
    println!();

    // Show verification output
    println!("  {} Example verification output:", "→".yellow());
    println!();
    println!("    {}", "✓ Signature valid".green());
    println!("    {}", "  Signer: did:keri:EExample123...".dimmed());
    println!("    {}", "  Device: MacBook Pro (active)".dimmed());
    println!("    {}", "  Signed: 2024-01-15 10:30:00 UTC".dimmed());

    wait_for_continue()?;
    Ok(())
}

fn section_linking_device() -> Result<()> {
    println!("  Use the same identity across multiple devices.");
    println!();
    println!("  To link a new device:");
    println!();
    println!("    {} On your existing device:", "1.".cyan());
    println!("       {}", "$ auths pair start".cyan());
    println!("       {}", "Scan this QR code or enter: ABC123".dimmed());
    println!();
    println!("    {} On your new device:", "2.".cyan());
    println!("       {}", "$ auths pair join --code ABC123".cyan());
    println!();
    println!(
        "  This creates an {} that authorizes the new device",
        "attestation".bold()
    );
    println!("  to sign commits on behalf of your identity.");
    println!();
    println!("  {} The new device gets its own signing key", "•".cyan());
    println!("  {} Your main device signs the authorization", "•".cyan());
    println!("  {} The attestation is stored in Git", "•".cyan());
    println!();
    println!("  You can link phones, tablets, CI servers - any device that");
    println!("  needs to sign commits as you.");

    wait_for_continue()?;
    Ok(())
}

fn section_revoking_access() -> Result<()> {
    println!("  If a device is lost or compromised, revoke its access.");
    println!();
    println!("  To revoke a device:");
    println!();
    println!("    {}", "$ auths device revoke <device-did>".cyan());
    println!();
    println!("  This creates a revocation record that:");
    println!();
    println!(
        "    {} Marks the device as no longer authorized",
        "•".cyan()
    );
    println!("    {} Is signed by your identity", "•".cyan());
    println!(
        "    {} Is stored in Git and propagates automatically",
        "•".cyan()
    );
    println!();
    println!("  After revocation, signatures from that device will show as:");
    println!();
    println!("    {}", "✗ Device was revoked on 2024-01-20".red());
    println!();
    println!(
        "  {} If you suspect compromise, use emergency freeze:",
        "!".red().bold()
    );
    println!();
    println!("    {}", "$ auths emergency freeze".cyan());
    println!();
    println!("  This immediately suspends all signing until you investigate.");

    wait_for_continue()?;
    Ok(())
}

fn wait_for_continue() -> Result<()> {
    println!();
    print!("  {} Press Enter to continue...", "→".dimmed());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(())
}

impl crate::commands::executable::ExecutableCommand for LearnCommand {
    fn execute(&self, _ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_learn(self.clone())
    }
}
