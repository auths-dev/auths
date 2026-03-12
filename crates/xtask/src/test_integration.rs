use std::process::Command;

pub fn run(filter: Option<&str>) -> anyhow::Result<()> {
    println!("Building CLI binaries...");
    let build = Command::new("cargo")
        .args(["build", "--package", "auths-cli"])
        .status()?;
    if !build.success() {
        anyhow::bail!("cargo build failed");
    }

    println!("Running CLI integration tests...");
    let mut args = vec![
        "nextest".to_string(),
        "run".to_string(),
        "-p".to_string(),
        "auths-cli".to_string(),
    ];

    if let Some(f) = filter {
        args.push("-E".to_string());
        args.push(format!("test({})", f));
    } else {
        args.push("-E".to_string());
        args.push(
            "test(test_init_ | test_sign_verify | test_doctor | test_verify_json | test_key_rotation | test_emergency_revoke)".to_string(),
        );
    }

    let test = Command::new("cargo").args(&args).status()?;
    if !test.success() {
        anyhow::bail!(
            "integration tests failed (exit {})",
            test.code().unwrap_or(1)
        );
    }

    println!("All integration tests passed.");
    Ok(())
}
