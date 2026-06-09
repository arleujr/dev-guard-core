use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;

#[test]
fn test_cli_blocks_secret_and_returns_exit_code_1() {
    // Creates a native isolation sandbox directory for the integration test
    let sandbox_path = Path::new("devguard_cli_integration_sandbox");
    if sandbox_path.exists() {
        fs::remove_dir_all(sandbox_path).unwrap();
    }
    fs::create_dir(sandbox_path).unwrap();
    
    // Simulate a developer accidentally committing a valid AWS Access Key format
    let file_path = sandbox_path.join("mock_config.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";").unwrap();

    // Execute our compiled target binary directly against the sandbox directory environment
    // Note: Ensure you run tests using `cargo test` so target binaries are evaluated properly
    let output = Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg(".")
        .current_dir(sandbox_path)
        .output()
        .expect("Failed to execute dev-guard-core integration target process");

    let stdout_content = String::from_utf8_lossy(&output.stdout);

    // Assert cleanups are executed correctly before finalizing constraints
    fs::remove_dir_all(sandbox_path).unwrap();

    // Verify DevSecOps technical requirements: binary must return failure exit code (1)
    // and correctly identify the explicit compromise vector signature
    assert!(!output.status.success(), "The CLI should have failed due to a detected secret leak");
    assert!(stdout_content.contains("AWS Access Key") || stdout_content.contains("High Entropy Token"), "Audit output logs should register a clear vulnerability flag");
    assert!(stdout_content.contains("Audit Failed"), "Audit logs must transition status to Failed state");
}
