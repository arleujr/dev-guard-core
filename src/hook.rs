use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HookError {
    #[error("Could not find .git directory. Are you at the repository root?")]
    NoGitDir,
    #[error("I/O error while writing the hook: {0}")]
    Io(#[from] std::io::Error),
}

/// Installs the pre-commit hook automatically in the local repository.
pub fn install_pre_commit_hook() -> Result<(), HookError> {
    let git_dir = PathBuf::from(".git");
    
    if !git_dir.exists() || !git_dir.is_dir() {
        return Err(HookError::NoGitDir);
    }

    let hooks_dir = git_dir.join("hooks");
    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir)?;
    }

    let hook_path = hooks_dir.join("pre-commit");
    
    // The bash script that will be executed by Git
    let script_content = r#"#!/bin/sh

# [Dev-Guard] Auto-generated Pre-Commit Hook
# Blocks the commit if hardcoded secrets are detected in the staged files.

exec dev-guard-core --diff
"#;

    let mut file = File::create(&hook_path)?;
    file.write_all(script_content.as_bytes())?;

    // Modifies file permissions to make it executable.
    // The #[cfg(unix)] macro ensures this code only compiles on Unix/Linux/macOS systems.
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755); // Equivalent to `chmod +x` (rwxr-xr-x)
        fs::set_permissions(&hook_path, perms)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_install_hook_creates_executable_file() {
        let temp_dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();

        // Create mock .git/hooks directory
        fs::create_dir_all(".git/hooks").unwrap();

        let result = install_pre_commit_hook();
        assert!(result.is_ok());

        let hook_content = fs::read_to_string(".git/hooks/pre-commit").unwrap();
        assert!(hook_content.contains("exec dev-guard-core --diff"));

        env::set_current_dir(original_dir).unwrap();
    }

    #[test]
    fn test_install_hook_fails_without_git_dir() {
        let temp_dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();

        // Intentionally NOT creating a .git directory
        let result = install_pre_commit_hook();
        assert!(matches!(result, Err(HookError::NoGitDir)));

        env::set_current_dir(original_dir).unwrap();
    }
}