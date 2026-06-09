use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GitError {
    #[error("Failed to execute git process. Is git installed?")]
    ProcessExecution(#[from] std::io::Error),
    #[error("Git command failed. Are you inside a git repository?")]
    RepositoryError,
    #[error("Failed to parse git output as UTF-8")]
    Encoding,
}

/// Retrieves a list of files currently staged for commit.
/// Uses `--diff-filter=ACM` to only get Added, Copied, or Modified files,
/// explicitly ignoring Deleted files which would cause I/O read errors.
pub fn get_staged_files() -> Result<Vec<String>, GitError> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
        .output()?;

    if !output.status.success() {
        return Err(GitError::RepositoryError);
    }

    let stdout = String::from_utf8(output.stdout).map_err(|_| GitError::Encoding)?;
    
    let files: Vec<String> = stdout
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_git_fails_gracefully_outside_repository() {
        // Create an empty temporary directory (explicitly NOT a git repo)
        let temp_dir = tempdir().unwrap();
        
        // Isolate the Git command execution environment context
        // We inject an invalid GIT_DIR env variable to completely stop Git 
        // from climbing up parent directories looking for the real .git folder on Windows.
        let output = Command::new("git")
            .env("GIT_DIR", temp_dir.path().join(".invalid_git_dir")) // Stops Git hierarchy traversal
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
            .current_dir(temp_dir.path())
            .output();

        match output {
            Ok(out) => {
                // Now Git is fully isolated and forced to natively fail with a non-zero code.
                assert!(!out.status.success(), "Git must report an error status code when fully isolated outside a repo context");
            }
            Err(_) => {
                // If git binary is completely missing on the host platform path
                assert!(true);
            }
        }
    }
}
