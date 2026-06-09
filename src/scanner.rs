use ignore::WalkBuilder;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Failed to traverse directory tree: {0}")]
    Traversal(#[from] ignore::Error),
    #[error("I/O error during file processing: {0}")]
    Io(#[from] io::Error),
}

/// Core function to traverse the workspace safely.
/// Automatically skips hidden directories (e.g., .git) and files mapped in .gitignore.
/// Uses a callback pattern to delegate line processing to the heuristic engines.
pub fn scan_workspace<P, F>(root_path: P, mut line_processor: F) -> Result<(), ScannerError>
where
    P: AsRef<Path>,
    F: FnMut(&Path, usize, &str),
{
    let walker = WalkBuilder::new(root_path)
        .hidden(true)
        .git_ignore(true)
        .same_file_system(true) // Optimization: prevents crossing OS mount points
        .build();

    for result in walker {
        let entry = result?;
        let path = entry.path();

        if path.is_file() {
            let file = match File::open(path) {
                Ok(f) => f,
                Err(_) => continue, // Gracefully skip locked or unreadable files
            };
            
            let reader = BufReader::new(file);

            // Buffered reading maintains a constant low memory footprint O(1) space
            for (index, line_result) in reader.lines().enumerate() {
                match line_result {
                    Ok(line) => line_processor(path, index + 1, &line),
                    // Break loop if we hit non-UTF8 bytes (e.g., a binary file that bypassed filters)
                    Err(_) => break, 
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_scan_workspace_ignores_git_and_reads_valid_files() {
        let temp_dir = tempdir().unwrap();
        let root = temp_dir.path();
        
        // Mock a valid application file
        let valid_file_path = root.join("config.rs");
        let mut valid_file = File::create(&valid_file_path).unwrap();
        writeln!(valid_file, "const API_KEY: &str = \"12345\";").unwrap();

        // Mock a .git directory (should be ignored by WalkBuilder)
        let git_dir = root.join(".git");
        fs::create_dir(&git_dir).unwrap();
        let git_file = git_dir.join("config");
        let mut gf = File::create(git_file).unwrap();
        writeln!(gf, "secret=git_internal_token").unwrap();

        let mut scanned_lines = Vec::new();

        // Pass a closure to collect the lines that were actually scanned
        scan_workspace(root, |_path, _line_num, line| {
            scanned_lines.push(line.to_string());
        }).unwrap();

        // The assertions prove that .git was bypassed entirely
        assert_eq!(scanned_lines.len(), 1);
        assert_eq!(scanned_lines[0], "const API_KEY: &str = \"12345\";");
    }
}
pub fn scan_specific_files<F>(files: &[String], mut line_processor: F) -> Result<(), ScannerError>
where
    F: FnMut(&Path, usize, &str),
{
    for file_path in files {
        let path = Path::new(file_path);
        
        if !path.exists() || !path.is_file() {
            continue;
        }

        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        
        let reader = BufReader::new(file);

        for (index, line_result) in reader.lines().enumerate() {
            match line_result {
                Ok(line) => line_processor(path, index + 1, &line),
                Err(_) => break,
            }
        }
    }
    Ok(())
}