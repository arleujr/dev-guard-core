use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("Failed to write JSON report to disk: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to serialize report data: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Represents a single leaked secret found during the scan.
#[derive(Serialize, Clone)]
pub struct Vulnerability {
    pub file: String,
    pub line: usize,
    pub issue_type: String,
}

/// The root structure of the security audit report.
#[derive(Serialize)]
pub struct SecurityReport {
    pub total_leaks: usize,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_duration_ms: u128,
}

/// Serializes the audit results into a structured JSON file for CI/CD consumption.
pub fn generate_json_report(report: &SecurityReport, output_path: &Path) -> Result<(), ReportError> {
    // Generates a pretty-printed JSON string
    let json_string = serde_json::to_string_pretty(report)?;
    
    let mut file = File::create(output_path)?;
    file.write_all(json_string.as_bytes())?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_generate_json_report_creates_valid_file() {
        let temp_dir = tempdir().unwrap();
        let report_path = temp_dir.path().join("test_report.json");

        let mock_report = SecurityReport {
            total_leaks: 1,
            vulnerabilities: vec![Vulnerability {
                file: "src/config.rs".to_string(),
                line: 42,
                issue_type: "AWS Access Key".to_string(),
            }],
            scan_duration_ms: 15,
        };

        let result = generate_json_report(&mock_report, &report_path);
        assert!(result.is_ok());

        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("\"total_leaks\": 1"));
        assert!(content.contains("\"AWS Access Key\""));
    }
}