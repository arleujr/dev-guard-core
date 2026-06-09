use regex::Regex;
use std::sync::OnceLock;

/// Holds pre-compiled regular expressions to prevent the massive performance
/// overhead of recompiling them on every line scanned.
pub struct SignatureScanner {
    aws_regex: &'static Regex,
    postgres_regex: &'static Regex,
}

impl SignatureScanner {
    /// Initializes the scanner using `OnceLock` to guarantee thread-safe, 
    /// zero-cost lazy initialization of the Regex engines.
    pub fn new() -> Self {
        // Rust 1.70+ standard library feature for safe lazy evaluation
        static AWS_REGEX: OnceLock<Regex> = OnceLock::new();
        static POSTGRES_REGEX: OnceLock<Regex> = OnceLock::new();

        Self {
            // Unwrapping here is an accepted fail-fast architectural decision:
            // if a hardcoded regex pattern is malformed, the application should panic at startup,
            // never during runtime traversal.
            aws_regex: AWS_REGEX.get_or_init(|| {
                Regex::new(r"(?i)AKIA[0-9A-Z]{16}").expect("Invalid AWS Regex")
            }),
            postgres_regex: POSTGRES_REGEX.get_or_init(|| {
                Regex::new(r"(?i)postgres(ql)?://[^:]+:[^@]+@[^:]+:\d+/[^/?]+").expect("Invalid Postgres Regex")
            }),
        }
    }

    /// Evaluates a single line against all known signatures.
    /// Returns a static string describing the vulnerability if found.
    pub fn scan_line(&self, line: &str) -> Option<&'static str> {
        if self.aws_regex.is_match(line) {
            return Some("AWS Access Key");
        }
        if self.postgres_regex.is_match(line) {
            return Some("PostgreSQL Connection String");
        }
        
        None
    }
}

// Implement Default to satisfy clippy and idiomatic Rust guidelines
impl Default for SignatureScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_detection() {
        let scanner = SignatureScanner::new();
        let line = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        assert_eq!(scanner.scan_line(line), Some("AWS Access Key"));
    }

    #[test]
    fn test_postgres_url_detection() {
        let scanner = SignatureScanner::new();
        // Simulating a careless hardcoded DB string
        let line = "let db_url = \"postgres://admin:supersecret123@localhost:5432/production_db\";";
        assert_eq!(scanner.scan_line(line), Some("PostgreSQL Connection String"));
    }

    #[test]
    fn test_safe_line_ignored() {
        let scanner = SignatureScanner::new();
        let line = "let greeting = \"Hello, World!\";";
        assert_eq!(scanner.scan_line(line), None);
    }
}