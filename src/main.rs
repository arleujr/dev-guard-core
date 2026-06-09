mod entropy;
mod git;
mod hook;
mod report;
mod scanner;
mod signatures;

use owo_colors::OwoColorize;
use std::path::Path;
use std::time::Instant;

/// Application entry point for `dev-guard-core`.
/// Orchestrates the entire security suite, processing automation hooks (`--install-hook`),
/// incremental evaluations (`--diff`), and metadata auditing compilation (`--json`).
fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // Command Router: Check for automation installation flags before firing the scan matrix
    if args.contains(&String::from("--install-hook")) {
        match hook::install_pre_commit_hook() {
            Ok(_) => {
                println!("{} Git pre-commit hook installed successfully!", "✅ [Dev-Guard]".green().bold());
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("{} {}", "❌ Hook installation failed:".red().bold(), e);
                std::process::exit(1);
            }
        }
    }

    let is_incremental = args.contains(&String::from("--diff"));
    let generate_json = args.contains(&String::from("--json"));

    println!("{}", "🚀 [Dev-Guard] Initiating Workspace Security Audit...".cyan().bold());
    let start_time = Instant::now();

    let sig_scanner = signatures::SignatureScanner::new();
    
    // Core telemetry vector capturing discovered compromise structures
    let mut vulnerabilities: Vec<report::Vulnerability> = Vec::new();

    let mut process_line = |path: &Path, line_num: usize, line: &str| {
        // 1. Fast-Path: Static Signature Regex Verification
        if let Some(vuln_type) = sig_scanner.scan_line(line) {
            print_alert(path, line_num, vuln_type);
            vulnerabilities.push(report::Vulnerability {
                file: path.display().to_string(),
                line: line_num,
                issue_type: vuln_type.to_string(),
            });
            return; // Early return to save CPU cycles
        }

        // 2. Slow-Path: Heuristic Entropy Engine with strict restriction rules
        if line.len() > 16 && !line.contains(' ') {
            let lower_line = line.to_lowercase();
            // False Positive Mitigation: Discard obvious test strings
            if !lower_line.contains("dummy") && !lower_line.contains("test") {
                if let Ok(true) = entropy::is_highly_random(line, 4.5) {
                    print_alert(path, line_num, "High Entropy Token (Unknown Secret)");
                    vulnerabilities.push(report::Vulnerability {
                        file: path.display().to_string(),
                        line: line_num,
                        issue_type: "High Entropy Token".to_string(),
                    });
                }
            }
        }
    };

    // Ingestion Layer: Route between differential staged scan or recursive traversal
    let result = if is_incremental {
        println!("{}", "ℹ️  Incremental mode: Scanning only staged files.".bright_black());
        match git::get_staged_files() {
            Ok(files) => scanner::scan_specific_files(&files, &mut process_line),
            Err(e) => {
                eprintln!("{} {}", "❌ Git integration error:".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else {
        scanner::scan_workspace(".", &mut process_line)
    };

    if let Err(e) = result {
        eprintln!("{} {}", "❌ Critical scanning error:".red().bold(), e);
        std::process::exit(1);
    }

    let duration = start_time.elapsed();
    let total_leaks = vulnerabilities.len();

    // Audit Report Compilation: Serialize metadata if requested by the workflow pipeline
    if generate_json {
        let sec_report = report::SecurityReport {
            total_leaks,
            vulnerabilities,
            scan_duration_ms: duration.as_millis(),
        };
        
        let output_path = Path::new("dev-guard-report.json");
        if let Err(e) = report::generate_json_report(&sec_report, output_path) {
            eprintln!("{} {}", "⚠️  Failed to write JSON report:".yellow().bold(), e);
        } else {
            println!("{} Report exported to {}", "📄 [Dev-Guard]".blue().bold(), output_path.display().bold());
        }
    }

    println!("\n{}", "=".repeat(50).bright_black());
    
    // Deterministic Exit Code handling for secure CI/CD integrations
    if total_leaks > 0 {
        println!("{} {} leaks found in {:.2?}", "⚠️  Audit Failed:".red().bold(), total_leaks, duration);
        std::process::exit(1); // Blocks Git commits or breaks build pipelines
    } else {
        println!("{} Workspace is secure. (Scanned in {:.2?})", "✅ Audit Passed:".green().bold(), duration);
        std::process::exit(0); // Authorizes workflow transition
    }
}

/// Renders a premium UX console alert pinpointing the exact compromise vector.
fn print_alert(path: &Path, line_num: usize, alert_type: &str) {
    let file_display = path.display().to_string();
    println!(
        "{} {} at {}:{}",
        "[ERR-042]".red().bold(),
        alert_type.yellow().bold(),
        file_display.underline(),
        line_num.bright_blue()
    );
}
