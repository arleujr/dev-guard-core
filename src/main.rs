mod entropy;
mod git;
mod hook; // Novo módulo
mod scanner;
mod signatures;

use owo_colors::OwoColorize;
use std::path::Path;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // Intercepts the execution if the user just wants to install the hook
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

    println!("{}", "🚀 [Dev-Guard] Initiating Workspace Security Audit...".cyan().bold());
    let start_time = Instant::now();

    let sig_scanner = signatures::SignatureScanner::new();
    let mut leaks_found = 0;

    // Extracted the core heuristic logic into a reusable closure
    let mut process_line = |path: &Path, line_num: usize, line: &str| {
        if let Some(vuln_type) = sig_scanner.scan_line(line) {
            print_alert(path, line_num, vuln_type);
            leaks_found += 1;
            return;
        }

        if line.len() > 16 && !line.contains(' ') {
            let lower_line = line.to_lowercase();
            if !lower_line.contains("dummy") && !lower_line.contains("test") {
                if let Ok(true) = entropy::is_highly_random(line, 4.5) {
                    print_alert(path, line_num, "High Entropy Token (Unknown Secret)");
                    leaks_found += 1;
                }
            }
        }
    };

    // Route execution based on CLI flag
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
    println!("\n{}", "=".repeat(50).bright_black());
    
    if leaks_found > 0 {
        println!("{} {} leaks found in {:.2?}", "⚠️  Audit Failed:".red().bold(), leaks_found, duration);
        std::process::exit(1);
    } else {
        println!("{} Workspace is secure. (Scanned in {:.2?})", "✅ Audit Passed:".green().bold(), duration);
        std::process::exit(0);
    }
}

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