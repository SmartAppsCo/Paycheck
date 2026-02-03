//! Audit test to ensure errors are logged before being discarded.
//!
//! This test prevents regression of the pattern where errors are silently converted
//! to error responses without logging, making production debugging nearly impossible.

use std::fs;
use std::path::Path;

/// Pattern that indicates silent error discarding.
/// `map_err(|_|` discards the error without logging.
const FORBIDDEN_PATTERN: &str = "map_err(|_|";

/// Recursively collect all .rs files in a directory.
fn collect_rs_files(dir: &Path, files: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                if let Some(path_str) = path.to_str() {
                    files.push(path_str.to_string());
                }
            }
        }
    }
}

/// Check if a map_err closure at the given position contains logging.
/// Returns true if logging is present (no violation), false if missing (violation).
fn closure_has_logging(content: &str, start_pos: usize) -> bool {
    // Find the closing of this map_err call by counting braces/parens
    let bytes = content.as_bytes();
    let mut depth = 0;
    let mut in_closure = false;
    let mut closure_content = String::new();

    for i in start_pos..bytes.len() {
        let ch = bytes[i] as char;

        if ch == '|' && !in_closure {
            in_closure = true;
            continue;
        }

        if in_closure {
            if ch == '{' || ch == '(' {
                depth += 1;
            } else if ch == '}' || ch == ')' {
                if depth == 0 {
                    // End of map_err call
                    break;
                }
                depth -= 1;
            }
            closure_content.push(ch);
        }
    }

    // Check if the closure contains any tracing call
    closure_content.contains("tracing::")
}

#[test]
fn errors_must_be_logged_before_discarding() {
    let mut violations = Vec::new();
    let mut rs_files = Vec::new();

    collect_rs_files(Path::new("src"), &mut rs_files);

    for file_path in &rs_files {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: Failed to read {}: {}", file_path, e);
                continue;
            }
        };

        // Find all occurrences of the forbidden pattern
        let mut search_start = 0;
        while let Some(pos) = content[search_start..].find(FORBIDDEN_PATTERN) {
            let absolute_pos = search_start + pos;

            // Check if this closure contains logging
            if !closure_has_logging(&content, absolute_pos) {
                // Find the line number
                let line_num = content[..absolute_pos].matches('\n').count() + 1;
                let line = content.lines().nth(line_num - 1).unwrap_or("");

                violations.push(format!("{}:{}: {}", file_path, line_num, line.trim()));
            }

            search_start = absolute_pos + FORBIDDEN_PATTERN.len();
        }
    }

    if !violations.is_empty() {
        panic!(
            "Found {} instance(s) of silent error discarding (map_err(|_|) without logging).\n\
             Errors should be logged before being discarded.\n\n\
             Use this pattern instead:\n\
             .map_err(|e| {{\n    \
                 tracing::warn!(\"Description of operation: {{}}\", e);\n    \
                 AppError::SomeVariant(\"User-facing message\".into())\n\
             }})\n\n\
             Or if the error type doesn't implement Display:\n\
             .map_err(|_| {{\n    \
                 tracing::warn!(\"Description with context\");\n    \
                 AppError::SomeVariant(\"User-facing message\".into())\n\
             }})\n\n\
             Violations:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}

#[test]
fn test_pattern_detection() {
    // Verify the pattern detection works correctly
    let bad_code = r#"
        let conn = state.db.get().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    "#;

    let good_code = r#"
        let conn = state.db.get().map_err(|e| {
            tracing::error!("Failed to get database connection: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    "#;

    assert!(
        bad_code.contains(FORBIDDEN_PATTERN),
        "Pattern should detect bad code"
    );
    assert!(
        !good_code.contains(FORBIDDEN_PATTERN),
        "Pattern should not flag good code"
    );
}
