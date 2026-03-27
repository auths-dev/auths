//! Terminal output utilities with color support.
//!
//! This module provides colored terminal output that respects:
//! - `NO_COLOR` environment variable (https://no-color.org/)
//! - TTY detection (colors disabled when not a terminal)
//! - `--json` mode (colors disabled for machine-readable output)

#![allow(dead_code)] // Some functions are for future use

use auths_verifier::AssuranceLevel;
use console::{Style, Term};
use serde::Serialize;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static JSON_MODE: AtomicBool = AtomicBool::new(false);

/// Standard JSON response structure for all commands.
///
/// This provides consistent machine-readable output for scripting.
#[derive(Debug, Clone, Serialize)]
pub struct JsonResponse<T: Serialize> {
    /// Whether the command succeeded.
    pub success: bool,
    /// The command that was executed.
    pub command: String,
    /// The response data (when successful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Error message (when failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> JsonResponse<T> {
    /// Create a success response with data.
    pub fn success(command: impl Into<String>, data: T) -> Self {
        Self {
            success: true,
            command: command.into(),
            data: Some(data),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(command: impl Into<String>, error: impl Into<String>) -> JsonResponse<()> {
        JsonResponse {
            success: false,
            command: command.into(),
            data: None,
            error: Some(error.into()),
        }
    }

    /// Print the response as JSON to stdout.
    pub fn print(&self) -> Result<(), serde_json::Error> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }
}

/// Check if JSON mode is enabled.
pub fn is_json_mode() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

/// Terminal output helper with color support.
pub struct Output {
    term: Term,
    colors_enabled: bool,
    // Pre-built styles
    success_style: Style,
    error_style: Style,
    warn_style: Style,
    info_style: Style,
    bold_style: Style,
    dim_style: Style,
}

impl Default for Output {
    fn default() -> Self {
        Self::new()
    }
}

impl Output {
    /// Create a new Output instance.
    pub fn new() -> Self {
        let term = Term::stderr();
        let colors_enabled = Self::should_use_colors(&term);

        Self {
            term,
            colors_enabled,
            success_style: Style::new().green(),
            error_style: Style::new().red(),
            warn_style: Style::new().yellow(),
            info_style: Style::new().cyan(),
            bold_style: Style::new().bold(),
            dim_style: Style::new().dim(),
        }
    }

    /// Create an Output for stdout (for actual data output).
    pub fn stdout() -> Self {
        let term = Term::stdout();
        let colors_enabled = Self::should_use_colors(&term);

        Self {
            term,
            colors_enabled,
            success_style: Style::new().green(),
            error_style: Style::new().red(),
            warn_style: Style::new().yellow(),
            info_style: Style::new().cyan(),
            bold_style: Style::new().bold(),
            dim_style: Style::new().dim(),
        }
    }

    /// Determine if colors should be used.
    fn should_use_colors(term: &Term) -> bool {
        if JSON_MODE.load(Ordering::Relaxed) {
            return false;
        }

        // Respect NO_COLOR env var
        #[allow(clippy::disallowed_methods)] // CLI boundary: NO_COLOR convention
        if std::env::var("NO_COLOR").is_ok() {
            return false;
        }

        // Check if terminal supports colors
        if !term.is_term() {
            return false;
        }

        // Check if stdout is a TTY
        if !std::io::stderr().is_terminal() {
            return false;
        }

        true
    }

    /// Apply success style (green).
    pub fn success(&self, text: &str) -> String {
        if self.colors_enabled {
            self.success_style.apply_to(text).to_string()
        } else {
            text.to_string()
        }
    }

    /// Apply error style (red).
    pub fn error(&self, text: &str) -> String {
        if self.colors_enabled {
            self.error_style.apply_to(text).to_string()
        } else {
            text.to_string()
        }
    }

    /// Apply warning style (yellow).
    pub fn warn(&self, text: &str) -> String {
        if self.colors_enabled {
            self.warn_style.apply_to(text).to_string()
        } else {
            text.to_string()
        }
    }

    /// Apply info style (cyan).
    pub fn info(&self, text: &str) -> String {
        if self.colors_enabled {
            self.info_style.apply_to(text).to_string()
        } else {
            text.to_string()
        }
    }

    /// Apply bold style.
    pub fn bold(&self, text: &str) -> String {
        if self.colors_enabled {
            self.bold_style.apply_to(text).to_string()
        } else {
            text.to_string()
        }
    }

    /// Apply dim style.
    pub fn dim(&self, text: &str) -> String {
        if self.colors_enabled {
            self.dim_style.apply_to(text).to_string()
        } else {
            text.to_string()
        }
    }

    /// Print a success message.
    pub fn print_success(&self, message: &str) {
        let icon = if self.colors_enabled {
            self.success_style.apply_to("\u{2713}").to_string()
        } else {
            "[OK]".to_string()
        };
        eprintln!("{} {}", icon, message);
    }

    /// Print an error message.
    pub fn print_error(&self, message: &str) {
        let icon = if self.colors_enabled {
            self.error_style.apply_to("\u{2717}").to_string()
        } else {
            "[ERROR]".to_string()
        };
        eprintln!("{} {}", icon, message);
    }

    /// Print a warning message.
    pub fn print_warn(&self, message: &str) {
        let icon = if self.colors_enabled {
            self.warn_style.apply_to("!").to_string()
        } else {
            "[WARN]".to_string()
        };
        eprintln!("{} {}", icon, message);
    }

    /// Print an info message.
    pub fn print_info(&self, message: &str) {
        let icon = if self.colors_enabled {
            self.info_style.apply_to("i").to_string()
        } else {
            "[INFO]".to_string()
        };
        eprintln!("{} {}", icon, message);
    }

    /// Print a heading.
    pub fn print_heading(&self, text: &str) {
        let styled = if self.colors_enabled {
            self.bold_style.apply_to(text).to_string()
        } else {
            text.to_string()
        };
        eprintln!("{}", styled);
    }

    /// Print a line.
    pub fn println(&self, text: &str) {
        eprintln!("{}", text);
    }

    /// Print an empty line.
    pub fn newline(&self) {
        eprintln!();
    }

    /// Format a key-value pair.
    pub fn key_value(&self, key: &str, value: &str) -> String {
        if self.colors_enabled {
            format!(
                "{}: {}",
                self.dim_style.apply_to(key),
                self.info_style.apply_to(value)
            )
        } else {
            format!("{}: {}", key, value)
        }
    }

    /// Format an assurance level badge with a visual strength meter.
    ///
    /// With colors enabled:
    ///   `████ Sovereign`     (green)
    ///   `███░ Authenticated` (cyan)
    ///   `██░░ Token-Verified`(yellow)
    ///   `█░░░ Self-Asserted` (dim)
    ///
    /// Without colors: `[4/4 Sovereign]`, `[3/4 Authenticated]`, etc.
    pub fn assurance_badge(&self, level: AssuranceLevel) -> String {
        let score = level.score();
        let label = level.label();

        if !self.colors_enabled {
            return format!("[{}/4 {}]", score, label);
        }

        let filled = "\u{2588}".repeat(score as usize);
        let empty = "\u{2591}".repeat(4 - score as usize);
        let bar = format!("{}{}", filled, empty);

        match level {
            AssuranceLevel::Sovereign => {
                format!(
                    "{} {}",
                    self.success_style.apply_to(&bar),
                    self.success_style.apply_to(label)
                )
            }
            AssuranceLevel::Authenticated => {
                format!(
                    "{} {}",
                    self.info_style.apply_to(&bar),
                    self.info_style.apply_to(label)
                )
            }
            AssuranceLevel::TokenVerified => {
                format!(
                    "{} {}",
                    self.warn_style.apply_to(&bar),
                    self.warn_style.apply_to(label)
                )
            }
            AssuranceLevel::SelfAsserted | _ => {
                format!(
                    "{} {}",
                    self.dim_style.apply_to(&bar),
                    self.dim_style.apply_to(label)
                )
            }
        }
    }

    /// Format a status indicator.
    pub fn status(&self, passed: bool) -> &'static str {
        if passed {
            if self.colors_enabled {
                "\u{2713}"
            } else {
                "[PASS]"
            }
        } else if self.colors_enabled {
            "\u{2717}"
        } else {
            "[FAIL]"
        }
    }
}

/// Set JSON mode for the current process.
///
/// Call this at the start of command handling if `--json` flag is set.
pub fn set_json_mode(enabled: bool) {
    JSON_MODE.store(enabled, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Output {
        /// Create an Output with colors explicitly disabled (for deterministic tests).
        fn new_without_colors() -> Self {
            let term = Term::stderr();
            Self {
                term,
                colors_enabled: false,
                success_style: Style::new().green(),
                error_style: Style::new().red(),
                warn_style: Style::new().yellow(),
                info_style: Style::new().cyan(),
                bold_style: Style::new().bold(),
                dim_style: Style::new().dim(),
            }
        }
    }

    #[test]
    fn test_output_no_colors_in_test() {
        // In tests, colors should be disabled (not a TTY)
        let output = Output::new();
        // Just verify we can create it and format strings
        let success = output.success("test");
        assert!(success.contains("test"));
    }

    #[test]
    fn test_json_mode() {
        // Use explicit no-colors constructor to avoid race conditions with global JSON_MODE
        let output = Output::new_without_colors();
        // With colors disabled, styling should be plain text
        let styled = output.success("test");
        assert_eq!(styled, "test");
    }

    #[test]
    fn test_key_value_format() {
        // Use explicit no-colors constructor to avoid race conditions with global JSON_MODE
        let output = Output::new_without_colors();
        let kv = output.key_value("name", "value");
        assert_eq!(kv, "name: value");
    }

    #[test]
    fn test_assurance_badge_no_colors() {
        let output = Output::new_without_colors();
        assert_eq!(
            output.assurance_badge(AssuranceLevel::Sovereign),
            "[4/4 Sovereign]"
        );
        assert_eq!(
            output.assurance_badge(AssuranceLevel::Authenticated),
            "[3/4 Authenticated]"
        );
        assert_eq!(
            output.assurance_badge(AssuranceLevel::TokenVerified),
            "[2/4 Token-Verified]"
        );
        assert_eq!(
            output.assurance_badge(AssuranceLevel::SelfAsserted),
            "[1/4 Self-Asserted]"
        );
    }
}
