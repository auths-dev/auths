//! Progressive disclosure guided setup flow.
//!
//! Wraps the existing init workflow with numbered section headings
//! so new users can follow along step by step.

use crate::ux::format::Output;

pub(crate) struct GuidedSetup<'a> {
    out: &'a Output,
    total_steps: usize,
    current_step: usize,
}

impl<'a> GuidedSetup<'a> {
    pub fn new(out: &'a Output, total_steps: usize) -> Self {
        Self {
            out,
            total_steps,
            current_step: 0,
        }
    }

    /// Display a section heading with step progress.
    pub fn section(&mut self, title: &str) {
        self.current_step += 1;
        self.out.newline();
        self.out.print_heading(&format!(
            "[{}/{}] {}",
            self.current_step, self.total_steps, title
        ));
        self.out.newline();
    }
}

/// Number of guided steps for each profile.
pub(crate) fn developer_steps() -> usize {
    5
}

pub(crate) fn ci_steps() -> usize {
    3
}

pub(crate) fn agent_steps() -> usize {
    3
}
