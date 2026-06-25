//! Constraint-system metrics.

/// Counts of multipliers and constraints in a constraint system.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Metrics {
    /// Multiplication gates allocated.
    pub multipliers: usize,
    /// Total constraints (phase one + phase two).
    pub constraints: usize,
    /// Phase-one constraints.
    pub phase_one_constraints: usize,
    /// Phase-two (randomized) callbacks registered.
    ///
    /// This counts callbacks passed to `specify_randomized_constraints`,
    /// not the constraints those callbacks add when run. The callbacks do
    /// not execute until `create_randomized_constraints` runs in
    /// `prove_and_return_transcript`, so `metrics()` cannot count their
    /// actual constraint output. Read this as "how many randomized phases
    /// are queued", not "how many constraints phase two added".
    pub phase_two_constraints: usize,
}
