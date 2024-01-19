pub(crate) const DEFAULT_HASH_LENGTH: u32 = 32;
pub(crate) const EXIT_STATUS_ERROR: i32 = 2;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 1;

pub(crate) const ARGON_MEM_COST_RECOMMENDED: u32 = 10000;
pub(crate) const ARGON_LANES_RECOMMENDED: u32 = 4;
pub(crate) const ARGON_ITERATIONS_RECOMMENDED: u32 = 8;

// tool name
pub(crate) const TOOL_NAME: &str = std::env!("CARGO_PKG_NAME");