//! ZHTP Blockchain Package
//! 
//! Core blockchain implementation with zero-knowledge transactions
//! and quantum-resistant consensus integration. Focuses on blockchain
//! fundamentals while delegating specialized functionality to other packages.

// External dependencies
extern crate zhtp_crypto;
extern crate zhtp_zk;
extern crate zhtp_identity;
// Economics package integration available when feature enabled
#[cfg(feature = "economics")]
extern crate zhtp_economics;

pub mod types;
pub mod transaction;
pub mod block;
pub mod blockchain;
pub mod mempool;
pub mod integration;
pub mod utils;

// Re-export core types for convenience
pub use types::*;
pub use transaction::*;
pub use block::*;
pub use blockchain::*;
pub use mempool::*;
pub use utils::*;

/// ZHTP blockchain protocol version
pub const BLOCKCHAIN_VERSION: u32 = 1;

/// Maximum block size in bytes (1MB)
pub const MAX_BLOCK_SIZE: usize = 1_048_576;

/// Target block time in seconds (10 seconds)
pub const TARGET_BLOCK_TIME: u64 = 10;

/// Maximum transactions per block
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 4096;

/// Genesis block timestamp (January 1, 2022 00:00:00 UTC)
pub const GENESIS_TIMESTAMP: u64 = 1640995200;

/// Initial difficulty for proof of work
pub const INITIAL_DIFFICULTY: u32 = 0x1d00ffff;

/// Difficulty adjustment interval (blocks)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

/// Target timespan for difficulty adjustment (2 weeks)
pub const TARGET_TIMESPAN: u64 = 14 * 24 * 60 * 60;

/// Maximum nullifier cache size
pub const MAX_NULLIFIER_CACHE: usize = 1_000_000;

/// Maximum UTXO cache size  
pub const MAX_UTXO_CACHE: usize = 10_000_000;

/// Genesis block message
pub const GENESIS_MESSAGE: &[u8] = b"In the beginning was the Word, and the Word was ZHTP";
