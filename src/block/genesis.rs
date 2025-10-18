//! Network-specific genesis block creation
//!
//! Provides genesis block configurations for different ZHTP networks:
//! - Mainnet: Production network (chain_id: 0x01)
//! - Testnet: Testing network (chain_id: 0x02)
//! - Development: Local development (chain_id: 0x03)

use anyhow::Result;
use crate::block::{Block, BlockHeader};
use crate::transaction::{Transaction, TransactionOutput};
use crate::types::{Hash, Difficulty, TransactionType};
use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
use crate::types::hash::blake3_hash;
use crate::transaction::hashing::calculate_transaction_merkle_root;

/// Genesis block configurations for different networks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisConfig {
    /// Production mainnet network
    Mainnet,
    /// Testing network for development and QA
    Testnet,
    /// Local development environment
    Development,
}

impl GenesisConfig {
    /// Get the network identifier string
    pub fn network_id(&self) -> &str {
        match self {
            Self::Mainnet => "zhtp-mainnet",
            Self::Testnet => "zhtp-testnet",
            Self::Development => "zhtp-dev",
        }
    }
    
    /// Get the chain ID for replay protection
    /// - 0x01: Mainnet
    /// - 0x02: Testnet
    /// - 0x03: Development
    pub fn chain_id(&self) -> u8 {
        match self {
            Self::Mainnet => 0x01,
            Self::Testnet => 0x02,
            Self::Development => 0x03,
        }
    }
    
    /// Get the genesis block timestamp (Unix timestamp)
    pub fn genesis_timestamp(&self) -> u64 {
        match self {
            // Mainnet: January 1, 2025 00:00:00 UTC
            Self::Mainnet => 1735689600,
            // Testnet: December 1, 2024 00:00:00 UTC
            Self::Testnet => 1733097600,
            // Development: January 1, 2022 00:00:00 UTC (current default)
            Self::Development => 1640995200,
        }
    }
    
    /// Get the genesis block message
    pub fn genesis_message(&self) -> &[u8] {
        match self {
            Self::Mainnet => b"ZHTP Mainnet - Sovereign Network Genesis - January 2025",
            Self::Testnet => b"ZHTP Testnet - Testing Network Genesis - December 2024",
            Self::Development => b"ZHTP Development - Local Testing Genesis",
        }
    }
    
    /// Get the initial mining difficulty for the network
    pub fn initial_difficulty(&self) -> Difficulty {
        match self {
            // Mainnet: Standard difficulty for production
            Self::Mainnet => Difficulty::from_bits(0x1d00ffff),
            // Testnet: Easier difficulty for faster testing
            Self::Testnet => Difficulty::from_bits(0x1e00ffff),
            // Development: Very easy difficulty for rapid development
            Self::Development => Difficulty::from_bits(0x1fffffff),
        }
    }
    
    /// Get the target block time in seconds
    pub fn target_block_time(&self) -> u64 {
        match self {
            Self::Mainnet => 10,      // 10 seconds for mainnet
            Self::Testnet => 5,       // 5 seconds for testnet
            Self::Development => 2,   // 2 seconds for dev
        }
    }
    
    /// Get the maximum block size in bytes
    pub fn max_block_size(&self) -> usize {
        match self {
            Self::Mainnet => 2_097_152,      // 2 MB for mainnet
            Self::Testnet => 2_097_152,      // 2 MB for testnet
            Self::Development => 1_048_576,  // 1 MB for dev
        }
    }
    
    /// Get the daily UBI amount for this network
    pub fn daily_ubi_amount(&self) -> u64 {
        match self {
            Self::Mainnet => 33,      // 33 ZHTP per day (production)
            Self::Testnet => 50,      // 50 ZHTP per day (testing)
            Self::Development => 100, // 100 ZHTP per day (development)
        }
    }
}

/// Create a network-specific genesis block
pub fn create_genesis_block_for_network(config: GenesisConfig) -> Block {
    let network_id = config.network_id();
    let chain_id = config.chain_id();
    let timestamp = config.genesis_timestamp();
    let message = config.genesis_message();
    let difficulty = config.initial_difficulty();
    
    // Create genesis transaction with network metadata embedded
    let genesis_tx = Transaction {
        version: 1,
        transaction_type: TransactionType::Transfer, // Genesis is a special transfer from network creation
        chain_id, // NEW: Network-specific chain ID for replay protection
        inputs: vec![],
        outputs: vec![
            // Genesis output with network identifier
            TransactionOutput {
                commitment: blake3_hash(format!("{}_genesis_commitment", network_id).as_bytes()),
                note: blake3_hash(message),
                recipient: PublicKey::new(format!("{}_genesis_recipient", network_id).as_bytes().to_vec()),
            }
        ],
        fee: 0,
        signature: Signature {
            signature: format!("{}_genesis_signature", network_id).as_bytes().to_vec(),
            public_key: PublicKey::new(format!("{}_genesis_key", network_id).as_bytes().to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp,
        },
        memo: message.to_vec(),
        wallet_data: None,
        identity_data: None,
    };
    
    // Calculate merkle root from genesis transaction
    let merkle_root = calculate_transaction_merkle_root(&[genesis_tx.clone()]);
    let transaction_size = bincode::serialize(&genesis_tx).map(|data| data.len()).unwrap_or(0);
    
    // Create genesis block header
    let header = BlockHeader::new(
        1,                            // version
        Hash::default(),              // previous_block_hash (none for genesis)
        merkle_root,                  // merkle_root
        timestamp,                    // timestamp
        difficulty,                   // difficulty
        0,                            // height
        1,                            // transaction_count
        transaction_size as u32,      // block_size
        difficulty,                   // cumulative_difficulty
    );
    
    Block::new(header, vec![genesis_tx])
}

/// Create the default genesis block (uses Development network)
/// This maintains backward compatibility with existing code
pub fn create_genesis_block() -> Block {
    create_genesis_block_for_network(GenesisConfig::Development)
}

/// Verify that a block is a valid genesis block for a specific network
pub fn verify_genesis_block(block: &Block, expected_config: GenesisConfig) -> Result<()> {
    // Check height is 0
    if block.height() != 0 {
        return Err(anyhow::anyhow!("Genesis block must have height 0"));
    }
    
    // Check previous hash is default (no previous block)
    if block.previous_hash() != Hash::default() {
        return Err(anyhow::anyhow!("Genesis block must have default previous hash"));
    }
    
    // Check timestamp matches expected
    if block.timestamp() != expected_config.genesis_timestamp() {
        return Err(anyhow::anyhow!(
            "Genesis block timestamp mismatch. Expected {}, got {}",
            expected_config.genesis_timestamp(),
            block.timestamp()
        ));
    }
    
    // Check difficulty matches expected
    if block.difficulty().bits() != expected_config.initial_difficulty().bits() {
        return Err(anyhow::anyhow!(
            "Genesis block difficulty mismatch. Expected {:x}, got {:x}",
            expected_config.initial_difficulty().bits(),
            block.difficulty().bits()
        ));
    }
    
    // Check that genesis transaction exists and has correct chain_id
    if block.transactions.is_empty() {
        return Err(anyhow::anyhow!("Genesis block must contain at least one transaction"));
    }
    
    let genesis_tx = &block.transactions[0];
    if genesis_tx.chain_id != expected_config.chain_id() {
        return Err(anyhow::anyhow!(
            "Genesis transaction chain_id mismatch. Expected {}, got {}",
            expected_config.chain_id(),
            genesis_tx.chain_id
        ));
    }
    
    // Check genesis message in memo
    let expected_message = expected_config.genesis_message();
    if genesis_tx.memo != expected_message {
        return Err(anyhow::anyhow!("Genesis transaction memo does not match expected message"));
    }
    
    Ok(())
}

/// Get genesis configuration from network ID string
pub fn genesis_config_from_network_id(network_id: &str) -> Option<GenesisConfig> {
    match network_id {
        "zhtp-mainnet" => Some(GenesisConfig::Mainnet),
        "zhtp-testnet" => Some(GenesisConfig::Testnet),
        "zhtp-dev" => Some(GenesisConfig::Development),
        _ => None,
    }
}

/// Get genesis configuration from chain ID
pub fn genesis_config_from_chain_id(chain_id: u8) -> Option<GenesisConfig> {
    match chain_id {
        0x01 => Some(GenesisConfig::Mainnet),
        0x02 => Some(GenesisConfig::Testnet),
        0x03 => Some(GenesisConfig::Development),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_config_network_ids() {
        assert_eq!(GenesisConfig::Mainnet.network_id(), "zhtp-mainnet");
        assert_eq!(GenesisConfig::Testnet.network_id(), "zhtp-testnet");
        assert_eq!(GenesisConfig::Development.network_id(), "zhtp-dev");
    }

    #[test]
    fn test_genesis_config_chain_ids() {
        assert_eq!(GenesisConfig::Mainnet.chain_id(), 0x01);
        assert_eq!(GenesisConfig::Testnet.chain_id(), 0x02);
        assert_eq!(GenesisConfig::Development.chain_id(), 0x03);
    }

    #[test]
    fn test_genesis_config_timestamps() {
        assert_eq!(GenesisConfig::Mainnet.genesis_timestamp(), 1735689600);
        assert_eq!(GenesisConfig::Testnet.genesis_timestamp(), 1733097600);
        assert_eq!(GenesisConfig::Development.genesis_timestamp(), 1640995200);
    }

    #[test]
    fn test_create_mainnet_genesis() {
        let genesis = create_genesis_block_for_network(GenesisConfig::Mainnet);
        assert_eq!(genesis.height(), 0);
        assert_eq!(genesis.timestamp(), 1735689600);
        assert!(!genesis.transactions.is_empty());
        assert_eq!(genesis.transactions[0].chain_id, 0x01);
    }

    #[test]
    fn test_create_testnet_genesis() {
        let genesis = create_genesis_block_for_network(GenesisConfig::Testnet);
        assert_eq!(genesis.height(), 0);
        assert_eq!(genesis.timestamp(), 1733097600);
        assert!(!genesis.transactions.is_empty());
        assert_eq!(genesis.transactions[0].chain_id, 0x02);
    }

    #[test]
    fn test_create_dev_genesis() {
        let genesis = create_genesis_block_for_network(GenesisConfig::Development);
        assert_eq!(genesis.height(), 0);
        assert_eq!(genesis.timestamp(), 1640995200);
        assert!(!genesis.transactions.is_empty());
        assert_eq!(genesis.transactions[0].chain_id, 0x03);
    }

    #[test]
    fn test_verify_mainnet_genesis() {
        let genesis = create_genesis_block_for_network(GenesisConfig::Mainnet);
        assert!(verify_genesis_block(&genesis, GenesisConfig::Mainnet).is_ok());
        assert!(verify_genesis_block(&genesis, GenesisConfig::Testnet).is_err());
    }

    #[test]
    fn test_verify_testnet_genesis() {
        let genesis = create_genesis_block_for_network(GenesisConfig::Testnet);
        assert!(verify_genesis_block(&genesis, GenesisConfig::Testnet).is_ok());
        assert!(verify_genesis_block(&genesis, GenesisConfig::Mainnet).is_err());
    }

    #[test]
    fn test_genesis_config_from_network_id() {
        assert_eq!(
            genesis_config_from_network_id("zhtp-mainnet"),
            Some(GenesisConfig::Mainnet)
        );
        assert_eq!(
            genesis_config_from_network_id("zhtp-testnet"),
            Some(GenesisConfig::Testnet)
        );
        assert_eq!(
            genesis_config_from_network_id("zhtp-dev"),
            Some(GenesisConfig::Development)
        );
        assert_eq!(genesis_config_from_network_id("invalid"), None);
    }

    #[test]
    fn test_genesis_config_from_chain_id() {
        assert_eq!(genesis_config_from_chain_id(0x01), Some(GenesisConfig::Mainnet));
        assert_eq!(genesis_config_from_chain_id(0x02), Some(GenesisConfig::Testnet));
        assert_eq!(genesis_config_from_chain_id(0x03), Some(GenesisConfig::Development));
        assert_eq!(genesis_config_from_chain_id(0xFF), None);
    }

    #[test]
    fn test_different_genesis_blocks_have_different_hashes() {
        let mainnet_genesis = create_genesis_block_for_network(GenesisConfig::Mainnet);
        let testnet_genesis = create_genesis_block_for_network(GenesisConfig::Testnet);
        let dev_genesis = create_genesis_block_for_network(GenesisConfig::Development);
        
        // Each network should have a unique genesis block hash
        assert_ne!(mainnet_genesis.hash(), testnet_genesis.hash());
        assert_ne!(mainnet_genesis.hash(), dev_genesis.hash());
        assert_ne!(testnet_genesis.hash(), dev_genesis.hash());
    }
}
