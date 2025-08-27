//! Main blockchain data structure and implementation
//! 
//! Contains the core Blockchain struct and its methods, extracted from the original
//! blockchain.rs implementation with proper modularization.

use std::collections::{HashMap, HashSet};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use tracing::{info, warn};
use crate::types::{Hash, Difficulty};
use crate::transaction::{Transaction, TransactionInput, TransactionOutput, IdentityTransactionData};
use crate::types::transaction_type::TransactionType;
use crate::block::{Block, BlockHeader};
use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
use crate::integration::zk_integration::ZkTransactionProof;

/// Blockchain state with identity registry and UTXO management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    /// All blocks in the chain
    pub blocks: Vec<Block>,
    /// Current blockchain height
    pub height: u64,
    /// Current mining difficulty
    pub difficulty: Difficulty,
    /// Total work done (cumulative difficulty)
    pub total_work: u128,
    /// UTXO set for transaction validation
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    /// Used nullifiers to prevent double-spending
    pub nullifier_set: HashSet<Hash>,
    /// Pending transactions waiting to be mined
    pub pending_transactions: Vec<Transaction>,
    /// On-chain identity registry (DID -> Identity data)
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    /// Identity DID to block height mapping for verification
    pub identity_blocks: HashMap<String, u64>,
    /// Economics transaction storage (handled by zhtp-economics)
    pub economics_transactions: Vec<EconomicsTransaction>,
}

/// Economics transaction record (simplified for blockchain package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsTransaction {
    pub tx_id: Hash,
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub tx_type: String,
    pub timestamp: u64,
    pub block_height: u64,
}

impl Blockchain {
    /// Create a new blockchain with genesis block
    pub fn new() -> Result<Self> {
        let genesis_block = crate::block::create_genesis_block();
        
        let mut blockchain = Blockchain {
            blocks: vec![genesis_block.clone()],
            height: 0,
            difficulty: Difficulty::from_bits(crate::INITIAL_DIFFICULTY),
            total_work: 0,
            utxo_set: HashMap::new(),
            nullifier_set: HashSet::new(),
            pending_transactions: Vec::new(),
            identity_registry: HashMap::new(),
            identity_blocks: HashMap::new(),
            economics_transactions: Vec::new(),
        };

        blockchain.update_utxo_set(&genesis_block)?;
        Ok(blockchain)
    }

    /// Add a new block to the chain
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        // Verify the block
        let previous_block = self.blocks.last();
        if !self.verify_block(&block, previous_block)? {
            return Err(anyhow::anyhow!("Invalid block"));
        }

        // Check for double spends
        for tx in &block.transactions {
            for input in &tx.inputs {
                if self.nullifier_set.contains(&input.nullifier) {
                    return Err(anyhow::anyhow!("Double spend detected"));
                }
            }
        }

        // Update blockchain state
        self.blocks.push(block.clone());
        self.height += 1;
        self.update_utxo_set(&block)?;
        self.adjust_difficulty()?;
        
        // Remove processed transactions from pending pool
        self.remove_pending_transactions(&block.transactions);

        // Process identity transactions
        self.process_identity_transactions(&block)?;

        Ok(())
    }

    /// Verify a block against the current chain state
    pub fn verify_block(&self, block: &Block, previous_block: Option<&Block>) -> Result<bool> {
        info!("🔍 Starting block verification for height {}", block.height());
        
        // Verify block header
        if let Some(prev) = previous_block {
            if block.previous_hash() != prev.hash() {
                warn!("🔍 Previous hash mismatch: block={:?}, prev={:?}", block.previous_hash(), prev.hash());
                return Ok(false);
            }
            if block.height() != prev.height() + 1 {
                warn!("🔍 Height mismatch: block={}, expected={}", block.height(), prev.height() + 1);
                return Ok(false);
            }
        }

        // Verify proof of work - skip for consensus/system blocks with easy difficulty
        if block.difficulty().bits() < 0x1fffffff {
            if !block.header.meets_difficulty_target() {
                warn!("🔍 Block does not meet difficulty target");
                return Ok(false);
            }
        } else {
            // For consensus blocks with easy difficulty, just check it's reasonable
            if block.difficulty().bits() != 0x1fffffff {
                warn!("🔍 Easy difficulty mismatch: {}", block.difficulty().bits());
                return Ok(false);
            }
        }

        // Verify all transactions
        for (i, tx) in block.transactions.iter().enumerate() {
            if !self.verify_transaction(tx)? {
                warn!("🔍 Transaction {} failed verification in block", i);
                return Ok(false);
            }
        }

        // Verify Merkle root
        if !block.verify_merkle_root() {
            warn!("🔍 Merkle root verification failed");
            return Ok(false);
        }

        info!("🔍 Block verification successful for height {}", block.height());
        Ok(true)
    }

    /// Verify a transaction against current blockchain state
    pub fn verify_transaction(&self, transaction: &Transaction) -> Result<bool> {
        // Use the transaction validation module
        let validator = crate::transaction::validation::TransactionValidator::new();
        let result = validator.validate_transaction(transaction);
        
        if let Err(ref error) = result {
            warn!("🔍 Transaction validation failed: {:?}", error);
            warn!("🔍 Transaction details: inputs={}, outputs={}, fee={}, type={:?}", 
                transaction.inputs.len(), 
                transaction.outputs.len(), 
                transaction.fee,
                transaction.transaction_type);
        }
        
        Ok(result.is_ok())
    }

    /// Update UTXO set with new block
    fn update_utxo_set(&mut self, block: &Block) -> Result<()> {
        for tx in &block.transactions {
            // Remove spent outputs (add nullifiers)
            for input in &tx.inputs {
                self.nullifier_set.insert(input.nullifier);
            }

            // Add new outputs
            for (index, output) in tx.outputs.iter().enumerate() {
                let output_id = self.calculate_output_id(&tx.hash(), index);
                self.utxo_set.insert(output_id, output.clone());
            }
        }

        Ok(())
    }

    /// Calculate output ID from transaction hash and index
    fn calculate_output_id(&self, tx_hash: &Hash, index: usize) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(tx_hash.as_bytes());
        data.extend_from_slice(&index.to_le_bytes());
        crate::types::hash::blake3_hash(&data)
    }

    /// Adjust mining difficulty based on block times
    fn adjust_difficulty(&mut self) -> Result<()> {
        if self.height % crate::DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
            return Ok(());
        }

        if self.height < crate::DIFFICULTY_ADJUSTMENT_INTERVAL {
            return Ok(());
        }

        let current_block = &self.blocks[self.height as usize];
        let interval_start = &self.blocks[(self.height - crate::DIFFICULTY_ADJUSTMENT_INTERVAL) as usize];
        
        let actual_timespan = current_block.timestamp() - interval_start.timestamp();
        let actual_timespan = actual_timespan.max(crate::TARGET_TIMESPAN / 4).min(crate::TARGET_TIMESPAN * 4);

        let new_difficulty_bits = (self.difficulty.bits() as u64 * crate::TARGET_TIMESPAN / actual_timespan) as u32;
        self.difficulty = Difficulty::from_bits(new_difficulty_bits);

        tracing::info!(
            "Difficulty adjusted from {} to {} at height {}",
            self.difficulty.bits(),
            new_difficulty_bits,
            self.height
        );

        Ok(())
    }

    /// Get the latest block
    pub fn latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }

    /// Get block by height
    pub fn get_block(&self, height: u64) -> Option<&Block> {
        if height >= self.blocks.len() as u64 {
            return None;
        }
        Some(&self.blocks[height as usize])
    }

    /// Get current blockchain height
    pub fn get_height(&self) -> u64 {
        self.height
    }

    /// Check if a nullifier has been used
    pub fn is_nullifier_used(&self, nullifier: &Hash) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    /// Get pending transactions
    pub fn get_pending_transactions(&self) -> Vec<Transaction> {
        self.pending_transactions.clone()
    }

    /// Add a transaction to the pending pool
    pub fn add_pending_transaction(&mut self, transaction: Transaction) -> Result<()> {
        // Verify transaction before adding to pool
        if !self.verify_transaction(&transaction)? {
            return Err(anyhow::anyhow!("Transaction verification failed"));
        }

        self.pending_transactions.push(transaction);
        Ok(())
    }

    /// Remove transactions from pending pool
    pub fn remove_pending_transactions(&mut self, transactions: &[Transaction]) {
        let tx_hashes: HashSet<Hash> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        
        self.pending_transactions.retain(|tx| !tx_hashes.contains(&tx.hash()));
    }

    // ===== IDENTITY MANAGEMENT METHODS =====

    /// Register a new identity on the blockchain
    pub fn register_identity(&mut self, identity_data: IdentityTransactionData) -> Result<Hash> {
        // Check if identity already exists
        if self.identity_registry.contains_key(&identity_data.did) {
            return Err(anyhow::anyhow!("Identity {} already exists on blockchain", identity_data.did));
        }

        // Create identity registration transaction
        let registration_tx = Transaction::new_identity_registration(
            identity_data.clone(),
            vec![], // Fee outputs handled separately
            Signature {
                signature: identity_data.ownership_proof.clone(),
                public_key: PublicKey::new(identity_data.public_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: identity_data.created_at,
            },
            format!("Identity registration for {}", identity_data.did).into_bytes(),
        );

        // Add to pending transactions for inclusion in next block
        self.add_pending_transaction(registration_tx.clone())?;

        // Store in identity registry immediately for queries
        self.identity_registry.insert(identity_data.did.clone(), identity_data.clone());
        self.identity_blocks.insert(identity_data.did.clone(), self.height + 1);

        Ok(registration_tx.hash())
    }

    /// Get identity data from blockchain
    pub fn get_identity(&self, did: &str) -> Option<&IdentityTransactionData> {
        self.identity_registry.get(did)
    }

    /// Check if identity exists on blockchain
    pub fn identity_exists(&self, did: &str) -> bool {
        self.identity_registry.contains_key(did)
    }

    /// Update an existing identity on the blockchain
    pub fn update_identity(&mut self, did: &str, updated_data: IdentityTransactionData) -> Result<Hash> {
        // Check if identity exists
        if !self.identity_registry.contains_key(did) {
            return Err(anyhow::anyhow!("Identity {} not found on blockchain", did));
        }

        // Create update transaction with authorization
        let auth_input = TransactionInput {
            previous_output: Hash::default(),
            output_index: 0,
            nullifier: crate::types::hash::blake3_hash(&format!("identity_update_{}", did).as_bytes()),
            zk_proof: ZkTransactionProof::default(),
        };

        let update_tx = Transaction::new_identity_update(
            updated_data.clone(),
            vec![auth_input],
            vec![], // No outputs needed
            100,    // Update fee
            Signature {
                signature: updated_data.ownership_proof.clone(),
                public_key: PublicKey::new(updated_data.public_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: updated_data.created_at,
            },
            format!("Identity update for {}", did).into_bytes(),
        );

        // Add to pending transactions
        self.add_pending_transaction(update_tx.clone())?;

        // Update registry
        self.identity_registry.insert(did.to_string(), updated_data);

        Ok(update_tx.hash())
    }

    /// Revoke an identity on the blockchain
    pub fn revoke_identity(&mut self, did: &str, authorizing_signature: Vec<u8>) -> Result<Hash> {
        // Check if identity exists
        if !self.identity_registry.contains_key(did) {
            return Err(anyhow::anyhow!("Identity {} not found on blockchain", did));
        }

        // Create authorization input from existing identity
        let auth_input = TransactionInput {
            previous_output: Hash::default(),
            output_index: 0,
            nullifier: crate::types::hash::blake3_hash(&format!("identity_revoke_{}", did).as_bytes()),
            zk_proof: ZkTransactionProof::default(),
        };

        let revocation_tx = Transaction::new_identity_revocation(
            did.to_string(),
            vec![auth_input],
            50, // Revocation fee
            Signature {
                signature: authorizing_signature,
                public_key: PublicKey::new(vec![]), // Would be filled from auth
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: crate::utils::time::current_timestamp(),
            },
            format!("Identity revocation for {}", did).into_bytes(),
        );

        // Add to pending transactions
        self.add_pending_transaction(revocation_tx.clone())?;

        // Remove from registry (mark as revoked)
        if let Some(mut identity_data) = self.identity_registry.remove(did) {
            identity_data.identity_type = "revoked".to_string();
            self.identity_registry.insert(format!("{}_revoked", did), identity_data);
        }

        Ok(revocation_tx.hash())
    }

    /// Get all identities on the blockchain
    pub fn list_all_identities(&self) -> Vec<&IdentityTransactionData> {
        self.identity_registry.values().collect()
    }

    /// Get all identities as HashMap
    pub fn get_all_identities(&self) -> &HashMap<String, IdentityTransactionData> {
        &self.identity_registry
    }

    /// Get identity block confirmation count
    pub fn get_identity_confirmations(&self, did: &str) -> Option<u64> {
        self.identity_blocks.get(did).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    /// Process identity transactions in a block
    pub fn process_identity_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if transaction.transaction_type.is_identity_transaction() {
                if let Some(ref identity_data) = transaction.identity_data {
                    match transaction.transaction_type {
                        TransactionType::IdentityRegistration => {
                            self.identity_registry.insert(
                                identity_data.did.clone(),
                                identity_data.clone()
                            );
                            self.identity_blocks.insert(
                                identity_data.did.clone(),
                                block.height()
                            );
                        }
                        TransactionType::IdentityUpdate => {
                            self.identity_registry.insert(
                                identity_data.did.clone(),
                                identity_data.clone()
                            );
                        }
                        TransactionType::IdentityRevocation => {
                            let mut revoked_data = identity_data.clone();
                            revoked_data.identity_type = "revoked".to_string();
                            self.identity_registry.insert(
                                format!("{}_revoked", identity_data.did),
                                revoked_data
                            );
                            self.identity_registry.remove(&identity_data.did);
                        }
                        _ => {} // Other transaction types
                    }
                }
            }
        }
        Ok(())
    }

    /// Store an economics transaction on the blockchain
    pub fn store_economics_transaction(&mut self, transaction: EconomicsTransaction) {
        self.economics_transactions.push(transaction);
    }

    /// Get all economics transactions for a specific address
    pub fn get_transactions_for_address(&self, address: &str) -> Vec<serde_json::Value> {
        let address_bytes = if address.len() == 64 {
            address.as_bytes().to_vec()
        } else {
            let mut addr_bytes = [0u8; 32];
            let input_bytes = address.as_bytes();
            let copy_len = std::cmp::min(input_bytes.len(), 32);
            addr_bytes[..copy_len].copy_from_slice(&input_bytes[..copy_len]);
            addr_bytes.to_vec()
        };

        let mut address_array = [0u8; 32];
        if address_bytes.len() >= 32 {
            address_array.copy_from_slice(&address_bytes[..32]);
        } else {
            address_array[..address_bytes.len()].copy_from_slice(&address_bytes);
        }

        self.economics_transactions
            .iter()
            .filter(|tx| tx.to == address_array || tx.from == address_array)
            .map(|tx| {
                serde_json::json!({
                    "id": format!("{:?}", tx.tx_id),
                    "hash": format!("{:?}", tx.tx_id),
                    "from": format!("{:?}", tx.from),
                    "to": format!("{:?}", tx.to),
                    "amount": tx.amount,
                    "transaction_type": tx.tx_type,
                    "timestamp": tx.timestamp,
                    "block_height": tx.block_height,
                })
            })
            .collect()
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new().expect("Failed to create default blockchain")
    }
}
