//! Main blockchain data structure and implementation
//! 
//! Contains the core Blockchain struct and its methods, extracted from the original
//! blockchain.rs implementation with proper modularization.

use std::collections::{HashMap, HashSet};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error, debug};
use crate::types::{Hash, Difficulty};
use crate::transaction::{Transaction, TransactionInput, TransactionOutput, IdentityTransactionData};
use crate::types::transaction_type::TransactionType;
use crate::block::Block;
use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
use crate::integration::zk_integration::ZkTransactionProof;
use crate::integration::economic_integration::{EconomicTransactionProcessor, TreasuryStats};
use crate::integration::consensus_integration::{BlockchainConsensusCoordinator, ConsensusStatus};
use crate::integration::storage_integration::{BlockchainStorageManager, BlockchainStorageConfig, StorageOperationResult};

/// Messages for real-time blockchain synchronization
#[derive(Debug, Clone)]
pub enum BlockchainBroadcastMessage {
    /// New block created locally and should be broadcast to peers
    NewBlock(Block),
    /// New transaction submitted locally and should be broadcast to peers
    NewTransaction(Transaction),
}

// Import lib-proofs for recursive proof aggregation
// Import lib-proofs for recursive proof aggregation
use lib_proofs::{
    RecursiveProofAggregator, InstantStateVerifier,
    verifiers::transaction_verifier::{BatchedPrivateTransaction, BatchMetadata}
};

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
    /// On-chain wallet registry (wallet_id -> Wallet data)
    pub wallet_registry: HashMap<String, crate::transaction::WalletTransactionData>,
    /// Wallet ID to block height mapping for verification
    pub wallet_blocks: HashMap<String, u64>,
    /// Economics transaction storage (handled by lib-economy)
    pub economics_transactions: Vec<EconomicsTransaction>,
    /// Smart contract registry - Token contracts (contract_id -> TokenContract)
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    /// Smart contract registry - Web4 Website contracts (contract_id -> Web4Contract)
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    /// Contract deployment block heights (contract_id -> block_height)
    pub contract_blocks: HashMap<[u8; 32], u64>,
    /// On-chain validator registry (identity_id -> Validator info)
    pub validator_registry: HashMap<String, ValidatorInfo>,
    /// Validator registration block heights (identity_id -> block_height)
    pub validator_blocks: HashMap<String, u64>,
    /// Economic transaction processor for lib-economy integration
    #[serde(skip)]
    pub economic_processor: Option<EconomicTransactionProcessor>,
    /// Consensus coordinator for lib-consensus integration
    #[serde(skip)]
    pub consensus_coordinator: Option<std::sync::Arc<tokio::sync::RwLock<BlockchainConsensusCoordinator>>>,
    /// Storage manager for persistent data
    #[serde(skip)]
    pub storage_manager: Option<std::sync::Arc<tokio::sync::RwLock<BlockchainStorageManager>>>,
    /// Recursive proof aggregator for O(1) state verification
    #[serde(skip)]
    pub proof_aggregator: Option<std::sync::Arc<tokio::sync::RwLock<lib_proofs::RecursiveProofAggregator>>>,
    /// Auto-persistence configuration
    pub auto_persist_enabled: bool,
    /// Block counter for auto-persistence
    pub blocks_since_last_persist: u64,
    /// Broadcast channel for real-time block/transaction propagation
    #[serde(skip)]
    pub broadcast_sender: Option<tokio::sync::mpsc::UnboundedSender<BlockchainBroadcastMessage>>,
}

/// Validator information stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator identity ID
    pub identity_id: String,
    /// Staked amount (in micro-ZHTP)
    pub stake: u64,
    /// Storage provided (in bytes)
    pub storage_provided: u64,
    /// Public key for consensus (post-quantum)
    pub consensus_key: Vec<u8>,
    /// Network address for validator communication
    pub network_address: String,
    /// Commission rate (percentage 0-100)
    pub commission_rate: u8,
    /// Validator status
    pub status: String, // "active", "inactive", "jailed", "slashed"
    /// Registration timestamp
    pub registered_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Total blocks validated
    pub blocks_validated: u64,
    /// Slash count
    pub slash_count: u32,
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

/// Blockchain import structure for deserializing received chains
#[derive(Serialize, Deserialize)]
pub struct BlockchainImport {
    pub blocks: Vec<Block>,
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    pub wallet_registry: HashMap<String, crate::transaction::WalletTransactionData>,
    pub validator_registry: HashMap<String, ValidatorInfo>,
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    pub contract_blocks: HashMap<[u8; 32], u64>,
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
            wallet_registry: HashMap::new(),
            wallet_blocks: HashMap::new(),
            economics_transactions: Vec::new(),
            token_contracts: HashMap::new(),
            web4_contracts: HashMap::new(),
            contract_blocks: HashMap::new(),
            validator_registry: HashMap::new(),
            validator_blocks: HashMap::new(),
            economic_processor: Some(EconomicTransactionProcessor::new()),
            consensus_coordinator: None,
            storage_manager: None,
            proof_aggregator: None,
            auto_persist_enabled: true,
            blocks_since_last_persist: 0,
            broadcast_sender: None,
        };

        blockchain.update_utxo_set(&genesis_block)?;
        Ok(blockchain)
    }

    /// Create a new blockchain with storage manager
    pub async fn new_with_storage(storage_config: BlockchainStorageConfig) -> Result<Self> {
        let mut blockchain = Self::new()?;
        blockchain.initialize_storage_manager(storage_config).await?;
        Ok(blockchain)
    }

    /// Initialize the storage manager
    pub async fn initialize_storage_manager(&mut self, config: BlockchainStorageConfig) -> Result<()> {
        info!("🗃️ Initializing blockchain storage manager");
        
        let storage_manager = BlockchainStorageManager::new(config).await?;
        self.storage_manager = Some(std::sync::Arc::new(tokio::sync::RwLock::new(storage_manager)));
        self.auto_persist_enabled = true;
        
        info!("Storage manager initialized successfully");
        Ok(())
    }

    /// Initialize the recursive proof aggregator for O(1) state verification
    pub fn initialize_proof_aggregator(&mut self) -> Result<()> {
        info!("Initializing recursive proof aggregator");
        
        let aggregator = lib_proofs::RecursiveProofAggregator::new()?;
        self.proof_aggregator = Some(std::sync::Arc::new(tokio::sync::RwLock::new(aggregator)));
        
        info!("Recursive proof aggregator initialized successfully");
        Ok(())
    }

    /// Set broadcast channel for real-time block/transaction propagation
    pub fn set_broadcast_channel(&mut self, sender: tokio::sync::mpsc::UnboundedSender<BlockchainBroadcastMessage>) {
        debug!("Blockchain broadcast channel configured");
        self.broadcast_sender = Some(sender);
    }

    /// Load blockchain from persistent storage
    pub async fn load_from_storage(storage_config: BlockchainStorageConfig, content_hash: lib_storage::types::ContentHash) -> Result<Self> {
        info!("Loading blockchain from storage");
        
        let mut storage_manager = BlockchainStorageManager::new(storage_config).await?;
        let mut blockchain = storage_manager.retrieve_blockchain_state(content_hash).await?;
        
        // Re-initialize non-serialized components
        blockchain.economic_processor = Some(EconomicTransactionProcessor::new());
        blockchain.storage_manager = Some(std::sync::Arc::new(tokio::sync::RwLock::new(storage_manager)));
        blockchain.proof_aggregator = None; // Will be initialized on first use
        blockchain.auto_persist_enabled = true;
        blockchain.blocks_since_last_persist = 0;
        
        info!("Blockchain loaded from storage (height: {})", blockchain.height);
        Ok(blockchain)
    }

    /// Persist blockchain state to storage
    pub async fn persist_to_storage(&mut self) -> Result<StorageOperationResult> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            info!(" Persisting blockchain state to storage (height: {})", self.height);
            
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_blockchain_state(self).await?;
            
            self.blocks_since_last_persist = 0;
            
            info!("Blockchain state persisted successfully");
            Ok(result)
        } else {
            Err(anyhow::anyhow!("Storage manager not initialized"))
        }
    }

    /// Backup entire blockchain to distributed storage
    pub async fn backup_to_storage(&mut self) -> Result<Vec<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            info!(" Starting blockchain backup to distributed storage");
            
            let mut storage_manager = storage_manager_arc.write().await;
            let results = storage_manager.backup_blockchain(self).await?;
            
            let successful_backups = results.iter().filter(|r| r.success).count();
            info!("Blockchain backup completed: {}/{} operations successful", 
                  successful_backups, results.len());
            
            Ok(results)
        } else {
            Err(anyhow::anyhow!("Storage manager not initialized"))
        }
    }

    /// Auto-persist if conditions are met
    async fn auto_persist_if_needed(&mut self) -> Result<()> {
        if !self.auto_persist_enabled {
            return Ok(());
        }
        
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let storage_manager = storage_manager_arc.read().await;
            let persist_frequency = storage_manager.get_config().persist_frequency;
            drop(storage_manager);
            
            if self.blocks_since_last_persist >= persist_frequency {
                info!(" Auto-persisting blockchain state (blocks since last persist: {})", 
                      self.blocks_since_last_persist);
                self.persist_to_storage().await?;
            }
        }
        
        Ok(())
    }

    /// Store a block in persistent storage
    pub async fn persist_block(&mut self, block: &Block) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_block(block).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Store a transaction in persistent storage
    pub async fn persist_transaction(&mut self, transaction: &Transaction) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_transaction(transaction).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Store identity data in persistent storage
    pub async fn persist_identity_data(&mut self, did: &str, identity_data: &IdentityTransactionData) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_identity_data(did, identity_data).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Store UTXO set in persistent storage
    pub async fn persist_utxo_set(&mut self) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_utxo_set(&self.utxo_set).await?;
            // Also store using the latest key for recovery
            storage_manager.store_latest_utxo_set(&self.utxo_set).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Persist just the blockchain state (height, difficulty, nullifiers) to storage
    pub async fn persist_blockchain_state(&mut self) -> Result<Option<()>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let storage_manager = storage_manager_arc.read().await;
            
            let state = crate::integration::storage_integration::BlockchainState {
                height: self.height,
                difficulty: self.difficulty.clone(),
                nullifier_set: self.nullifier_set.clone(),
            };
            
            storage_manager.store_latest_blockchain_state(&state).await?;
            
            info!("Blockchain state persisted to storage");
            return Ok(Some(()));
        }
        Ok(None)
    }

    /// Retrieve a block from storage by height
    pub async fn retrieve_block_from_storage(&self, height: u64) -> Result<Option<Block>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            storage_manager.retrieve_block_by_height(height).await
        } else {
            Ok(None)
        }
    }

    /// Perform storage maintenance
    pub async fn perform_storage_maintenance(&mut self) -> Result<()> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            info!(" Performing blockchain storage maintenance");
            
            let mut storage_manager = storage_manager_arc.write().await;
            storage_manager.perform_maintenance().await?;
            
            info!("Storage maintenance completed");
        }
        Ok(())
    }

    /// Get storage statistics
    pub async fn get_storage_statistics(&self) -> Result<Option<lib_storage::UnifiedStorageStats>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let stats = storage_manager.get_storage_statistics().await?;
            Ok(Some(stats))
        } else {
            Ok(None)
        }
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
        self.process_wallet_transactions(&block)?;
        self.process_contract_transactions(&block)?;

        // Update persistence counter
        self.blocks_since_last_persist += 1;

        // Broadcast new block to mesh network (if channel configured)
        if let Some(ref sender) = self.broadcast_sender {
            if let Err(e) = sender.send(BlockchainBroadcastMessage::NewBlock(block.clone())) {
                warn!("Failed to broadcast new block to network: {}", e);
            } else {
                debug!("Block {} broadcast to mesh network", block.height());
            }
        }

        Ok(())
    }

    /// Add a new block to the chain with automatic persistence
    pub async fn add_block_with_persistence(&mut self, block: Block) -> Result<()> {
        // Add block using existing logic
        self.add_block(block.clone())?;

        // Persist the block to storage if storage manager is available
        if let Some(_) = self.persist_block(&block).await? {
            info!(" Block {} persisted to storage", block.height());
        }

        // Persist UTXO set every 10 blocks or if auto-persist is enabled
        if self.auto_persist_enabled && (self.height % 10 == 0 || self.blocks_since_last_persist >= 10) {
            if let Some(_) = self.persist_utxo_set().await? {
                info!(" UTXO set persisted to storage at height {}", self.height);
            }
        }

        // Auto-persist blockchain state if needed
        self.auto_persist_if_needed().await?;

        Ok(())
    }

    /// Verify a block against the current chain state
    pub fn verify_block(&self, block: &Block, previous_block: Option<&Block>) -> Result<bool> {
        info!("Starting block verification for height {}", block.height());
        
        // Verify block header
        if let Some(prev) = previous_block {
            if block.previous_hash() != prev.hash() {
                warn!("Previous hash mismatch: block={:?}, prev={:?}", block.previous_hash(), prev.hash());
                return Ok(false);
            }
            if block.height() != prev.height() + 1 {
                warn!("Height mismatch: block={}, expected={}", block.height(), prev.height() + 1);
                return Ok(false);
            }
        }

        // Verify proof of work - skip for consensus/system blocks with easy difficulty
        if block.difficulty().bits() < 0x1fffffff {
            if !block.header.meets_difficulty_target() {
                warn!("Block does not meet difficulty target");
                return Ok(false);
            }
        } else {
            // For consensus blocks with easy difficulty, just check it's reasonable
            if block.difficulty().bits() != 0x1fffffff {
                warn!("Easy difficulty mismatch: {}", block.difficulty().bits());
                return Ok(false);
            }
        }

        // Verify all transactions
        for (i, tx) in block.transactions.iter().enumerate() {
            if !self.verify_transaction(tx)? {
                warn!("Transaction {} failed verification in block", i);
                return Ok(false);
            }
        }

        // Verify Merkle root
        if !block.verify_merkle_root() {
            warn!("Merkle root verification failed");
            return Ok(false);
        }

        info!("Block verification successful for height {}", block.height());
        Ok(true)
    }

    /// Verify a transaction against current blockchain state
    pub fn verify_transaction(&self, transaction: &Transaction) -> Result<bool> {
        // Use the stateful transaction validator with blockchain context for identity verification
        let validator = crate::transaction::validation::StatefulTransactionValidator::new(self);
        
        // Check if this is a system transaction (empty inputs indicates system transaction)
        let is_system_transaction = transaction.inputs.is_empty();
        
        tracing::info!("Verifying transaction with identity verification enabled");
        tracing::info!("System transaction: {}", is_system_transaction);
        tracing::info!("Transaction type: {:?}", transaction.transaction_type);
        
        let result = validator.validate_transaction_with_state(transaction);
        
        if let Err(ref error) = result {
            tracing::warn!("Transaction validation failed: {:?}", error);
            tracing::warn!("Transaction details: inputs={}, outputs={}, fee={}, type={:?}, system={}", 
                transaction.inputs.len(), 
                transaction.outputs.len(), 
                transaction.fee,
                transaction.transaction_type,
                is_system_transaction);
        } else {
            tracing::info!("Transaction validation passed with identity verification");
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

        self.pending_transactions.push(transaction.clone());

        // Broadcast new transaction to mesh network (if channel configured)
        if let Some(ref sender) = self.broadcast_sender {
            if let Err(e) = sender.send(BlockchainBroadcastMessage::NewTransaction(transaction.clone())) {
                warn!("Failed to broadcast new transaction to network: {}", e);
            } else {
                debug!("Transaction {} broadcast to mesh network", transaction.hash());
            }
        }

        Ok(())
    }

    /// Add a transaction to the pending pool with persistent storage
    pub async fn add_pending_transaction_with_persistence(&mut self, transaction: Transaction) -> Result<()> {
        // Add transaction to pending pool normally
        self.add_pending_transaction(transaction.clone())?;

        // Store transaction in persistent storage if available
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            if let Err(e) = storage_manager.store_transaction(&transaction).await {
                eprintln!("Warning: Failed to persist transaction to storage: {}", e);
            }
        }

        Ok(())
    }

    /// Add system transaction to pending pool without validation (for identity registration, etc.)
    pub fn add_system_transaction(&mut self, transaction: Transaction) -> Result<()> {
        tracing::info!("Adding system transaction to pending pool (bypassing validation)");
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

    /// Register a new identity on the blockchain with persistent storage
    pub async fn register_identity_with_persistence(&mut self, identity_data: IdentityTransactionData) -> Result<Hash> {
        // Register identity normally
        let tx_hash = self.register_identity(identity_data.clone())?;

        // Store identity data in persistent storage if available
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            if let Err(e) = storage_manager.store_identity_data(&identity_data.did, &identity_data).await {
                eprintln!("Warning: Failed to persist identity data to storage: {}", e);
            }
        }

        Ok(tx_hash)
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

    /// Update an existing identity on the blockchain with persistent storage
    pub async fn update_identity_with_persistence(&mut self, did: &str, updated_data: IdentityTransactionData) -> Result<Hash> {
        // Update identity normally
        let tx_hash = self.update_identity(did, updated_data.clone())?;

        // Store updated identity data in persistent storage if available
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            if let Err(e) = storage_manager.store_identity_data(did, &updated_data).await {
                eprintln!("Warning: Failed to persist updated identity data to storage: {}", e);
            }
        }

        Ok(tx_hash)
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

    // ===== WALLET MANAGEMENT METHODS =====

    /// Register a new wallet on the blockchain
    pub fn register_wallet(&mut self, wallet_data: crate::transaction::WalletTransactionData) -> Result<Hash> {
        // Check if wallet already exists
        let wallet_id_str = hex::encode(wallet_data.wallet_id.as_bytes());
        if self.wallet_registry.contains_key(&wallet_id_str) {
            return Err(anyhow::anyhow!("Wallet {} already exists on blockchain", wallet_id_str));
        }

        // Create wallet registration transaction
        let registration_tx = Transaction::new_wallet_registration(
            wallet_data.clone(),
            vec![], // Fee outputs handled separately
            Signature {
                signature: wallet_data.public_key.clone(),
                public_key: PublicKey::new(wallet_data.public_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: wallet_data.created_at,
            },
            format!("Wallet registration for {}", wallet_data.wallet_name).into_bytes(),
        );

        // Add to pending transactions for inclusion in next block
        self.add_pending_transaction(registration_tx.clone())?;

        // Store in wallet registry immediately for queries
        self.wallet_registry.insert(wallet_id_str.clone(), wallet_data.clone());
        self.wallet_blocks.insert(wallet_id_str, self.height + 1);

        Ok(registration_tx.hash())
    }

    /// Get wallet by ID
    pub fn get_wallet(&self, wallet_id: &str) -> Option<&crate::transaction::WalletTransactionData> {
        self.wallet_registry.get(wallet_id)
    }

    /// Check if wallet exists
    pub fn wallet_exists(&self, wallet_id: &str) -> bool {
        self.wallet_registry.contains_key(wallet_id)
    }

    /// Get all wallets on the blockchain
    pub fn list_all_wallets(&self) -> Vec<&crate::transaction::WalletTransactionData> {
        self.wallet_registry.values().collect()
    }

    /// Get all wallets as HashMap
    pub fn get_all_wallets(&self) -> &HashMap<String, crate::transaction::WalletTransactionData> {
        &self.wallet_registry
    }

    /// Get wallet block confirmation count
    pub fn get_wallet_confirmations(&self, wallet_id: &str) -> Option<u64> {
        self.wallet_blocks.get(wallet_id).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    /// Get wallets for a specific owner identity
    pub fn get_wallets_for_owner(&self, owner_identity_id: &Hash) -> Vec<&crate::transaction::WalletTransactionData> {
        self.wallet_registry.values()
            .filter(|wallet| {
                wallet.owner_identity_id.as_ref() == Some(owner_identity_id)
            })
            .collect()
    }

    /// Process wallet transactions in a block
    pub fn process_wallet_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if transaction.transaction_type == TransactionType::WalletRegistration {
                if let Some(ref wallet_data) = transaction.wallet_data {
                    let wallet_id_str = hex::encode(wallet_data.wallet_id.as_bytes());
                    self.wallet_registry.insert(
                        wallet_id_str.clone(),
                        wallet_data.clone()
                    );
                    self.wallet_blocks.insert(
                        wallet_id_str,
                        block.height()
                    );
                }
            }
        }
        Ok(())
    }

    // ========================================================================
    // Validator registration and management
    // ========================================================================

    /// Register a new validator on the blockchain
    pub fn register_validator(&mut self, validator_info: ValidatorInfo) -> Result<Hash> {
        // Check if validator already exists
        if self.validator_registry.contains_key(&validator_info.identity_id) {
            return Err(anyhow::anyhow!("Validator {} already exists on blockchain", validator_info.identity_id));
        }

        // Verify the identity exists
        if !self.identity_registry.contains_key(&validator_info.identity_id) {
            return Err(anyhow::anyhow!("Identity {} must be registered before becoming a validator", validator_info.identity_id));
        }

        // Create validator registration transaction (using Identity type as placeholder until we add Validator type)
        let validator_tx_data = IdentityTransactionData {
            did: validator_info.identity_id.clone(),
            display_name: format!("Validator: {}", validator_info.network_address),
            public_key: validator_info.consensus_key.clone(),
            ownership_proof: vec![], // Empty for system validator registration
            identity_type: "validator".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(
                format!("validator:{}:{}", validator_info.identity_id, validator_info.registered_at).as_bytes()
            ),
            created_at: validator_info.registered_at,
            registration_fee: 0, // No fee for validator registration (paid via stake)
            dao_fee: 0,
        };

        let registration_tx = Transaction::new_identity_registration(
            validator_tx_data,
            vec![], // Fee outputs handled separately
            Signature {
                signature: validator_info.consensus_key.clone(),
                public_key: PublicKey::new(validator_info.consensus_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: validator_info.registered_at,
            },
            format!("Validator registration for {} with stake {}", validator_info.identity_id, validator_info.stake).into_bytes(),
        );

        // Add to pending transactions for inclusion in next block
        self.add_pending_transaction(registration_tx.clone())?;

        // Store in validator registry immediately for queries
        self.validator_registry.insert(validator_info.identity_id.clone(), validator_info.clone());
        self.validator_blocks.insert(validator_info.identity_id.clone(), self.height + 1);

        info!("✅ Validator {} registered with {} ZHTP stake and {} bytes storage", 
              validator_info.identity_id, validator_info.stake, validator_info.storage_provided);

        Ok(registration_tx.hash())
    }

    /// Get validator by identity ID
    pub fn get_validator(&self, identity_id: &str) -> Option<&ValidatorInfo> {
        self.validator_registry.get(identity_id)
    }

    /// Check if validator exists
    pub fn validator_exists(&self, identity_id: &str) -> bool {
        self.validator_registry.contains_key(identity_id)
    }

    /// Get all validators on the blockchain
    pub fn list_all_validators(&self) -> Vec<&ValidatorInfo> {
        self.validator_registry.values().collect()
    }

    /// Get all active validators
    pub fn get_active_validators(&self) -> Vec<&ValidatorInfo> {
        self.validator_registry.values()
            .filter(|v| v.status == "active")
            .collect()
    }

    /// Get all validators as HashMap
    pub fn get_all_validators(&self) -> &HashMap<String, ValidatorInfo> {
        &self.validator_registry
    }

    /// Update validator information
    pub fn update_validator(&mut self, identity_id: &str, updated_info: ValidatorInfo) -> Result<Hash> {
        // Check if validator exists
        if !self.validator_registry.contains_key(identity_id) {
            return Err(anyhow::anyhow!("Validator {} not found on blockchain", identity_id));
        }

        // Create update transaction
        let validator_tx_data = IdentityTransactionData {
            did: updated_info.identity_id.clone(),
            display_name: format!("Validator Update: {}", updated_info.network_address),
            public_key: updated_info.consensus_key.clone(),
            ownership_proof: vec![],
            identity_type: "validator".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(
                format!("validator_update:{}:{}", updated_info.identity_id, updated_info.last_activity).as_bytes()
            ),
            created_at: updated_info.last_activity,
            registration_fee: 0,
            dao_fee: 0,
        };

        let update_tx = Transaction::new_identity_update(
            validator_tx_data,
            vec![],
            vec![],
            100, // Update fee
            Signature {
                signature: updated_info.consensus_key.clone(),
                public_key: PublicKey::new(updated_info.consensus_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: updated_info.last_activity,
            },
            format!("Validator update for {}", identity_id).into_bytes(),
        );

        // Add to pending transactions
        self.add_pending_transaction(update_tx.clone())?;

        // Update registry
        self.validator_registry.insert(identity_id.to_string(), updated_info);

        Ok(update_tx.hash())
    }

    /// Unregister a validator
    pub fn unregister_validator(&mut self, identity_id: &str) -> Result<Hash> {
        // Check if validator exists
        if !self.validator_registry.contains_key(identity_id) {
            return Err(anyhow::anyhow!("Validator {} not found on blockchain", identity_id));
        }

        // Get validator info
        let mut validator_info = self.validator_registry.get(identity_id).unwrap().clone();
        validator_info.status = "inactive".to_string();

        // Create unregistration transaction
        let unregister_tx = Transaction::new_identity_revocation(
            identity_id.to_string(),
            vec![],
            100,
            Signature {
                signature: validator_info.consensus_key.clone(),
                public_key: PublicKey::new(validator_info.consensus_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: validator_info.last_activity,
            },
            format!("Validator unregistration for {}", identity_id).into_bytes(),
        );

        // Add to pending transactions
        self.add_pending_transaction(unregister_tx.clone())?;

        // Update status in registry
        self.validator_registry.insert(identity_id.to_string(), validator_info);

        info!("Validator {} unregistered", identity_id);

        Ok(unregister_tx.hash())
    }

    /// Get validator block confirmation count
    pub fn get_validator_confirmations(&self, identity_id: &str) -> Option<u64> {
        self.validator_blocks.get(identity_id).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    /// Process validator transactions in a block
    pub fn process_validator_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if let Some(ref identity_data) = transaction.identity_data {
                if identity_data.identity_type == "validator" {
                    // Extract validator info from identity transaction
                    // This is a simplified version - in production, you'd have a dedicated ValidatorTransactionData
                    if let Some(validator_info) = self.validator_registry.get(&identity_data.did) {
                        let mut updated_info = validator_info.clone();
                        updated_info.last_activity = identity_data.created_at;
                        updated_info.blocks_validated += 1;
                        
                        self.validator_registry.insert(
                            identity_data.did.clone(),
                            updated_info
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Process contract deployment transactions from a block
    pub fn process_contract_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if transaction.transaction_type == TransactionType::ContractDeployment {
                // Contract data is serialized in the first output's commitment
                if let Some(output) = transaction.outputs.first() {
                    // Try to deserialize as Web4Contract first (JSON format)
                    if let Ok(web4_contract) = serde_json::from_slice::<crate::contracts::web4::Web4Contract>(output.commitment.as_bytes()) {
                        // Generate contract ID from the note field or domain
                        let contract_id = lib_crypto::hash_blake3(web4_contract.domain.as_bytes());
                        self.register_web4_contract(contract_id, web4_contract, block.height());
                        info!(" Processed Web4Contract deployment in block {}", block.height());
                    } 
                    // Try to deserialize as TokenContract (bincode format)
                    else if let Ok(token_contract) = bincode::deserialize::<crate::contracts::TokenContract>(output.commitment.as_bytes()) {
                        let contract_id = token_contract.token_id;
                        self.register_token_contract(contract_id, token_contract, block.height());
                        info!(" Processed TokenContract deployment in block {}", block.height());
                    } else {
                        debug!(" Could not deserialize contract in transaction {}", transaction.hash());
                    }
                }
            }
        }
        Ok(())
    }

    /// Get access to the recursive proof aggregator for O(1) verification
    pub async fn get_proof_aggregator(&mut self) -> Result<std::sync::Arc<tokio::sync::RwLock<lib_proofs::RecursiveProofAggregator>>> {
        if self.proof_aggregator.is_none() {
            self.initialize_proof_aggregator()?;
        }
        
        self.proof_aggregator.clone()
            .ok_or_else(|| anyhow::anyhow!("Failed to initialize proof aggregator"))
    }

    /// Enable O(1) verification for the blockchain by processing all blocks through recursive aggregation
    pub async fn enable_instant_verification(&mut self) -> Result<()> {
        info!(" Enabling O(1) instant verification for blockchain");
        
        // Initialize aggregator if not already done
        let aggregator_arc = self.get_proof_aggregator().await?;
        
        // Process each block through the aggregator to build recursive proof chain
        let mut aggregator = aggregator_arc.write().await;
        let mut previous_chain_proof: Option<lib_proofs::ChainRecursiveProof> = None;
        
        for (i, block) in self.blocks.iter().enumerate() {
            info!("Processing block {} for recursive proof aggregation", i);
            
            // Convert block transactions to the format expected by the aggregator
            let batched_transactions: Vec<BatchedPrivateTransaction> = 
                block.transactions.iter().map(|tx| {
                    // Create batched transaction metadata
                    let batch_metadata = BatchMetadata {
                        transaction_count: 1,
                        fee_tier: 0, // Standard fee tier
                        block_height: block.height(),
                        batch_commitment: tx.hash().as_array(),
                    };

                    // Create a ZkTransactionProof for the transaction
                    let zk_tx_proof = lib_proofs::ZkTransactionProof::default(); // Using default for demo

                    BatchedPrivateTransaction {
                        transaction_proofs: vec![zk_tx_proof],
                        merkle_root: tx.hash().as_array(),
                        batch_metadata,
                    }
                }).collect();

            // Get previous state root (using merkle root as state representation)
            let previous_state_root = if i > 0 {
                let merkle_bytes = self.blocks[i - 1].header.merkle_root.as_bytes();
                let mut root = [0u8; 32];
                root.copy_from_slice(merkle_bytes);
                root
            } else {
                [0u8; 32] // Genesis block
            };

            // Aggregate block proof
            match aggregator.aggregate_block_transactions(
                block.height(),
                &batched_transactions,
                &previous_state_root,
                block.header.timestamp,
            ) {
                Ok(block_proof) => {
                    info!("Block {} proof aggregated successfully", i);

                    // Create recursive chain proof
                    match aggregator.create_recursive_chain_proof(&block_proof, previous_chain_proof.as_ref()) {
                        Ok(chain_proof) => {
                            info!(" Recursive chain proof created for block {}", i);
                            previous_chain_proof = Some(chain_proof);
                        }
                        Err(e) => {
                            error!("Failed to create recursive chain proof for block {}: {}", i, e);
                            return Err(anyhow::anyhow!("Failed to create recursive chain proof: {}", e));
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to aggregate block {} proof: {}", i, e);
                    return Err(anyhow::anyhow!("Failed to aggregate block proof: {}", e));
                }
            }
        }

        // Verify the final recursive proof works
        if let Some(final_chain_proof) = previous_chain_proof {
            let verifier = lib_proofs::InstantStateVerifier::new()?;
            match verifier.verify_current_state(&final_chain_proof) {
                Ok(true) => {
                    info!("Final recursive chain proof verification successful");
                }
                Ok(false) => {
                    warn!("Final recursive chain proof verification failed");
                    return Err(anyhow::anyhow!("Recursive chain proof verification failed"));
                }
                Err(e) => {
                    error!("Error verifying final recursive chain proof: {}", e);
                    return Err(anyhow::anyhow!("Error verifying recursive chain proof: {}", e));
                }
            }
        }
        
        info!("O(1) instant verification enabled for entire blockchain with {} blocks", self.blocks.len());
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

    // ===== ECONOMIC INTEGRATION METHODS =====

    /// Create UBI distribution transactions using lib-economy
    pub async fn create_ubi_distributions(
        &mut self,
        citizens: &[(lib_economy::wasm::IdentityId, u64)],
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_txs = processor.create_ubi_distributions_for_blockchain(citizens, system_keypair).await?;
            let mut tx_hashes = Vec::new();
            
            for tx in blockchain_txs {
                let tx_hash = tx.hash();
                self.add_pending_transaction(tx)?;
                tx_hashes.push(tx_hash);
            }
            
            info!("🏦 Created {} UBI distribution transactions", tx_hashes.len());
            Ok(tx_hashes)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Create network reward transactions using lib-economy
    pub async fn create_network_rewards(
        &mut self,
        rewards: &[([u8; 32], u64)], // (recipient, amount)
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_txs = processor.create_network_reward_transactions(rewards, system_keypair).await?;
            let mut tx_hashes = Vec::new();
            
            for tx in blockchain_txs {
                let tx_hash = tx.hash();
                self.add_pending_transaction(tx)?;
                tx_hashes.push(tx_hash);
            }
            
            info!("🏦 Created {} network reward transactions", tx_hashes.len());
            Ok(tx_hashes)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Create payment transaction with proper economic fee calculation
    pub async fn create_payment_transaction(
        &mut self,
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        priority: lib_economy::Priority,
        sender_keypair: &lib_crypto::KeyPair,
    ) -> Result<Hash> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_tx = processor.create_payment_transaction_for_blockchain(
                from, to, amount, priority, sender_keypair
            ).await?;
            
            let tx_hash = blockchain_tx.hash();
            self.add_pending_transaction(blockchain_tx)?;
            
            info!("🏦 Created payment transaction: {} ZHTP from {:?} to {:?}", amount, from, to);
            Ok(tx_hash)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Create welfare funding transactions using lib-economy
    pub async fn create_welfare_funding(
        &mut self,
        services: &[(String, [u8; 32], u64)], // (service_name, address, amount)
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut _processor) = self.economic_processor {
            let blockchain_txs = crate::integration::economic_integration::create_welfare_funding_transactions(
                services, system_keypair
            ).await?;
            
            let mut tx_hashes = Vec::new();
            for tx in blockchain_txs {
                let tx_hash = tx.hash();
                self.add_pending_transaction(tx)?;
                tx_hashes.push(tx_hash);
            }
            
            info!("🏦 Created {} welfare funding transactions", tx_hashes.len());
            Ok(tx_hashes)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Get economic treasury statistics
    pub async fn get_treasury_statistics(&self) -> Result<TreasuryStats> {
        if let Some(ref processor) = self.economic_processor {
            processor.get_treasury_statistics().await
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Calculate transaction fees using economic rules
    pub fn calculate_transaction_fees(
        &self,
        tx_size: u64,
        amount: u64,
        priority: lib_economy::Priority,
        is_system_transaction: bool,
    ) -> (u64, u64, u64) {
        if let Some(ref processor) = self.economic_processor {
            processor.calculate_transaction_fees_with_exemptions(tx_size, amount, priority, is_system_transaction)
        } else {
            // Fallback basic fee calculation if processor not available
            if is_system_transaction {
                (0, 0, 0)
            } else {
                let base_fee = tx_size * 10; // Basic fallback
                let dao_fee = amount * 200 / 10000; // 2% DAO fee
                (base_fee, dao_fee, base_fee + dao_fee)
            }
        }
    }

    /// Get wallet balance for an address using economic processor
    pub fn get_wallet_balance(&self, address: &[u8; 32]) -> Option<u64> {
        if let Some(ref processor) = self.economic_processor {
            processor.get_wallet_balance(address).map(|balance| balance.total_balance())
        } else {
            None
        }
    }

    /// Initialize economic processor if not already done
    pub fn ensure_economic_processor(&mut self) {
        if self.economic_processor.is_none() {
            self.economic_processor = Some(EconomicTransactionProcessor::new());
            info!("🏦 Economic processor initialized for blockchain");
        }
    }

    /// Initialize consensus coordinator if not already done
    pub async fn initialize_consensus_coordinator(
        &mut self,
        mempool: std::sync::Arc<tokio::sync::RwLock<crate::mempool::Mempool>>,
        consensus_type: lib_consensus::ConsensusType,
    ) -> Result<()> {
        if self.consensus_coordinator.is_none() {
            let blockchain_arc = std::sync::Arc::new(tokio::sync::RwLock::new(self.clone()));
            let coordinator = crate::integration::consensus_integration::initialize_consensus_integration(
                blockchain_arc,
                mempool,
                consensus_type,
            ).await?;
            
            self.consensus_coordinator = Some(std::sync::Arc::new(tokio::sync::RwLock::new(coordinator)));
            info!(" Consensus coordinator initialized for blockchain");
        }
        Ok(())
    }

    /// Get consensus coordinator reference
    pub fn get_consensus_coordinator(&self) -> Option<&std::sync::Arc<tokio::sync::RwLock<BlockchainConsensusCoordinator>>> {
        self.consensus_coordinator.as_ref()
    }

    /// Start consensus coordinator
    pub async fn start_consensus(&mut self) -> Result<()> {
        if let Some(ref coordinator_arc) = self.consensus_coordinator {
            let mut coordinator = coordinator_arc.write().await;
            coordinator.start_consensus_coordinator().await?;
            info!("Consensus coordinator started for blockchain");
        } else {
            return Err(anyhow::anyhow!("Consensus coordinator not initialized"));
        }
        Ok(())
    }

    /// Register as validator in consensus
    pub async fn register_as_validator(
        &mut self,
        identity: lib_identity::IdentityId,
        stake_amount: u64,
        storage_capacity: u64,
        consensus_keypair: &lib_crypto::KeyPair,
        commission_rate: u8,
    ) -> Result<()> {
        if let Some(ref coordinator_arc) = self.consensus_coordinator {
            let mut coordinator = coordinator_arc.write().await;
            coordinator.register_as_validator(
                identity,
                stake_amount,
                storage_capacity,
                consensus_keypair,
                commission_rate,
            ).await?;
            info!("Registered as validator with consensus coordinator");
        } else {
            return Err(anyhow::anyhow!("Consensus coordinator not initialized"));
        }
        Ok(())
    }

    /// Get consensus status
    pub async fn get_consensus_status(&self) -> Result<Option<ConsensusStatus>> {
        if let Some(ref coordinator_arc) = self.consensus_coordinator {
            let coordinator = coordinator_arc.read().await;
            let status = coordinator.get_consensus_status().await?;
            Ok(Some(status))
        } else {
            Ok(None)
        }
    }

    /// Create DAO proposal through consensus
    pub async fn create_dao_proposal(
        &self,
        proposer_keypair: &lib_crypto::KeyPair,
        title: String,
        description: String,
        proposal_type: lib_consensus::DaoProposalType,
    ) -> Result<crate::types::Hash> {
        let proposal_tx = crate::integration::consensus_integration::create_dao_proposal_transaction(
            proposer_keypair,
            title,
            description,
            proposal_type,
        )?;

        // Add to pending transactions
        let tx_hash = proposal_tx.hash();
        // Note: In a mutable context, you would call self.add_pending_transaction(proposal_tx)?;
        // For now, just return the transaction hash
        Ok(tx_hash)
    }

    /// Cast DAO vote through consensus
    pub async fn cast_dao_vote(
        &self,
        voter_keypair: &lib_crypto::KeyPair,
        proposal_id: lib_crypto::Hash,
        vote_choice: lib_consensus::DaoVoteChoice,
    ) -> Result<crate::types::Hash> {
        let vote_tx = crate::integration::consensus_integration::create_dao_vote_transaction(
            voter_keypair,
            proposal_id,
            vote_choice,
        )?;

        // Add to pending transactions
        let tx_hash = vote_tx.hash();
        // Note: In a mutable context, you would call self.add_pending_transaction(vote_tx)?;
        // For now, just return the transaction hash
        Ok(tx_hash)
    }

    /// Verify block with consensus rules
    pub async fn verify_block_with_consensus(&self, block: &Block, previous_block: Option<&Block>) -> Result<bool> {
        // First run standard blockchain verification
        if !self.verify_block(block, previous_block)? {
            return Ok(false);
        }

        // If consensus coordinator is available, perform additional consensus verification
        if let Some(ref coordinator_arc) = self.consensus_coordinator {
            let coordinator = coordinator_arc.read().await;
            let status = coordinator.get_consensus_status().await?;
            
            // Verify block height matches consensus expectations
            if block.height() != status.current_height {
                warn!("Block height mismatch: block={}, consensus={}", 
                      block.height(), status.current_height);
                return Ok(false);
            }

            // Additional consensus-specific validations would go here
            info!("Block passed consensus verification at height {}", block.height());
        }

        Ok(true)
    }

    /// Check if a transaction is an economic system transaction (UBI/welfare/rewards)
    pub fn is_economic_system_transaction(&self, transaction: &Transaction) -> bool {
        crate::integration::economic_integration::utils::is_ubi_distribution(transaction) ||
        crate::integration::economic_integration::utils::is_welfare_distribution(transaction) ||
        crate::integration::economic_integration::utils::is_network_reward(transaction)
    }

    // ===== BLOCKCHAIN RECOVERY METHODS =====

    /// Recover blockchain state from persistent storage
    pub async fn recover_from_storage(&mut self) -> Result<bool> {
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut _storage_manager = storage_manager_arc.write().await;
            info!(" Starting blockchain recovery from storage...");

            // For now, return false since the retrieval methods need proper implementation
            // TODO: Implement proper blockchain state recovery
            info!("Blockchain recovery needs complete retrieval method implementation");
            return Ok(false);
        }

        Ok(false)
    }

    /// Verify blockchain integrity after recovery
    pub async fn verify_blockchain_integrity(&self) -> Result<bool> {
        info!("Verifying blockchain integrity...");

        // Verify block chain continuity
        for i in 1..self.blocks.len() {
            let current = &self.blocks[i];
            let previous = &self.blocks[i - 1];

            if current.previous_hash() != previous.hash() {
                error!("Block chain continuity broken at height {}", i);
                return Ok(false);
            }

            if current.height() != previous.height() + 1 {
                error!("Block height sequence broken at height {}", i);
                return Ok(false);
            }
        }

        // Verify UTXO set consistency by rebuilding it
        let mut rebuilt_utxo_set = HashMap::new();
        let mut rebuilt_nullifier_set = HashSet::new();

        for block in &self.blocks {
            for tx in &block.transactions {
                // Add nullifiers
                for input in &tx.inputs {
                    rebuilt_nullifier_set.insert(input.nullifier);
                }

                // Add new outputs
                for (index, output) in tx.outputs.iter().enumerate() {
                    let output_id = self.calculate_output_id(&tx.hash(), index);
                    rebuilt_utxo_set.insert(output_id, output.clone());
                }
            }
        }

        if rebuilt_utxo_set.len() != self.utxo_set.len() {
            error!("UTXO set size mismatch: expected={}, actual={}", 
                   rebuilt_utxo_set.len(), self.utxo_set.len());
            return Ok(false);
        }

        if rebuilt_nullifier_set.len() != self.nullifier_set.len() {
            error!("Nullifier set size mismatch: expected={}, actual={}", 
                   rebuilt_nullifier_set.len(), self.nullifier_set.len());
            return Ok(false);
        }

        info!("Blockchain integrity verification passed");
        Ok(true)
    }

    /// Create a full backup of the blockchain to storage
    pub async fn create_full_backup(&self) -> Result<bool> {
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            info!(" Creating full blockchain backup...");

            // Backup using the storage manager's backup functionality
            let backup_result = storage_manager.backup_blockchain(self).await?;
            let successful_backups = backup_result.iter().filter(|r| r.success).count();
            
            info!("Full blockchain backup completed: {}/{} operations successful", successful_backups, backup_result.len());
            return Ok(true);
        }

        warn!("No storage manager available for backup");
        Ok(false)
    }

    /// Restore blockchain from a backup
    pub async fn restore_from_backup(&mut self, backup_id: &str) -> Result<bool> {
        if let Some(_storage_manager) = &self.storage_manager {
            info!(" Restoring blockchain from backup: {}", backup_id);

            // Implementation would depend on storage manager's backup format
            // This is a placeholder for the restore functionality
            info!("Backup restore functionality needs implementation in storage manager");
            
            return Ok(false);
        }

        warn!("No storage manager available for restore");
        Ok(false)
    }

    /// Synchronize blockchain with storage (ensure consistency)
    pub async fn synchronize_with_storage(&mut self) -> Result<()> {
        if let Some(storage_manager_arc) = self.storage_manager.clone() {
            info!(" Synchronizing blockchain with storage...");

            // Persist current state
            self.persist_to_storage().await?;
            self.persist_utxo_set().await?;

            let mut storage_manager = storage_manager_arc.write().await;
            // Persist any unpersisted blocks
            for block in &self.blocks {
                let _ = storage_manager.store_block(block).await;
            }

            // Persist all identity data
            for (did, identity_data) in &self.identity_registry {
                let _ = storage_manager.store_identity_data(did, identity_data).await;
            }

            info!("Blockchain synchronization with storage completed");
        }

        Ok(())
    }

    // ===== STORAGE CONFIGURATION AND MONITORING =====

    /// Enable or disable automatic persistence
    pub fn set_auto_persist(&mut self, enabled: bool) {
        self.auto_persist_enabled = enabled;
        if enabled {
            info!("Automatic persistence enabled");
        } else {
            info!("Automatic persistence disabled");
        }
    }

    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> Result<Option<serde_json::Value>> {
        if let Some(_storage_manager) = &self.storage_manager {
            // This would return storage statistics from the unified storage system
            // Implementation depends on storage manager capabilities
            let stats = serde_json::json!({
                "utxo_count": self.utxo_set.len(),
                "identity_count": self.identity_registry.len(),
                "block_count": self.blocks.len(),
                "nullifier_count": self.nullifier_set.len(),
                "height": self.height,
                "auto_persist_enabled": self.auto_persist_enabled,
                "blocks_since_last_persist": self.blocks_since_last_persist
            });
            return Ok(Some(stats));
        }
        Ok(None)
    }

    /// Check if storage is healthy and accessible
    pub async fn check_storage_health(&self) -> Result<bool> {
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            // Perform a simple storage health check
            match storage_manager.store_test_data().await {
                Ok(_) => {
                    info!("Storage health check passed");
                    Ok(true)
                }
                Err(e) => {
                    error!("Storage health check failed: {}", e);
                    Ok(false)
                }
            }
        } else {
            warn!("No storage manager configured");
            Ok(false)
        }
    }

    /// Cleanup old storage data (for maintenance)
    pub async fn cleanup_storage(&self, retain_blocks: u32) -> Result<()> {
        if let Some(_storage_manager) = &self.storage_manager {
            info!(" Starting storage cleanup, retaining last {} blocks", retain_blocks);
            
            // This would implement cleanup logic in the storage manager
            // For now, just log the operation
            info!("Storage cleanup implementation needed in storage manager");
        }
        Ok(())
    }

    /// Export the entire blockchain state for network transfer
    /// Includes: blocks, UTXO set, identity registry, wallet registry, and smart contracts
    pub fn export_chain(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct BlockchainExport {
            blocks: Vec<Block>,
            utxo_set: HashMap<Hash, TransactionOutput>,
            identity_registry: HashMap<String, IdentityTransactionData>,
            wallet_registry: HashMap<String, crate::transaction::WalletTransactionData>,
            validator_registry: HashMap<String, ValidatorInfo>,
            token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
            web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
            contract_blocks: HashMap<[u8; 32], u64>,
        }

        let export = BlockchainExport {
            blocks: self.blocks.clone(),
            utxo_set: self.utxo_set.clone(),
            identity_registry: self.identity_registry.clone(),
            wallet_registry: self.wallet_registry.clone(),
            validator_registry: self.validator_registry.clone(),
            token_contracts: self.token_contracts.clone(),
            web4_contracts: self.web4_contracts.clone(),
            contract_blocks: self.contract_blocks.clone(),
        };

        info!(" Exporting blockchain: {} blocks, {} validators, {} token contracts, {} web4 contracts", 
            self.blocks.len(), self.validator_registry.len(), self.token_contracts.len(), self.web4_contracts.len());
        
        // Debug: Log transaction counts for each block
        for (i, block) in self.blocks.iter().enumerate() {
            info!("   Block {}: height={}, transactions={}, merkle_root={}", 
                  i, block.height(), block.transactions.len(), hex::encode(block.header.merkle_root.as_bytes()));
        }

        bincode::serialize(&export)
            .map_err(|e| anyhow::anyhow!("Failed to serialize blockchain: {}", e))
    }

    /// Evaluate and potentially merge a blockchain from another node
    /// Uses consensus rules to decide whether to adopt the imported chain
    pub async fn evaluate_and_merge_chain(&mut self, data: Vec<u8>) -> Result<lib_consensus::ChainMergeResult> {
        let import: BlockchainImport = bincode::deserialize(&data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize blockchain: {}", e))?;

        // Verify all blocks in sequence
        for (i, block) in import.blocks.iter().enumerate() {
            if i == 0 {
                // Genesis block - just verify it's valid
                if !self.verify_block(block, None)? {
                    return Err(anyhow::anyhow!("Invalid genesis block in imported chain"));
                }
            } else {
                let prev_block = &import.blocks[i - 1];
                if block.header.previous_block_hash != prev_block.header.block_hash {
                    return Err(anyhow::anyhow!("Block chain integrity broken at block {}", i));
                }
                if !self.verify_block(block, Some(prev_block))? {
                    return Err(anyhow::anyhow!("Invalid block {} in imported chain", i));
                }
            }
        }

        // Create chain summaries for consensus evaluation
        let local_summary = self.create_local_chain_summary_async().await;
        let imported_summary = self.create_imported_chain_summary(
            &import.blocks,
            &import.identity_registry,
            &import.utxo_set,
            &import.token_contracts,
            &import.web4_contracts
        );

        // DEBUG: Log genesis hashes being compared
        info!("🔍 Comparing blockchains for merge:");
        info!("   Local genesis hash:    {}", local_summary.genesis_hash);
        info!("   Imported genesis hash: {}", imported_summary.genesis_hash);
        info!("   Hashes equal: {}", local_summary.genesis_hash == imported_summary.genesis_hash);

        // Use consensus rules to decide which chain to adopt
        let decision = lib_consensus::ChainEvaluator::evaluate_chains(&local_summary, &imported_summary);

        match decision {
            lib_consensus::ChainDecision::KeepLocal => {
                info!(" Local chain is better - keeping current state");
                info!("   Local: height={}, work={}, identities={}", 
                      local_summary.height, local_summary.total_work, local_summary.total_identities);
                info!("   Imported: height={}, work={}, identities={}", 
                      imported_summary.height, imported_summary.total_work, imported_summary.total_identities);
                Ok(lib_consensus::ChainMergeResult::LocalKept)
            },
            lib_consensus::ChainDecision::MergeContentOnly => {
                info!(" Local chain is longer - merging unique content from shorter chain");
                info!("   Local: height={}, work={}, identities={}", 
                      local_summary.height, local_summary.total_work, local_summary.total_identities);
                info!("   Imported: height={}, work={}, identities={}", 
                      imported_summary.height, imported_summary.total_work, imported_summary.total_identities);
                
                // Extract unique content from imported chain (shorter) into local (longer)
                match self.merge_unique_content(&import) {
                    Ok(merged_items) => {
                        info!(" Successfully merged unique content: {}", merged_items);
                        Ok(lib_consensus::ChainMergeResult::ContentMerged)
                    },
                    Err(e) => {
                        warn!("Failed to merge content: {} - keeping local only", e);
                        Ok(lib_consensus::ChainMergeResult::Failed(format!("Content merge error: {}", e)))
                    }
                }
            },
            lib_consensus::ChainDecision::AdoptImported => {
                info!("🔄 Imported chain is better - performing intelligent merge");
                info!("   Local: height={}, work={}, identities={}", 
                      local_summary.height, local_summary.total_work, local_summary.total_identities);
                info!("   Imported: height={}, work={}, identities={}", 
                      imported_summary.height, imported_summary.total_work, imported_summary.total_identities);
                
                // Check if this is a genesis replacement (different genesis blocks)
                let is_genesis_replacement = if !self.blocks.is_empty() && !import.blocks.is_empty() {
                    self.blocks[0].header.block_hash != import.blocks[0].header.block_hash
                } else {
                    false
                };
                
                if is_genesis_replacement {
                    info!("🔀 Genesis mismatch detected - performing full consolidation merge");
                    info!("   Old genesis: {}", hex::encode(self.blocks[0].header.block_hash.as_bytes()));
                    info!("   New genesis: {}", hex::encode(import.blocks[0].header.block_hash.as_bytes()));
                    
                    // Perform intelligent merge: adopt imported chain but preserve unique local data
                    match self.merge_with_genesis_mismatch(&import) {
                        Ok(merge_report) => {
                            info!("✅ Successfully merged chains with genesis consolidation");
                            info!("{}", merge_report);
                            Ok(lib_consensus::ChainMergeResult::ImportedAdopted)
                        }
                        Err(e) => {
                            warn!("⚠️ Genesis merge failed: {} - adopting imported chain only", e);
                            // Fallback: just adopt imported chain
                            self.blocks = import.blocks;
                            self.height = self.blocks.len() as u64 - 1;
                            self.utxo_set = import.utxo_set;
                            self.identity_registry = import.identity_registry;
                            self.wallet_registry = import.wallet_registry;
                            self.validator_registry = import.validator_registry;
                            self.token_contracts = import.token_contracts;
                            self.web4_contracts = import.web4_contracts;
                            self.contract_blocks = import.contract_blocks;
                            Ok(lib_consensus::ChainMergeResult::ImportedAdopted)
                        }
                    }
                } else {
                    info!("🔄 Same genesis - adopting longer chain");
                    // Simple case: same genesis, just adopt imported chain
                    self.blocks = import.blocks;
                    self.height = self.blocks.len() as u64 - 1;
                    self.utxo_set = import.utxo_set;
                    self.identity_registry = import.identity_registry;
                    self.wallet_registry = import.wallet_registry;
                    self.validator_registry = import.validator_registry;
                    self.token_contracts = import.token_contracts;
                    self.web4_contracts = import.web4_contracts;
                    self.contract_blocks = import.contract_blocks;
                    
                    // Clear nullifier set and rebuild from new chain
                    self.nullifier_set.clear();
                    for block in &self.blocks {
                        for tx in &block.transactions {
                            for input in &tx.inputs {
                                self.nullifier_set.insert(input.nullifier);
                            }
                        }
                    }
                    
                    info!("✅ Adopted imported chain");
                    info!("   New height: {}", self.height);
                    info!("   Identities: {}", self.identity_registry.len());
                    info!("   Validators: {}", self.validator_registry.len());
                    info!("   UTXOs: {}", self.utxo_set.len());
                    
                    Ok(lib_consensus::ChainMergeResult::ImportedAdopted)
                }
            },
            lib_consensus::ChainDecision::Merge => {
                info!(" Merging compatible chains");
                info!("   Local: height={}, work={}, identities={}, contracts={}", 
                      local_summary.height, local_summary.total_work, 
                      local_summary.total_identities, local_summary.total_contracts);
                info!("   Imported: height={}, work={}, identities={}, contracts={}", 
                      imported_summary.height, imported_summary.total_work, 
                      imported_summary.total_identities, imported_summary.total_contracts);
                
                match self.merge_chain_content(&import) {
                    Ok(merged_items) => {
                        info!(" Successfully merged chains: {}", merged_items);
                        Ok(lib_consensus::ChainMergeResult::Merged)
                    },
                    Err(e) => {
                        warn!("Failed to merge chains: {} - keeping local", e);
                        Ok(lib_consensus::ChainMergeResult::Failed(format!("Merge error: {}", e)))
                    }
                }
            },
            lib_consensus::ChainDecision::Conflict => {
                warn!(" Chain conflict detected - different genesis blocks");
                warn!("   Local genesis: {}", 
                      if !self.blocks.is_empty() { 
                          hex::encode(self.blocks[0].header.block_hash.as_bytes()) 
                      } else { 
                          "none".to_string() 
                      });
                warn!("   Imported genesis: {}", 
                      if !import.blocks.is_empty() { 
                          hex::encode(import.blocks[0].header.block_hash.as_bytes()) 
                      } else { 
                          "none".to_string() 
                      });
                warn!("   These chains are from different networks and cannot be merged");
                
                Ok(lib_consensus::ChainMergeResult::Failed(
                    "Genesis hash mismatch - chains from different networks".to_string()
                ))
            }
        }
    }

    /// Create chain summary for local blockchain
    async fn create_local_chain_summary_async(&self) -> lib_consensus::ChainSummary {
        let genesis_hash = self.blocks.first()
            .map(|b| b.header.block_hash.to_string())
            .unwrap_or_else(|| "none".to_string());
            
        let genesis_timestamp = self.blocks.first()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
            
        let latest_timestamp = self.blocks.last()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);

        // Get consensus data if coordinator is available
        let (validator_count, total_validator_stake, validator_set_hash) = 
            if let Some(ref coordinator_arc) = self.consensus_coordinator {
                let coordinator = coordinator_arc.read().await;
                match coordinator.get_consensus_status().await {
                    Ok(status) => {
                        // Get validator stats for stake information
                        let validator_infos = coordinator.list_all_validators().await.unwrap_or_default();
                        let total_stake: u128 = validator_infos.iter().map(|v| v.stake_amount as u128).fold(0u128, |acc, x| acc.saturating_add(x));
                        
                        // Calculate validator set hash
                        let validator_ids: Vec<String> = validator_infos.iter()
                            .map(|v| v.identity.to_string())
                            .collect();
                        let validator_hash = if !validator_ids.is_empty() {
                            hex::encode(lib_crypto::hash_blake3(format!("{:?}", validator_ids).as_bytes()))
                        } else {
                            String::new()
                        };
                        
                        (
                            status.active_validators as u64,
                            total_stake,
                            validator_hash
                        )
                    },
                    Err(_) => (0, 0, String::new())
                }
            } else {
                (0, 0, String::new())
            };

        // Estimate TPS based on recent blocks
        let expected_tps = if self.blocks.len() >= 10 {
            let recent_blocks = &self.blocks[self.blocks.len().saturating_sub(10)..];
            let total_txs: u64 = recent_blocks.iter().map(|b| b.transactions.len() as u64).fold(0u64, |acc, x| acc.saturating_add(x));
            let time_span = recent_blocks.last().map(|b| b.header.timestamp)
                .unwrap_or(0) - recent_blocks.first().map(|b| b.header.timestamp)
                .unwrap_or(0);
            if time_span > 0 {
                total_txs / time_span.max(1)
            } else {
                100
            }
        } else {
            100
        };

        // Network size estimate from identity registry (each identity represents a potential node)
        let network_size = self.identity_registry.len().max(1) as u64;

        // Bridge node count (for now, based on special identity types in registry)
        let bridge_node_count = self.identity_registry.values()
            .filter(|id| id.identity_type.contains("bridge") || id.identity_type.contains("Bridge"))
            .count() as u64;

        lib_consensus::ChainSummary {
            height: self.get_height(),
            total_work: self.calculate_total_work(),
            total_transactions: self.blocks.iter().map(|b| b.transactions.len() as u64).fold(0u64, |acc, x| acc.saturating_add(x)),
            total_identities: self.identity_registry.len() as u64,
            total_utxos: self.utxo_set.len() as u64,
            total_contracts: (self.token_contracts.len() + self.web4_contracts.len()) as u64,
            genesis_timestamp,
            latest_timestamp,
            genesis_hash,
            validator_count,
            total_validator_stake,
            validator_set_hash,
            bridge_node_count,
            expected_tps,
            network_size,
        }
    }

    /// Merge content from compatible blockchain without replacing existing data
    fn merge_chain_content(&mut self, import: &BlockchainImport) -> Result<String> {
        let mut merged_items = Vec::new();
        
        // Merge identities (add new ones, preserve existing)
        let mut new_identities = 0;
        for (did, identity_data) in &import.identity_registry {
            if !self.identity_registry.contains_key(did) {
                self.identity_registry.insert(did.clone(), identity_data.clone());
                new_identities += 1;
            }
        }
        if new_identities > 0 {
            merged_items.push(format!("{} identities", new_identities));
        }
        
        // Merge wallets (add new ones, preserve existing)
        let mut new_wallets = 0;
        for (wallet_id, wallet_data) in &import.wallet_registry {
            if !self.wallet_registry.contains_key(wallet_id as &str) {
                self.wallet_registry.insert(wallet_id.clone(), wallet_data.clone());
                new_wallets += 1;
            }
        }
        if new_wallets > 0 {
            merged_items.push(format!("{} wallets", new_wallets));
        }
        
        // Merge contracts (add new ones, preserve existing)
        let mut new_token_contracts = 0;
        for (contract_id, contract) in &import.token_contracts {
            if !self.token_contracts.contains_key(contract_id as &[u8; 32]) {
                self.token_contracts.insert(*contract_id, contract.clone());
                new_token_contracts += 1;
            }
        }
        if new_token_contracts > 0 {
            merged_items.push(format!("{} token contracts", new_token_contracts));
        }
        
        let mut new_web4_contracts = 0;
        for (contract_id, contract) in &import.web4_contracts {
            if !self.web4_contracts.contains_key(contract_id as &[u8; 32]) {
                self.web4_contracts.insert(*contract_id, contract.clone());
                new_web4_contracts += 1;
            }
        }
        if new_web4_contracts > 0 {
            merged_items.push(format!("{} web4 contracts", new_web4_contracts));
        }
        
        // Merge UTXOs (add new ones, preserve existing)
        let mut new_utxos = 0;
        for (utxo_hash, utxo) in &import.utxo_set {
            if !self.utxo_set.contains_key(utxo_hash as &Hash) {
                self.utxo_set.insert(*utxo_hash, utxo.clone());
                new_utxos += 1;
            }
        }
        if new_utxos > 0 {
            merged_items.push(format!("{} UTXOs", new_utxos));
        }
        
        // Merge contract deployment heights (for tracking)
        let mut new_contract_blocks = 0;
        for (contract_id, block_height) in &import.contract_blocks {
            if !self.contract_blocks.contains_key(contract_id as &[u8; 32]) {
                self.contract_blocks.insert(*contract_id, *block_height);
                new_contract_blocks += 1;
            }
        }
        
        // If chains have different heights, merge missing blocks
        if import.blocks.len() != self.blocks.len() {
            if import.blocks.len() > self.blocks.len() {
                // Imported chain is longer - add missing blocks
                let missing_blocks = &import.blocks[self.blocks.len()..];
                let mut added_blocks = 0;
                
                for block in missing_blocks {
                    // Verify block before adding
                    let prev_block = self.blocks.last();
                    if self.verify_block(block, prev_block)? {
                        self.blocks.push(block.clone());
                        self.height = block.height();
                        added_blocks += 1;
                        info!("  Added missing block at height {}", block.height());
                    } else {
                        warn!("  Failed to verify imported block at height {}, stopping block merge", block.height());
                        break;
                    }
                }
                
                if added_blocks > 0 {
                    merged_items.push(format!("{} blocks", added_blocks));
                }
            } else {
                // Local chain is longer - just report the difference
                let block_diff = self.blocks.len() - import.blocks.len();
                info!("  Local chain is {} blocks ahead, not adopting shorter chain", block_diff);
            }
        }
        
        if merged_items.is_empty() {
            Ok("no new content to merge".to_string())
        } else {
            Ok(merged_items.join(", "))
        }
    }

    /// Intelligently merge two chains with different genesis blocks
    /// Adopts the imported chain as the base and consolidates unique data from local chain
    /// This handles the case where two nodes create different genesis blocks and need to sync
    fn merge_with_genesis_mismatch(&mut self, import: &BlockchainImport) -> Result<String> {
        info!("🔀 Starting genesis mismatch merge");
        info!("   Local chain: {} blocks, {} identities, {} validators", 
              self.blocks.len(), self.identity_registry.len(), self.validator_registry.len());
        info!("   Imported chain: {} blocks, {} identities, {} validators", 
              import.blocks.len(), import.identity_registry.len(), import.validator_registry.len());
        
        let mut merge_report = Vec::new();
        
        // Step 1: Extract unique identities from local chain
        let mut unique_identities = 0;
        let mut local_identities_to_preserve = Vec::new();
        for (did, identity_data) in &self.identity_registry {
            if !import.identity_registry.contains_key(did) {
                local_identities_to_preserve.push((did.clone(), identity_data.clone()));
                unique_identities += 1;
            }
        }
        
        // Step 2: Extract unique validators from local chain
        let mut unique_validators = 0;
        let mut local_validators_to_preserve = Vec::new();
        for (validator_id, validator_info) in &self.validator_registry {
            if !import.validator_registry.contains_key(validator_id as &str) {
                local_validators_to_preserve.push((validator_id.clone(), validator_info.clone()));
                unique_validators += 1;
            }
        }
        
        // Step 3: Extract unique wallets from local chain
        let mut unique_wallets = 0;
        let mut local_wallets_to_preserve = Vec::new();
        for (wallet_id, wallet_data) in &self.wallet_registry {
            if !import.wallet_registry.contains_key(wallet_id as &str) {
                local_wallets_to_preserve.push((wallet_id.clone(), wallet_data.clone()));
                unique_wallets += 1;
            }
        }
        
        // Step 4: Extract unique UTXOs from local chain
        let mut unique_utxos = 0;
        let mut local_utxos_to_preserve = Vec::new();
        for (utxo_hash, utxo) in &self.utxo_set {
            if !import.utxo_set.contains_key(utxo_hash as &Hash) {
                local_utxos_to_preserve.push((*utxo_hash, utxo.clone()));
                unique_utxos += 1;
            }
        }
        
        // Step 5: Extract unique contracts from local chain
        let mut unique_token_contracts = 0;
        let mut local_token_contracts = Vec::new();
        for (contract_id, contract) in &self.token_contracts {
            if !import.token_contracts.contains_key(contract_id as &[u8; 32]) {
                local_token_contracts.push((*contract_id, contract.clone()));
                unique_token_contracts += 1;
            }
        }
        
        let mut unique_web4_contracts = 0;
        let mut local_web4_contracts = Vec::new();
        for (contract_id, contract) in &self.web4_contracts {
            if !import.web4_contracts.contains_key(contract_id as &[u8; 32]) {
                local_web4_contracts.push((*contract_id, contract.clone()));
                unique_web4_contracts += 1;
            }
        }
        
        info!("📊 Found unique local data:");
        info!("   {} identities", unique_identities);
        info!("   {} validators", unique_validators);
        info!("   {} wallets", unique_wallets);
        info!("   {} UTXOs", unique_utxos);
        info!("   {} token contracts", unique_token_contracts);
        info!("   {} web4 contracts", unique_web4_contracts);
        
        // Step 6: Adopt imported chain as base
        self.blocks = import.blocks.clone();
        self.height = self.blocks.len() as u64 - 1;
        self.identity_registry = import.identity_registry.clone();
        self.wallet_registry = import.wallet_registry.clone();
        self.validator_registry = import.validator_registry.clone();
        self.utxo_set = import.utxo_set.clone();
        self.token_contracts = import.token_contracts.clone();
        self.web4_contracts = import.web4_contracts.clone();
        self.contract_blocks = import.contract_blocks.clone();
        
        // Step 7: Merge unique local data into adopted chain
        for (did, identity_data) in local_identities_to_preserve {
            self.identity_registry.insert(did, identity_data);
        }
        if unique_identities > 0 {
            merge_report.push(format!("merged {} unique identities", unique_identities));
        }
        
        for (validator_id, validator_info) in local_validators_to_preserve {
            self.validator_registry.insert(validator_id, validator_info);
        }
        if unique_validators > 0 {
            merge_report.push(format!("merged {} unique validators", unique_validators));
        }
        
        for (wallet_id, wallet_data) in local_wallets_to_preserve {
            self.wallet_registry.insert(wallet_id, wallet_data);
        }
        if unique_wallets > 0 {
            merge_report.push(format!("merged {} unique wallets", unique_wallets));
        }
        
        for (utxo_hash, utxo) in local_utxos_to_preserve {
            self.utxo_set.insert(utxo_hash, utxo);
        }
        if unique_utxos > 0 {
            merge_report.push(format!("merged {} unique UTXOs", unique_utxos));
        }
        
        for (contract_id, contract) in local_token_contracts {
            self.token_contracts.insert(contract_id, contract);
        }
        if unique_token_contracts > 0 {
            merge_report.push(format!("merged {} unique token contracts", unique_token_contracts));
        }
        
        for (contract_id, contract) in local_web4_contracts {
            self.web4_contracts.insert(contract_id, contract);
        }
        if unique_web4_contracts > 0 {
            merge_report.push(format!("merged {} unique web4 contracts", unique_web4_contracts));
        }
        
        // Step 8: Rebuild nullifier set from merged state
        self.nullifier_set.clear();
        for block in &self.blocks {
            for tx in &block.transactions {
                for input in &tx.inputs {
                    self.nullifier_set.insert(input.nullifier);
                }
            }
        }
        
        info!("🎉 Genesis mismatch merge complete!");
        info!("   Final chain: {} blocks, {} identities, {} validators, {} UTXOs", 
              self.blocks.len(), self.identity_registry.len(), 
              self.validator_registry.len(), self.utxo_set.len());
        
        if merge_report.is_empty() {
            Ok("adopted imported chain (no unique local data to merge)".to_string())
        } else {
            Ok(format!("adopted imported chain and {}", merge_report.join(", ")))
        }
    }

    /// Merge unique content from shorter chain into longer chain
    /// This prevents data loss when local chain is longer but imported has unique identities/wallets/contracts
    fn merge_unique_content(&mut self, import: &BlockchainImport) -> Result<String> {
        let mut merged_items = Vec::new();
        
        info!("Extracting unique content from shorter chain (height {}) into longer chain (height {})",
              import.blocks.len(), self.blocks.len());
        
        // Merge identities (add new ones that don't exist in local chain)
        let mut new_identities = 0;
        for (did, identity_data) in &import.identity_registry {
            if !self.identity_registry.contains_key(did) {
                info!("  Adding unique identity: {}", did);
                self.identity_registry.insert(did.clone(), identity_data.clone());
                new_identities += 1;
            }
        }
        if new_identities > 0 {
            merged_items.push(format!("{} identities", new_identities));
        }
        
        // Merge wallets (add new ones that don't exist in local chain)
        let mut new_wallets = 0;
        for (wallet_id, wallet_data) in &import.wallet_registry {
            if !self.wallet_registry.contains_key(wallet_id as &str) {
                info!("  Adding unique wallet: {}", wallet_id);
                self.wallet_registry.insert(wallet_id.clone(), wallet_data.clone());
                new_wallets += 1;
            }
        }
        if new_wallets > 0 {
            merged_items.push(format!("{} wallets", new_wallets));
        }
        
        // Merge contracts (add new ones that don't exist in local chain)
        let mut new_token_contracts = 0;
        for (contract_id, contract) in &import.token_contracts {
            if !self.token_contracts.contains_key(contract_id as &[u8; 32]) {
                info!("  Adding unique token contract: {:?}", hex::encode(contract_id));
                self.token_contracts.insert(*contract_id, contract.clone());
                new_token_contracts += 1;
            }
        }
        if new_token_contracts > 0 {
            merged_items.push(format!("{} token contracts", new_token_contracts));
        }
        
        let mut new_web4_contracts = 0;
        for (contract_id, contract) in &import.web4_contracts {
            if !self.web4_contracts.contains_key(contract_id as &[u8; 32]) {
                info!("  Adding unique web4 contract: {:?}", hex::encode(contract_id));
                self.web4_contracts.insert(*contract_id, contract.clone());
                new_web4_contracts += 1;
            }
        }
        if new_web4_contracts > 0 {
            merged_items.push(format!("{} web4 contracts", new_web4_contracts));
        }
        
        // Merge UTXOs (add new ones that aren't spent in local chain)
        let mut new_utxos = 0;
        for (utxo_hash, utxo) in &import.utxo_set {
            if !self.utxo_set.contains_key(utxo_hash as &Hash) {
                self.utxo_set.insert(*utxo_hash, utxo.clone());
                new_utxos += 1;
            }
        }
        if new_utxos > 0 {
            merged_items.push(format!("{} UTXOs", new_utxos));
        }
        
        // Merge contract deployment records
        let mut new_contract_blocks = 0;
        for (contract_id, block_height) in &import.contract_blocks {
            if !self.contract_blocks.contains_key(contract_id as &[u8; 32]) {
                self.contract_blocks.insert(*contract_id, *block_height);
                new_contract_blocks += 1;
            }
        }
        
        if merged_items.is_empty() {
            Ok("no unique content found in shorter chain".to_string())
        } else {
            info!("Successfully merged unique content from shorter chain");
            Ok(merged_items.join(", "))
        }
    }

    /// Create chain summary for imported blockchain
    fn create_imported_chain_summary(&self, 
        blocks: &[Block], 
        identity_registry: &HashMap<String, IdentityTransactionData>,
        utxo_set: &HashMap<Hash, TransactionOutput>,
        token_contracts: &HashMap<[u8; 32], crate::contracts::TokenContract>,
        web4_contracts: &HashMap<[u8; 32], crate::contracts::web4::Web4Contract>
    ) -> lib_consensus::ChainSummary {
        let genesis_hash = blocks.first()
            .map(|b| b.header.block_hash.to_string())
            .unwrap_or_else(|| "none".to_string());
            
        let genesis_timestamp = blocks.first()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
            
        let latest_timestamp = blocks.last()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);

        // Estimate TPS based on recent blocks in imported chain
        let expected_tps = if blocks.len() >= 10 {
            let recent_blocks = &blocks[blocks.len().saturating_sub(10)..];
            let total_txs: u64 = recent_blocks.iter().map(|b| b.transactions.len() as u64).fold(0u64, |acc, x| acc.saturating_add(x));
            let time_span = recent_blocks.last().map(|b| b.header.timestamp)
                .unwrap_or(0) - recent_blocks.first().map(|b| b.header.timestamp)
                .unwrap_or(0);
            if time_span > 0 {
                total_txs / time_span.max(1)
            } else {
                100
            }
        } else {
            100
        };

        // Network size estimate from imported identity registry
        let network_size = identity_registry.len().max(1) as u64;

        // Bridge node count from imported identity registry
        let bridge_node_count = identity_registry.values()
            .filter(|id| id.identity_type.contains("bridge") || id.identity_type.contains("Bridge"))
            .count() as u64;

        // For imported chains, we don't have access to their consensus coordinator
        // So we estimate validator info from special identity types
        let validator_count = identity_registry.values()
            .filter(|id| id.identity_type.contains("validator") || id.identity_type.contains("Validator"))
            .count() as u64;

        // Estimate total stake from validator identities (if they have reputation scores)
        let total_validator_stake: u128 = identity_registry.values()
            .filter(|id| id.identity_type.contains("validator") || id.identity_type.contains("Validator"))
            .map(|id| id.registration_fee as u128)
            .fold(0u128, |acc, x| acc.saturating_add(x));

        // Calculate validator set hash from imported identities
        let validator_identities: Vec<String> = identity_registry.iter()
            .filter(|(_, id)| id.identity_type.contains("validator") || id.identity_type.contains("Validator"))
            .map(|(did, _)| did.clone())
            .collect();
        let validator_set_hash = if !validator_identities.is_empty() {
            hex::encode(lib_crypto::hash_blake3(format!("{:?}", validator_identities).as_bytes()))
        } else {
            String::new()
        };

        lib_consensus::ChainSummary {
            height: blocks.len().saturating_sub(1) as u64,
            total_work: self.calculate_imported_total_work(blocks),
            total_transactions: blocks.iter().map(|b| b.transactions.len() as u64).fold(0u64, |acc, x| acc.saturating_add(x)),
            total_identities: identity_registry.len() as u64,
            total_utxos: utxo_set.len() as u64,
            total_contracts: (token_contracts.len() + web4_contracts.len()) as u64,
            genesis_timestamp,
            latest_timestamp,
            genesis_hash,
            validator_count,
            total_validator_stake,
            validator_set_hash,
            bridge_node_count,
            expected_tps,
            network_size,
        }
    }

    /// Calculate total work for imported blocks
    fn calculate_imported_total_work(&self, blocks: &[Block]) -> u128 {
        blocks.iter()
            .map(|block| block.header.difficulty.work())
            .fold(0u128, |acc, work| acc.saturating_add(work))
    }

    /// Calculate total work for current blockchain
    fn calculate_total_work(&self) -> u128 {
        self.blocks.iter()
            .map(|block| block.header.difficulty.work())
            .fold(0u128, |acc, work| acc.saturating_add(work))
    }

    // ============================================================================
    // SMART CONTRACT REGISTRY METHODS
    // ============================================================================
    
    /// Register a token contract in the blockchain
    pub fn register_token_contract(&mut self, contract_id: [u8; 32], contract: crate::contracts::TokenContract, block_height: u64) {
        self.token_contracts.insert(contract_id, contract);
        self.contract_blocks.insert(contract_id, block_height);
        info!(" Registered token contract {} at block {}", hex::encode(contract_id), block_height);
    }
    
    /// Get a token contract from the blockchain
    pub fn get_token_contract(&self, contract_id: &[u8; 32]) -> Option<&crate::contracts::TokenContract> {
        self.token_contracts.get(contract_id)
    }
    
    /// Get a mutable reference to a token contract
    pub fn get_token_contract_mut(&mut self, contract_id: &[u8; 32]) -> Option<&mut crate::contracts::TokenContract> {
        self.token_contracts.get_mut(contract_id)
    }
    
    /// Register a Web4 contract in the blockchain
    pub fn register_web4_contract(&mut self, contract_id: [u8; 32], contract: crate::contracts::web4::Web4Contract, block_height: u64) {
        self.web4_contracts.insert(contract_id, contract);
        self.contract_blocks.insert(contract_id, block_height);
        info!(" Registered Web4 contract {} at block {}", hex::encode(contract_id), block_height);
    }
    
    /// Get a Web4 contract from the blockchain
    pub fn get_web4_contract(&self, contract_id: &[u8; 32]) -> Option<&crate::contracts::web4::Web4Contract> {
        self.web4_contracts.get(contract_id)
    }
    
    /// Get a mutable reference to a Web4 contract
    pub fn get_web4_contract_mut(&mut self, contract_id: &[u8; 32]) -> Option<&mut crate::contracts::web4::Web4Contract> {
        self.web4_contracts.get_mut(contract_id)
    }
    
    /// Get all token contracts
    pub fn get_all_token_contracts(&self) -> &HashMap<[u8; 32], crate::contracts::TokenContract> {
        &self.token_contracts
    }
    
    /// Get all Web4 contracts
    pub fn get_all_web4_contracts(&self) -> &HashMap<[u8; 32], crate::contracts::web4::Web4Contract> {
        &self.web4_contracts
    }
    
    /// Check if a contract exists
    pub fn contract_exists(&self, contract_id: &[u8; 32]) -> bool {
        self.token_contracts.contains_key(contract_id) || 
        self.web4_contracts.contains_key(contract_id)
    }
    
    /// Get the block height where a contract was deployed
    pub fn get_contract_block_height(&self, contract_id: &[u8; 32]) -> Option<u64> {
        self.contract_blocks.get(contract_id).copied()
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        let mut blockchain = Self::new().expect("Failed to create default blockchain");
        blockchain.ensure_economic_processor();
        // Note: Consensus coordinator requires async initialization and external dependencies
        // so it's not initialized in Default. Call initialize_consensus_coordinator() separately.
        blockchain
    }
}

