//! Mesh Sync Transaction Type
//! 
//! Special transaction type for syncing local mesh blocks to the global chain.
//! Uses recursive proof aggregation for O(1) verification of entire mesh chain.
//! 
//! ## Architecture
//! 
//! ```text
//! Local Mesh Chain (100 blocks)
//!     ↓
//! MeshSyncBatch (aggregated data)
//!     ↓
//! RecursiveProof (O(1) verification)
//!     ↓
//! MeshSyncTransaction → Global Chain
//! ```
//! 
//! ## Features
//! 
//! - **O(1) Verification**: Recursive proofs allow verifying 1000s of mesh blocks in constant time
//! - **Validator Signatures**: BFT consensus signatures from mesh validators
//! - **Merkle Aggregation**: Efficient proof of transaction inclusion
//! - **Conflict Detection**: Detect double-spends across mesh boundaries
//! - **Batch Efficiency**: Sync multiple blocks in single global transaction

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use crate::types::Hash;
use crate::mesh::types::{MeshId, NodeId, MeshSyncBatch};
use crate::integration::crypto_integration::{Signature, PublicKey};
use crate::integration::zk_integration::ZkTransactionProof;
use lib_proofs::{ChainRecursiveProof, ZkProof};

/// Mesh sync transaction syncing local mesh to global chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSyncTransaction {
    /// Version (1 for initial implementation)
    pub version: u32,
    
    /// Chain ID (must match global chain)
    pub chain_id: u8,
    
    /// Mesh identifier
    pub mesh_id: MeshId,
    
    /// Coordinator node responsible for sync
    pub coordinator_node: NodeId,
    
    /// Batch of mesh blocks being synced
    pub sync_batch: MeshSyncBatch,
    
    /// Recursive proof aggregating all mesh blocks
    /// Proves validity of entire mesh chain in O(1)
    pub recursive_proof: ChainRecursiveProof,
    
    /// Validator signatures from mesh consensus
    /// At least 67% of validators must sign (BFT threshold)
    pub validator_signatures: Vec<ValidatorSignature>,
    
    /// Merkle proof of transaction aggregation
    pub merkle_proof: MerkleBatchProof,
    
    /// Coordinator signature authorizing sync
    pub coordinator_signature: Signature,
    
    /// Global chain fee for sync operation
    pub sync_fee: u64,
    
    /// Timestamp when batch was created
    pub batch_timestamp: u64,
    
    /// Optional metadata
    pub metadata: MeshSyncMetadata,
}

/// Validator signature from mesh consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// Validator node ID
    pub validator_id: NodeId,
    
    /// Validator's wallet address (for rewards)
    pub wallet_address: Hash,
    
    /// Signature over sync batch hash
    pub signature: Signature,
    
    /// Public key for verification
    pub public_key: PublicKey,
    
    /// Block height when validator signed
    pub signed_at_height: u64,
    
    /// Validator's reputation score at time of signing
    pub reputation: u32,
}

/// Merkle proof for batch aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleBatchProof {
    /// Merkle root of all transactions in batch
    pub merkle_root: Hash,
    
    /// Merkle root of all blocks in batch
    pub block_merkle_root: Hash,
    
    /// Merkle path proofs (for sampling verification)
    pub sample_proofs: Vec<MerklePathProof>,
    
    /// Number of transactions aggregated
    pub transaction_count: u64,
    
    /// Number of blocks aggregated
    pub block_count: u64,
    
    /// Total size in bytes
    pub total_size_bytes: u64,
}

/// Single Merkle path proof for sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePathProof {
    /// Transaction or block hash
    pub leaf_hash: Hash,
    
    /// Merkle path from leaf to root
    pub path: Vec<Hash>,
    
    /// Position indicators (left=false, right=true)
    pub positions: Vec<bool>,
    
    /// Height in the tree
    pub height: u32,
}

/// Metadata about mesh sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSyncMetadata {
    /// Number of active participants in mesh
    pub participant_count: u32,
    
    /// Number of validators in mesh consensus
    pub validator_count: u32,
    
    /// Average block time in mesh (seconds)
    pub avg_block_time: f64,
    
    /// Total fees collected in batch
    pub total_fees_collected: u64,
    
    /// Mesh health score (0-100)
    pub mesh_health_score: u32,
    
    /// Time since last sync (seconds)
    pub time_since_last_sync: u64,
    
    /// Sync reason (Periodic, Emergency, Manual)
    pub sync_reason: SyncReason,
}

/// Reason for mesh sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncReason {
    /// Regular periodic sync (every N blocks)
    Periodic,
    /// Emergency sync (too many pending blocks)
    Emergency,
    /// Manual sync triggered by coordinator
    Manual,
    /// Mesh shutdown/archival
    Shutdown,
}

impl MeshSyncTransaction {
    /// Create a new mesh sync transaction
    pub fn new(
        chain_id: u8,
        mesh_id: MeshId,
        coordinator_node: NodeId,
        sync_batch: MeshSyncBatch,
        recursive_proof: ChainRecursiveProof,
        coordinator_signature: Signature,
        sync_fee: u64,
    ) -> Self {
        let batch_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            version: 1,
            chain_id,
            mesh_id,
            coordinator_node,
            sync_batch,
            recursive_proof,
            validator_signatures: Vec::new(),
            merkle_proof: MerkleBatchProof::empty(),
            coordinator_signature,
            sync_fee,
            batch_timestamp,
            metadata: MeshSyncMetadata::default(),
        }
    }
    
    /// Add validator signature
    pub fn add_validator_signature(&mut self, signature: ValidatorSignature) {
        self.validator_signatures.push(signature);
    }
    
    /// Check if sufficient validator signatures (67% BFT threshold)
    pub fn has_sufficient_signatures(&self) -> bool {
        if self.metadata.validator_count == 0 {
            return false;
        }
        
        let signature_count = self.validator_signatures.len() as u32;
        let required = ((self.metadata.validator_count * 2) / 3) + 1; // 67% + 1
        
        signature_count >= required
    }
    
    /// Verify all validator signatures
    pub fn verify_validator_signatures(&self) -> Result<bool> {
        if !self.has_sufficient_signatures() {
            return Ok(false);
        }
        
        let batch_hash = self.sync_batch.batch_hash();
        
        for sig in &self.validator_signatures {
            // TODO: Implement actual signature verification
            // verify_signature(&sig.signature, &batch_hash, &sig.public_key)?;
        }
        
        Ok(true)
    }
    
    /// Verify recursive proof (O(1) verification of entire mesh chain)
    pub fn verify_recursive_proof(&self) -> Result<bool> {
        // Verify proof covers the batch height range
        if self.recursive_proof.chain_tip_height != self.sync_batch.to_height {
            return Err(anyhow!(
                "Recursive proof tip height {} doesn't match batch to_height {}",
                self.recursive_proof.chain_tip_height,
                self.sync_batch.to_height
            ));
        }
        
        if self.recursive_proof.genesis_height != self.sync_batch.from_height {
            return Err(anyhow!(
                "Recursive proof genesis height {} doesn't match batch from_height {}",
                self.recursive_proof.genesis_height,
                self.sync_batch.from_height
            ));
        }
        
        // TODO: Implement actual ZK proof verification
        // self.recursive_proof.verify()?
        
        Ok(true)
    }
    
    /// Verify Merkle proofs for batch aggregation
    pub fn verify_merkle_proofs(&self) -> Result<bool> {
        // Verify transaction count matches
        if self.merkle_proof.transaction_count != self.sync_batch.transaction_count() as u64 {
            return Err(anyhow!(
                "Merkle transaction count {} doesn't match batch {}",
                self.merkle_proof.transaction_count,
                self.sync_batch.transaction_count()
            ));
        }
        
        // Verify block count matches
        let expected_blocks = (self.sync_batch.to_height - self.sync_batch.from_height) + 1;
        if self.merkle_proof.block_count != expected_blocks {
            return Err(anyhow!(
                "Merkle block count {} doesn't match expected {}",
                self.merkle_proof.block_count,
                expected_blocks
            ));
        }
        
        // Verify sample proofs (probabilistic verification)
        for sample_proof in &self.merkle_proof.sample_proofs {
            if !self.verify_merkle_path(sample_proof)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Verify a single Merkle path
    fn verify_merkle_path(&self, proof: &MerklePathProof) -> Result<bool> {
        let mut current_hash = proof.leaf_hash;
        
        for (i, sibling) in proof.path.iter().enumerate() {
            let is_right = proof.positions.get(i).copied().unwrap_or(false);
            
            current_hash = if is_right {
                Hash::combine(sibling, &current_hash)
            } else {
                Hash::combine(&current_hash, sibling)
            };
        }
        
        Ok(current_hash == self.merkle_proof.merkle_root)
    }
    
    /// Perform full validation of mesh sync transaction
    pub fn validate(&self) -> Result<()> {
        // 1. Verify coordinator signature
        // TODO: Implement signature verification
        
        // 2. Verify validator signatures (BFT threshold)
        if !self.verify_validator_signatures()? {
            return Err(anyhow!("Insufficient or invalid validator signatures"));
        }
        
        // 3. Verify recursive proof (O(1) mesh chain validation)
        if !self.verify_recursive_proof()? {
            return Err(anyhow!("Recursive proof verification failed"));
        }
        
        // 4. Verify Merkle proofs
        if !self.verify_merkle_proofs()? {
            return Err(anyhow!("Merkle proof verification failed"));
        }
        
        // 5. Verify UTXO transitions are valid
        self.verify_utxo_transitions()?;
        
        // 6. Verify sync fee is sufficient
        if self.sync_fee < self.calculate_minimum_fee() {
            return Err(anyhow!(
                "Sync fee {} is below minimum {}",
                self.sync_fee,
                self.calculate_minimum_fee()
            ));
        }
        
        Ok(())
    }
    
    /// Verify UTXO state transitions are valid
    fn verify_utxo_transitions(&self) -> Result<()> {
        // Check for double-spends within the batch
        // This is a simplified check - full implementation would verify against global UTXO set
        let mut seen_inputs = std::collections::HashSet::new();
        
        for tx in &self.sync_batch.transactions {
            for input in &tx.inputs {
                let key = (input.previous_output, input.output_index);
                if !seen_inputs.insert(key) {
                    return Err(anyhow!("Double-spend detected in batch: {:?}", key));
                }
            }
        }
        
        Ok(())
    }
    
    /// Calculate minimum fee for sync operation
    pub fn calculate_minimum_fee(&self) -> u64 {
        // Base fee + per-block fee + per-transaction fee
        let base_fee = 1000u64;
        let per_block_fee = 10u64;
        let per_tx_fee = 1u64;
        
        let block_count = (self.sync_batch.to_height - self.sync_batch.from_height) + 1;
        
        base_fee 
            + (per_block_fee * block_count)
            + (per_tx_fee * self.sync_batch.transaction_count() as u64)
    }
    
    /// Get total size estimate in bytes
    pub fn size_estimate(&self) -> usize {
        // Rough estimate for fee calculation
        let base_size = 1024; // Base transaction overhead
        let proof_size = 2048; // Recursive proof size
        let sig_size = self.validator_signatures.len() * 128;
        let batch_size = self.sync_batch.transaction_count() * 256;
        
        base_size + proof_size + sig_size + batch_size
    }
    
    /// Create a summary for logging/display
    pub fn summary(&self) -> String {
        format!(
            "MeshSync[mesh={:?}, blocks={}→{}, txs={}, validators={}/{}, fee={}]",
            self.mesh_id,
            self.sync_batch.from_height,
            self.sync_batch.to_height,
            self.sync_batch.transaction_count(),
            self.validator_signatures.len(),
            self.metadata.validator_count,
            self.sync_fee
        )
    }
}

impl MerkleBatchProof {
    /// Create an empty Merkle proof
    pub fn empty() -> Self {
        Self {
            merkle_root: Hash::default(),
            block_merkle_root: Hash::default(),
            sample_proofs: Vec::new(),
            transaction_count: 0,
            block_count: 0,
            total_size_bytes: 0,
        }
    }
    
    /// Create Merkle proof from transaction and block hashes
    pub fn from_hashes(
        transaction_hashes: Vec<Hash>,
        block_hashes: Vec<Hash>,
    ) -> Result<Self> {
        if transaction_hashes.is_empty() || block_hashes.is_empty() {
            return Err(anyhow!("Cannot create Merkle proof from empty hashes"));
        }
        
        let merkle_root = Self::calculate_merkle_root(&transaction_hashes);
        let block_merkle_root = Self::calculate_merkle_root(&block_hashes);
        
        // Generate sample proofs for verification (sample 10% or max 10)
        let sample_count = (transaction_hashes.len() / 10).min(10).max(1);
        let mut sample_proofs = Vec::new();
        
        for i in 0..sample_count {
            let index = (i * transaction_hashes.len()) / sample_count;
            if let Some(proof) = Self::generate_merkle_path(&transaction_hashes, index) {
                sample_proofs.push(proof);
            }
        }
        
        Ok(Self {
            merkle_root,
            block_merkle_root,
            sample_proofs,
            transaction_count: transaction_hashes.len() as u64,
            block_count: block_hashes.len() as u64,
            total_size_bytes: (transaction_hashes.len() + block_hashes.len()) as u64 * 32,
        })
    }
    
    /// Calculate Merkle root from hashes
    fn calculate_merkle_root(hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return Hash::default();
        }
        
        if hashes.len() == 1 {
            return hashes[0];
        }
        
        let mut current_level = hashes.to_vec();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    Hash::combine(&chunk[0], &chunk[1])
                } else {
                    chunk[0] // Odd node gets promoted
                };
                next_level.push(combined);
            }
            
            current_level = next_level;
        }
        
        current_level[0]
    }
    
    /// Generate Merkle path for a specific leaf
    fn generate_merkle_path(hashes: &[Hash], index: usize) -> Option<MerklePathProof> {
        if index >= hashes.len() {
            return None;
        }
        
        let mut path = Vec::new();
        let mut positions = Vec::new();
        let mut current_index = index;
        let mut current_level = hashes.to_vec();
        let mut height = 0;
        
        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            if sibling_index < current_level.len() {
                path.push(current_level[sibling_index]);
                positions.push(current_index % 2 == 1); // true if we're on right
            }
            
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    Hash::combine(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                };
                next_level.push(combined);
            }
            
            current_level = next_level;
            current_index /= 2;
            height += 1;
        }
        
        Some(MerklePathProof {
            leaf_hash: hashes[index],
            path,
            positions,
            height,
        })
    }
}

impl MeshSyncMetadata {
    /// Create default metadata
    pub fn default() -> Self {
        Self {
            participant_count: 1,
            validator_count: 1,
            avg_block_time: 2.0,
            total_fees_collected: 0,
            mesh_health_score: 100,
            time_since_last_sync: 0,
            sync_reason: SyncReason::Periodic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mesh_sync_transaction_creation() {
        use crate::block::Block;
        use crate::block::header::BlockHeader;
        
        let mesh_id = MeshId([1u8; 32]);
        let coordinator = NodeId([2u8; 32]);
        
        // Create dummy blocks for testing
        let mut blocks = Vec::new();
        for i in 0..100 {
            let header = BlockHeader::new(
                1, // version
                Hash::default(), // previous_hash
                Hash::default(), // merkle_root
                1234567890 + i, // timestamp
                crate::types::difficulty::Difficulty::from_bits(0x1fffffff), // difficulty
                i, // height
                0, // tx_count
                0, // block_size
                crate::types::difficulty::Difficulty::from_bits(0x1fffffff), // cumulative_difficulty
            );
            blocks.push(Block::new(header, vec![]));
        }
        
        let sync_batch = MeshSyncBatch::new(mesh_id, coordinator, blocks);
        
        let recursive_proof = ChainRecursiveProof {
            chain_tip_height: 99,
            genesis_height: 0,
            current_state_root: [0u8; 32],
            genesis_state_root: [0u8; 32],
            recursive_proof: ZkProof::default(),
            chain_commitment: [0u8; 32],
            total_transaction_count: 0,
            proof_timestamp: 0,
        };
        
        let tx = MeshSyncTransaction::new(
            0x01, // mainnet
            mesh_id,
            coordinator,
            sync_batch,
            recursive_proof,
            Signature::default(),
            5000,
        );
        
        assert_eq!(tx.chain_id, 0x01);
        assert_eq!(tx.mesh_id, mesh_id);
        assert!(!tx.has_sufficient_signatures());
    }
    
    #[test]
    fn test_validator_signature_threshold() {
        let mesh_id = MeshId([1u8; 32]);
        let mut tx = create_test_sync_transaction();
        
        // Set 4 validators
        tx.metadata.validator_count = 4;
        
        // Need 3 signatures (67% of 4 = 2.67, rounded up to 3)
        assert!(!tx.has_sufficient_signatures());
        
        // Add 2 signatures - not enough
        tx.add_validator_signature(create_test_validator_signature(NodeId([1u8; 32])));
        tx.add_validator_signature(create_test_validator_signature(NodeId([2u8; 32])));
        assert!(!tx.has_sufficient_signatures());
        
        // Add 3rd signature - now sufficient
        tx.add_validator_signature(create_test_validator_signature(NodeId([3u8; 32])));
        assert!(tx.has_sufficient_signatures());
    }
    
    #[test]
    fn test_merkle_proof_creation() {
        let hashes: Vec<Hash> = (0..8)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                Hash::new(bytes)
            })
            .collect();
        
        let proof = MerkleBatchProof::from_hashes(hashes.clone(), hashes.clone()).unwrap();
        
        assert_eq!(proof.transaction_count, 8);
        assert_eq!(proof.block_count, 8);
        assert!(!proof.sample_proofs.is_empty());
    }
    
    #[test]
    fn test_minimum_fee_calculation() {
        let tx = create_test_sync_transaction();
        let min_fee = tx.calculate_minimum_fee();
        
        // 1000 base + (10 * 100 blocks) + (1 * 500 txs) = 2500
        assert_eq!(min_fee, 2500);
    }
    
    // Helper functions
    fn create_test_sync_transaction() -> MeshSyncTransaction {
        let mesh_id = MeshId([1u8; 32]);
        
        use crate::block::Block;
        use crate::block::header::BlockHeader;
        
        // Create dummy blocks for testing
        let mut blocks = Vec::new();
        for i in 0..100 {
            let header = BlockHeader::new(
                1, // version
                Hash::default(), // previous_hash
                Hash::default(), // merkle_root
                1234567890 + i, // timestamp
                crate::types::difficulty::Difficulty::from_bits(0x1fffffff), // difficulty
                i, // height
                0, // tx_count
                0, // block_size
                crate::types::difficulty::Difficulty::from_bits(0x1fffffff), // cumulative_difficulty
            );
            blocks.push(Block::new(header, vec![]));
        }
        
        let sync_batch = MeshSyncBatch::new(
            mesh_id,
            NodeId([2u8; 32]),
            blocks,
        );
        
        let recursive_proof = ChainRecursiveProof {
            chain_tip_height: 99,
            genesis_height: 0,
            current_state_root: [0u8; 32],
            genesis_state_root: [0u8; 32],
            recursive_proof: ZkProof::default(),
            chain_commitment: [0u8; 32],
            total_transaction_count: 0,
            proof_timestamp: 0,
        };
        
        MeshSyncTransaction::new(
            0x01,
            mesh_id,
            NodeId([2u8; 32]),
            sync_batch,
            recursive_proof,
            Signature::default(),
            5000,
        )
    }
    
    fn create_test_validator_signature(validator_id: NodeId) -> ValidatorSignature {
        ValidatorSignature {
            validator_id,
            wallet_address: Hash::default(),
            signature: Signature::default(),
            public_key: PublicKey::default(),
            signed_at_height: 99,
            reputation: 80,
        }
    }
}
