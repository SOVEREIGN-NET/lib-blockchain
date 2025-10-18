//! Local Mesh Blockchain Implementation
//! 
//! Independent blockchain for local mesh clusters with lightweight consensus
//! and hierarchical sync to global validators.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use crate::types::{Hash, Difficulty};
use crate::block::{Block, BlockHeader};
use crate::transaction::{Transaction, TransactionOutput};
use super::types::{MeshId, NodeId, MeshParticipant, MeshSyncBatch, MeshEvent, MeshStatus};

/// Local mesh blockchain - operates independently from global chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalMeshBlockchain {
    /// Unique mesh identifier
    pub mesh_id: MeshId,
    
    /// Parent chain reference (snapshot when mesh was created)
    pub parent_chain_height: u64,
    pub parent_chain_hash: Hash,
    
    /// Local blockchain state
    pub blocks: Vec<Block>,
    pub height: u64,
    
    /// UTXO set for mesh (local state)
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    
    /// Nullifier set (spent outputs)
    pub nullifier_set: HashSet<Hash>,
    
    /// Pending transactions (mempool)
    pub pending_transactions: Vec<Transaction>,
    
    /// Mesh participants
    pub participants: HashMap<NodeId, MeshParticipant>,
    pub coordinator: NodeId,
    
    /// Consensus configuration
    pub consensus_threshold: u8, // Percentage (e.g., 67 for 2/3)
    pub validator_count: u32,
    
    /// Sync state
    pub last_sync_height: u64,
    pub last_sync_time: u64,
    pub pending_sync_blocks: Vec<Block>,
    
    /// Economic tracking
    pub total_mesh_transactions: u64,
    pub mesh_creation_time: u64,
    
    /// Mesh status
    pub status: MeshStatus,
    
    /// Event log
    pub events: Vec<MeshEvent>,
}

impl LocalMeshBlockchain {
    /// Create a new local mesh blockchain
    /// 
    /// # Arguments
    /// 
    /// * `coordinator` - Node ID of the mesh coordinator
    /// * `parent_chain_height` - Global chain height when mesh was created
    /// * `parent_chain_hash` - Global chain block hash at creation height
    /// 
    /// # Returns
    /// 
    /// A new LocalMeshBlockchain instance with genesis block
    pub fn new_mesh(
        coordinator: NodeId,
        parent_chain_height: u64,
        parent_chain_hash: Hash,
    ) -> Result<Self> {
        let mesh_creation_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mesh_id = MeshId::from_coordinator(coordinator, mesh_creation_time);
        
        // Create genesis block for mesh
        let genesis_block = Self::create_mesh_genesis_block(
            mesh_id,
            coordinator,
            parent_chain_height,
            mesh_creation_time,
        )?;
        
        // Initialize coordinator as first participant
        let coordinator_wallet = coordinator.as_hash(); // Use node ID hash as wallet
        let mut participants = HashMap::new();
        let mut coordinator_participant = MeshParticipant::new(
            coordinator,
            coordinator_wallet,
            0,
        );
        coordinator_participant.promote_to_validator();
        participants.insert(coordinator, coordinator_participant);
        
        // Initialize UTXO set from genesis
        let mut utxo_set = HashMap::new();
        for tx in &genesis_block.transactions {
            for (idx, output) in tx.outputs.iter().enumerate() {
                let output_hash = Self::calculate_output_hash(&tx.hash(), idx);
                utxo_set.insert(output_hash, output.clone());
            }
        }
        
        // Create mesh created event
        let creation_event = MeshEvent::MeshCreated {
            mesh_id,
            coordinator,
            parent_height: parent_chain_height,
        };
        
        Ok(Self {
            mesh_id,
            parent_chain_height,
            parent_chain_hash,
            blocks: vec![genesis_block],
            height: 0,
            utxo_set,
            nullifier_set: HashSet::new(),
            pending_transactions: Vec::new(),
            participants,
            coordinator,
            consensus_threshold: 67, // 2/3 majority
            validator_count: 1,
            last_sync_height: 0,
            last_sync_time: mesh_creation_time,
            pending_sync_blocks: Vec::new(),
            total_mesh_transactions: 0,
            mesh_creation_time,
            status: MeshStatus::new(),
            events: vec![creation_event],
        })
    }
    
    /// Create genesis block for mesh
    fn create_mesh_genesis_block(
        mesh_id: MeshId,
        coordinator: NodeId,
        parent_height: u64,
        timestamp: u64,
    ) -> Result<Block> {
        // Create genesis transaction
        let genesis_message = format!(
            "Mesh Genesis - Coordinator: {:?}, Parent: {}",
            coordinator, parent_height
        );
        
        let genesis_tx = Transaction::create_mesh_genesis_transaction(
            mesh_id,
            coordinator.as_hash(),
            genesis_message.as_bytes().to_vec(),
        )?;
        
        let merkle_root = Self::calculate_merkle_root(&[genesis_tx.clone()]);
        
        let header = BlockHeader::new(
            1,                              // version
            Hash::zero(),                  // previous_block_hash (genesis)
            merkle_root,                    // merkle_root
            timestamp,                      // timestamp
            Difficulty::from_bits(0x1fffffff), // Easy difficulty for mesh
            0,                              // height
            1,                              // transaction_count
            genesis_tx.size() as u32,       // block_size
            Difficulty::from_bits(0x1fffffff), // cumulative_difficulty
        );
        
        Ok(Block::new(header, vec![genesis_tx]))
    }
    
    /// Add a participant to the mesh
    /// 
    /// # Arguments
    /// 
    /// * `node_id` - Unique identifier for the node
    /// * `wallet_address` - Wallet address for rewards
    /// 
    /// # Returns
    /// 
    /// Ok(()) if participant was added successfully
    pub fn add_participant(
        &mut self,
        node_id: NodeId,
        wallet_address: Hash,
    ) -> Result<()> {
        // Check if already a participant
        if self.participants.contains_key(&node_id) {
            return Err(anyhow!("Node {} is already a participant", hex::encode(&node_id.0)));
        }
        
        let participant = MeshParticipant::new(node_id, wallet_address, self.height);
        self.participants.insert(node_id, participant);
        
        // Update status
        self.status.participant_count = self.participants.len() as u32;
        
        // Log event
        let event = MeshEvent::ParticipantJoined {
            mesh_id: self.mesh_id,
            node_id,
            height: self.height,
        };
        self.events.push(event);
        
        tracing::info!(
            "Mesh {}: Added participant {} at height {}",
            hex::encode(&self.mesh_id.0),
            hex::encode(&node_id.0),
            self.height
        );
        
        Ok(())
    }
    
    /// Remove a participant from the mesh
    pub fn remove_participant(&mut self, node_id: NodeId) -> Result<()> {
        // Can't remove coordinator
        if node_id == self.coordinator {
            return Err(anyhow!("Cannot remove mesh coordinator"));
        }
        
        // Check if was a validator before removing
        let was_validator = self.participants.get(&node_id)
            .map(|p| p.is_validator)
            .unwrap_or(false);
        
        if self.participants.remove(&node_id).is_none() {
            return Err(anyhow!("Participant not found"));
        }
        
        // Update validator count if was a validator
        if was_validator {
            self.validator_count = self.validator_count.saturating_sub(1);
        }
        
        // Update status
        self.status.participant_count = self.participants.len() as u32;
        
        // Log event
        let event = MeshEvent::ParticipantLeft {
            mesh_id: self.mesh_id,
            node_id,
            height: self.height,
        };
        self.events.push(event);
        
        Ok(())
    }
    
    /// Produce a new local block
    /// 
    /// Fast finality: 2-second block time for local transactions
    pub fn produce_local_block(
        &mut self,
        transactions: Vec<Transaction>,
    ) -> Result<Block> {
        let previous_block = self.blocks.last()
            .ok_or_else(|| anyhow!("No genesis block found"))?;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let merkle_root = Self::calculate_merkle_root(&transactions);
        let block_size: u32 = transactions.iter()
            .map(|tx| tx.size() as u32)
            .sum();
        
        let header = BlockHeader::new(
            1,                                    // version
            previous_block.hash(),                // previous_block_hash
            merkle_root,                          // merkle_root
            timestamp,                            // timestamp
            previous_block.header.difficulty,     // difficulty (no PoW for mesh)
            self.height + 1,                      // height
            transactions.len() as u32,            // transaction_count
            block_size,                           // block_size
            previous_block.header.cumulative_difficulty, // cumulative_difficulty
        );
        
        let block = Block::new(header, transactions.clone());
        
        // Update UTXO set
        self.update_utxo_set(&block)?;
        
        // Add block to chain
        self.blocks.push(block.clone());
        self.height += 1;
        self.total_mesh_transactions += transactions.len() as u64;
        
        // Add to pending sync
        self.pending_sync_blocks.push(block.clone());
        
        // Update status
        self.status.height = self.height;
        self.status.total_transactions = self.total_mesh_transactions;
        self.status.blocks_since_sync = self.pending_sync_blocks.len() as u64;
        
        // Log event
        let event = MeshEvent::BlockProduced {
            mesh_id: self.mesh_id,
            height: self.height,
            block_hash: block.hash(),
            transaction_count: transactions.len() as u32,
        };
        self.events.push(event);
        
        tracing::info!(
            "Mesh {}: Produced block {} with {} transactions",
            hex::encode(&self.mesh_id.0),
            self.height,
            transactions.len()
        );
        
        Ok(block)
    }
    
    /// Create a sync batch for submitting to global chain
    pub fn create_sync_batch(&mut self) -> Result<MeshSyncBatch> {
        if self.pending_sync_blocks.is_empty() {
            return Err(anyhow!("No blocks pending sync"));
        }
        
        let batch = MeshSyncBatch::new(
            self.mesh_id,
            self.coordinator,
            self.pending_sync_blocks.clone(),
        );
        
        // Update sync state
        self.last_sync_height = self.height;
        self.last_sync_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Clear pending blocks
        self.pending_sync_blocks.clear();
        
        // Update status
        self.status.blocks_since_sync = 0;
        
        // Log event
        let event = MeshEvent::BatchSynced {
            mesh_id: self.mesh_id,
            from_height: batch.from_height,
            to_height: batch.to_height,
            block_count: batch.block_count() as u32,
        };
        self.events.push(event);
        
        Ok(batch)
    }
    
    /// Update UTXO set from block
    fn update_utxo_set(&mut self, block: &Block) -> Result<()> {
        for tx in &block.transactions {
            // Remove spent outputs (inputs)
            for input in &tx.inputs {
                self.utxo_set.remove(&input.previous_output);
                self.nullifier_set.insert(input.previous_output);
            }
            
            // Add new outputs
            for (idx, output) in tx.outputs.iter().enumerate() {
                let output_hash = Self::calculate_output_hash(&tx.hash(), idx);
                self.utxo_set.insert(output_hash, output.clone());
            }
        }
        
        Ok(())
    }
    
    /// Calculate output hash
    fn calculate_output_hash(tx_hash: &Hash, index: usize) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(tx_hash.as_bytes());
        data.extend_from_slice(&index.to_le_bytes());
        Hash::from_slice(&blake3::hash(&data).as_bytes()[..32])
    }
    
    /// Calculate merkle root of transactions
    fn calculate_merkle_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::default();
        }
        
        let mut tx_hashes = Vec::new();
        for tx in transactions.iter() {
            tx_hashes.extend_from_slice(tx.hash().as_bytes());
        }
        
        Hash::from_slice(&blake3::hash(&tx_hashes).as_bytes()[..32])
    }
    
    /// Get mesh metadata
    pub fn get_metadata(&self) -> crate::mesh::types::MeshMetadata {
        crate::mesh::types::MeshMetadata {
            mesh_id: self.mesh_id,
            coordinator: self.coordinator,
            participant_count: self.participants.len() as u32,
            current_height: self.height,
            last_sync_height: self.last_sync_height,
            total_transactions: self.total_mesh_transactions,
            created_at: self.mesh_creation_time,
            parent_chain_height: self.parent_chain_height,
            parent_chain_hash: self.parent_chain_hash,
        }
    }
    
    /// Get current mesh status
    pub fn get_status(&self) -> &MeshStatus {
        &self.status
    }
    
    /// Get list of validators
    pub fn get_validators(&self) -> Vec<NodeId> {
        self.participants.values()
            .filter(|p| p.is_validator)
            .map(|p| p.node_id)
            .collect()
    }
    
    /// Get current blockchain height
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }
    
    /// Check if should create sync batch (every 100 blocks or 10 minutes)
    pub fn should_create_sync_batch(&self) -> bool {
        let blocks_since_sync = self.blocks.len() as u64 - self.last_sync_height;
        blocks_since_sync >= 100 // Sync every 100 blocks
    }
    
    /// Get coordinator node ID
    pub fn coordinator_node(&self) -> NodeId {
        self.coordinator
    }
    
    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }
    
    /// Get blocks since last sync
    pub fn blocks_since_last_sync(&self) -> u64 {
        self.height.saturating_sub(self.last_sync_height)
    }
    
    /// Get total syncs performed (estimated from events)
    pub fn total_syncs(&self) -> u64 {
        self.events.iter()
            .filter(|e| matches!(e, MeshEvent::BatchSynced { .. }))
            .count() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_node_id(val: u8) -> NodeId {
        NodeId([val; 32])
    }
    
    fn create_test_hash(val: u8) -> Hash {
        Hash::new([val; 32])
    }
    
    #[test]
    fn test_mesh_creation() {
        let coordinator = create_test_node_id(1);
        let parent_height = 1000;
        let parent_hash = create_test_hash(2);
        
        let mesh = LocalMeshBlockchain::new_mesh(
            coordinator,
            parent_height,
            parent_hash,
        ).expect("Failed to create mesh");
        
        assert_eq!(mesh.height, 0);
        assert_eq!(mesh.blocks.len(), 1); // Genesis block
        assert_eq!(mesh.participants.len(), 1); // Coordinator
        assert_eq!(mesh.coordinator, coordinator);
        assert_eq!(mesh.parent_chain_height, parent_height);
    }
    
    #[test]
    fn test_add_participant() {
        let coordinator = create_test_node_id(1);
        let parent_height = 1000;
        let parent_hash = create_test_hash(2);
        
        let mut mesh = LocalMeshBlockchain::new_mesh(
            coordinator,
            parent_height,
            parent_hash,
        ).expect("Failed to create mesh");
        
        let participant_id = create_test_node_id(3);
        let wallet = create_test_hash(4);
        
        mesh.add_participant(participant_id, wallet)
            .expect("Failed to add participant");
        
        assert_eq!(mesh.participants.len(), 2);
        assert_eq!(mesh.status.participant_count, 2);
    }
    
    #[test]
    fn test_remove_participant() {
        let coordinator = create_test_node_id(1);
        let parent_height = 1000;
        let parent_hash = create_test_hash(2);
        
        let mut mesh = LocalMeshBlockchain::new_mesh(
            coordinator,
            parent_height,
            parent_hash,
        ).expect("Failed to create mesh");
        
        let participant_id = create_test_node_id(3);
        let wallet = create_test_hash(4);
        
        mesh.add_participant(participant_id, wallet).unwrap();
        assert_eq!(mesh.participants.len(), 2);
        
        mesh.remove_participant(participant_id).unwrap();
        assert_eq!(mesh.participants.len(), 1);
        
        // Should not be able to remove coordinator
        let result = mesh.remove_participant(coordinator);
        assert!(result.is_err());
    }
}
