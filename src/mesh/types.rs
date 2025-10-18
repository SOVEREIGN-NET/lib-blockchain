//! Types for Local Mesh Blockchain

use serde::{Deserialize, Serialize};
use crate::types::Hash;
use crate::block::Block;
use crate::transaction::Transaction;
use std::collections::HashMap;

/// Unique identifier for a mesh network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshId(pub [u8; 32]);

impl MeshId {
    /// Create a new mesh ID from coordinator node ID and timestamp
    pub fn from_coordinator(coordinator: NodeId, timestamp: u64) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&coordinator.0);
        data.extend_from_slice(&timestamp.to_le_bytes());
        let hash_bytes = blake3::hash(&data);
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        MeshId(id)
    }
    
    /// Get as Hash for compatibility
    pub fn as_hash(&self) -> Hash {
        Hash::new(self.0)
    }
}

/// Node identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_hash(hash: &Hash) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_bytes());
        NodeId(id)
    }
    
    pub fn as_hash(&self) -> Hash {
        Hash::new(self.0)
    }
}

/// Mesh participant information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshParticipant {
    /// Unique node identifier
    pub node_id: NodeId,
    
    /// Wallet address for rewards
    pub wallet_address: Hash,
    
    /// Height when participant joined
    pub joined_at_height: u64,
    
    /// Is this participant a validator?
    pub is_validator: bool,
    
    /// Reputation score (0-100)
    pub reputation_score: u32,
    
    /// Total blocks validated
    pub blocks_validated: u64,
    
    /// Total uptime (seconds)
    pub total_uptime: u64,
}

impl MeshParticipant {
    /// Create a new mesh participant
    pub fn new(node_id: NodeId, wallet_address: Hash, height: u64) -> Self {
        Self {
            node_id,
            wallet_address,
            joined_at_height: height,
            is_validator: false,
            reputation_score: 50, // Start at 50/100
            blocks_validated: 0,
            total_uptime: 0,
        }
    }
    
    /// Promote participant to validator
    pub fn promote_to_validator(&mut self) {
        self.is_validator = true;
    }
    
    /// Increase reputation (max 100)
    pub fn increase_reputation(&mut self, amount: u32) {
        self.reputation_score = (self.reputation_score + amount).min(100);
    }
    
    /// Decrease reputation (min 0)
    pub fn decrease_reputation(&mut self, amount: u32) {
        self.reputation_score = self.reputation_score.saturating_sub(amount);
    }
}

/// Batch of mesh blocks for syncing to global chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSyncBatch {
    /// Mesh identifier
    pub mesh_id: MeshId,
    
    /// Coordinator node
    pub coordinator: NodeId,
    
    /// Height range being synced
    pub from_height: u64,
    pub to_height: u64,
    
    /// Blocks in this batch
    pub blocks: Vec<Block>,
    
    /// All transactions from these blocks (flattened)
    pub transactions: Vec<Transaction>,
    
    /// Merkle root of all blocks in batch
    pub merkle_root: Hash,
    
    /// Timestamp when batch was created
    pub created_at: u64,
}

impl MeshSyncBatch {
    /// Create a new sync batch from blocks
    pub fn new(
        mesh_id: MeshId,
        coordinator: NodeId,
        blocks: Vec<Block>,
    ) -> Self {
        let from_height = blocks.first().map(|b| b.height()).unwrap_or(0);
        let to_height = blocks.last().map(|b| b.height()).unwrap_or(0);
        
        // Extract all transactions
        let mut transactions = Vec::new();
        for block in &blocks {
            transactions.extend(block.transactions.clone());
        }
        
        // Calculate merkle root
        let merkle_root = Self::calculate_batch_merkle_root(&blocks);
        
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            mesh_id,
            coordinator,
            from_height,
            to_height,
            blocks,
            transactions,
            merkle_root,
            created_at,
        }
    }
    
    /// Calculate merkle root of block hashes
    fn calculate_batch_merkle_root(blocks: &[Block]) -> Hash {
        if blocks.is_empty() {
            return Hash::default();
        }
        
        let mut block_hashes = Vec::new();
        for block in blocks.iter() {
            block_hashes.extend_from_slice(block.hash().as_bytes());
        }
        
        Hash::from_slice(&blake3::hash(&block_hashes).as_bytes()[..32])
    }
    
    /// Get the number of blocks in batch
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
    
    /// Get the number of transactions in batch
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
    
    /// Calculate hash of this batch for signatures
    pub fn batch_hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.mesh_id.0);
        data.extend_from_slice(&self.coordinator.0);
        data.extend_from_slice(&self.from_height.to_le_bytes());
        data.extend_from_slice(&self.to_height.to_le_bytes());
        data.extend_from_slice(self.merkle_root.as_bytes());
        data.extend_from_slice(&self.created_at.to_le_bytes());
        
        Hash::from_slice(&blake3::hash(&data).as_bytes()[..32])
    }
}

/// Metadata about a mesh network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMetadata {
    /// Mesh identifier
    pub mesh_id: MeshId,
    
    /// Coordinator node
    pub coordinator: NodeId,
    
    /// Number of participants
    pub participant_count: u32,
    
    /// Current blockchain height
    pub current_height: u64,
    
    /// Last height synced to global chain
    pub last_sync_height: u64,
    
    /// Total transactions processed
    pub total_transactions: u64,
    
    /// Mesh creation time
    pub created_at: u64,
    
    /// Parent chain reference
    pub parent_chain_height: u64,
    pub parent_chain_hash: Hash,
}

/// Events that occur in mesh lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshEvent {
    /// Mesh was created
    MeshCreated {
        mesh_id: MeshId,
        coordinator: NodeId,
        parent_height: u64,
    },
    
    /// Participant joined mesh
    ParticipantJoined {
        mesh_id: MeshId,
        node_id: NodeId,
        height: u64,
    },
    
    /// Participant left mesh
    ParticipantLeft {
        mesh_id: MeshId,
        node_id: NodeId,
        height: u64,
    },
    
    /// Block was produced
    BlockProduced {
        mesh_id: MeshId,
        height: u64,
        block_hash: Hash,
        transaction_count: u32,
    },
    
    /// Batch was synced to global chain
    BatchSynced {
        mesh_id: MeshId,
        from_height: u64,
        to_height: u64,
        block_count: u32,
    },
    
    /// Coordinator changed
    CoordinatorChanged {
        mesh_id: MeshId,
        old_coordinator: NodeId,
        new_coordinator: NodeId,
    },
}

/// Current status of a mesh network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshStatus {
    /// Is mesh currently active?
    pub active: bool,
    
    /// Number of active participants
    pub participant_count: u32,
    
    /// Current height
    pub height: u64,
    
    /// Blocks since last sync
    pub blocks_since_sync: u64,
    
    /// Average block time (seconds)
    pub avg_block_time: f64,
    
    /// Total transactions processed
    pub total_transactions: u64,
    
    /// Health score (0-100)
    pub health_score: u32,
}

impl MeshStatus {
    /// Create a default status
    pub fn new() -> Self {
        Self {
            active: true,
            participant_count: 1,
            height: 0,
            blocks_since_sync: 0,
            avg_block_time: 2.0,
            total_transactions: 0,
            health_score: 100,
        }
    }
}

impl Default for MeshStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mesh_id_creation() {
        let coordinator = NodeId([1u8; 32]);
        let timestamp = 1234567890;
        
        let mesh_id = MeshId::from_coordinator(coordinator, timestamp);
        assert_ne!(mesh_id.0, [0u8; 32]);
    }
    
    #[test]
    fn test_mesh_participant() {
        let node_id = NodeId([2u8; 32]);
        let wallet = Hash::new([3u8; 32]);
        
        let mut participant = MeshParticipant::new(node_id, wallet, 0);
        assert_eq!(participant.reputation_score, 50);
        assert!(!participant.is_validator);
        
        participant.promote_to_validator();
        assert!(participant.is_validator);
        
        participant.increase_reputation(30);
        assert_eq!(participant.reputation_score, 80);
        
        participant.decrease_reputation(10);
        assert_eq!(participant.reputation_score, 70);
    }
    
    #[test]
    fn test_mesh_status() {
        let status = MeshStatus::new();
        assert!(status.active);
        assert_eq!(status.health_score, 100);
        assert_eq!(status.avg_block_time, 2.0);
    }
}
