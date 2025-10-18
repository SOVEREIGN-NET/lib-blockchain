//! Local Mesh Blockchain Module
//! 
//! Independent blockchain instances for local mesh clusters that operate autonomously
//! and sync to global validators using recursive proof aggregation.
//! 
//! ## Architecture
//! 
//! - **Local Mesh Blockchain**: Independent chain per mesh cluster (like Polkadot parachains)
//! - **Mesh Consensus**: Lightweight BFT consensus for local finality
//! - **Hierarchical Sync**: Mesh → Regional Relay → Global Validators
//! - **Recursive Proofs**: O(1) verification of entire mesh history
//! 
//! ## Key Components
//! 
//! - `LocalMeshBlockchain`: Core blockchain structure for mesh clusters
//! - `MeshParticipant`: Participant management and validation
//! - `MeshSyncBatch`: Batch of blocks for syncing to global chain
//! 
//! ## Example Usage
//! 
//! ```rust,no_run
//! use lib_blockchain::mesh::{LocalMeshBlockchain, MeshId};
//! use lib_crypto::Hash;
//! 
//! // Create a new local mesh blockchain
//! let coordinator_id = Hash::from_bytes(&[1u8; 32]);
//! let parent_height = 12345;
//! let parent_hash = Hash::from_bytes(&[2u8; 32]);
//! 
//! let mut mesh = LocalMeshBlockchain::new_mesh(
//!     coordinator_id,
//!     parent_height,
//!     parent_hash,
//! ).expect("Failed to create mesh");
//! 
//! // Add participants
//! let participant_id = Hash::from_bytes(&[3u8; 32]);
//! let wallet_addr = Hash::from_bytes(&[4u8; 32]);
//! mesh.add_participant(participant_id, wallet_addr)
//!     .expect("Failed to add participant");
//! 
//! // Produce local blocks with fast finality (2 seconds)
//! let transactions = vec![]; // Local transactions
//! let block = mesh.produce_local_block(transactions)
//!     .expect("Failed to produce block");
//! ```

pub mod local_mesh_blockchain;
pub mod types;

pub use local_mesh_blockchain::LocalMeshBlockchain;
pub use types::{
    MeshId, MeshParticipant, MeshSyncBatch, MeshMetadata,
    MeshEvent, MeshStatus,
};
