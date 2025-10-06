//! Core transaction structures
//!
//! Defines the fundamental transaction data structures used in the ZHTP blockchain.

use serde::{Serialize, Deserialize};
use crate::types::{Hash, transaction_type::TransactionType};
use crate::integration::crypto_integration::{Signature, PublicKey};
use crate::integration::zk_integration::ZkTransactionProof;

/// Zero-knowledge transaction with identity support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction version
    pub version: u32,
    /// Type of transaction (transfer, identity, contract)
    pub transaction_type: TransactionType,
    /// Transaction inputs (UTXOs being spent)
    pub inputs: Vec<TransactionInput>,
    /// Transaction outputs (new UTXOs being created)
    pub outputs: Vec<TransactionOutput>,
    /// Transaction fee amount
    pub fee: u64,
    /// Digital signature for transaction authorization
    pub signature: Signature,
    /// Optional memo data
    pub memo: Vec<u8>,
    /// Identity-specific data (only for identity transactions)
    /// This data is processed by lib-identity package
    pub identity_data: Option<IdentityTransactionData>,
    /// Wallet-specific data (only for wallet transactions)
    /// This data is processed by lib-identity package
    pub wallet_data: Option<WalletTransactionData>,
}

/// Transaction input referencing a previous output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    /// Hash of the transaction containing the output being spent
    pub previous_output: Hash,
    /// Index of the output in the previous transaction
    pub output_index: u32,
    /// Zero-knowledge nullifier to prevent double-spending
    pub nullifier: Hash,
    /// Zero-knowledge proof validating the spend
    pub zk_proof: ZkTransactionProof,
}

/// Transaction output creating a new UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOutput {
    /// Pedersen commitment hiding the amount
    pub commitment: Hash,
    /// Encrypted note for the recipient
    pub note: Hash,
    /// Public key of the recipient
    pub recipient: PublicKey,
}

/// Identity transaction data (processed by lib-identity package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityTransactionData {
    /// Zero-knowledge DID identifier
    pub did: String,
    /// Human-readable display name
    pub display_name: String,
    /// Public key for identity verification
    pub public_key: Vec<u8>,
    /// Zero-knowledge proof of identity ownership
    pub ownership_proof: Vec<u8>,
    /// Type of identity (human, organization, device, etc.)
    pub identity_type: String,
    /// Hash of the DID document
    pub did_document_hash: Hash,
    /// Creation timestamp
    pub created_at: u64,
    /// Registration fee paid
    pub registration_fee: u64,
    /// DAO fee contribution
    pub dao_fee: u64,
}

/// Wallet registration transaction data (processed by lib-identity package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransactionData {
    /// Unique wallet identifier (32-byte hash)
    pub wallet_id: Hash,
    /// Wallet type (Primary, UBI, Savings, etc.)
    pub wallet_type: String,
    /// Human-readable wallet name
    pub wallet_name: String,
    /// Optional wallet alias
    pub alias: Option<String>,
    /// Public key for wallet operations
    pub public_key: Vec<u8>,
    /// Owner identity ID (if associated with DID)
    pub owner_identity_id: Option<Hash>,
    /// Seed phrase commitment hash (for recovery verification)
    pub seed_commitment: Hash,
    /// Creation timestamp
    pub created_at: u64,
    /// Registration fee paid
    pub registration_fee: u64,
    /// Wallet capabilities flags
    pub capabilities: u32,
    /// Initial balance (if any)
    pub initial_balance: u64,
}

impl Transaction {
    /// Create a new standard transfer transaction
    pub fn new(
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            transaction_type: TransactionType::Transfer,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
        }
    }

    /// Create a new identity registration transaction
    pub fn new_identity_registration(
        identity_data: IdentityTransactionData,
        outputs: Vec<TransactionOutput>, // For fee payments
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            transaction_type: TransactionType::IdentityRegistration,
            inputs: Vec::new(), // Identity registration doesn't have inputs
            outputs,
            fee: identity_data.registration_fee + identity_data.dao_fee,
            signature,
            memo,
            identity_data: Some(identity_data),
            wallet_data: None,
        }
    }

    /// Create a new identity update transaction
    pub fn new_identity_update(
        identity_data: IdentityTransactionData,
        inputs: Vec<TransactionInput>, // Authorization from existing identity
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            transaction_type: TransactionType::IdentityUpdate,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: Some(identity_data),
            wallet_data: None,
        }
    }

    /// Create a new identity revocation transaction
    pub fn new_identity_revocation(
        did: String,
        inputs: Vec<TransactionInput>, // Authorization from existing identity
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        let revocation_data = IdentityTransactionData {
            did,
            display_name: "revoked".to_string(),
            public_key: Vec::new(), // Empty for revocation
            ownership_proof: Vec::new(),
            identity_type: "revoked".to_string(),
            did_document_hash: Hash::default(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            registration_fee: 0,
            dao_fee: 0,
        };

        Transaction {
            version: 1,
            transaction_type: TransactionType::IdentityRevocation,
            inputs,
            outputs: Vec::new(),
            fee,
            signature,
            memo,
            identity_data: Some(revocation_data),
            wallet_data: None,
        }
    }

    /// Create a new wallet registration transaction
    pub fn new_wallet_registration(
        wallet_data: WalletTransactionData,
        outputs: Vec<TransactionOutput>, // For fee payments
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            transaction_type: TransactionType::WalletRegistration,
            inputs: Vec::new(), // Wallet registration doesn't need inputs
            outputs,
            fee: wallet_data.registration_fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: Some(wallet_data),
        }
    }

    /// Calculate transaction hash
    pub fn hash(&self) -> Hash {
        crate::transaction::hashing::hash_transaction(self)
    }

    /// Calculate transaction hash for signing (excludes signature)
    pub fn signing_hash(&self) -> Hash {
        crate::transaction::hashing::hash_transaction_for_signing(self)
    }

    /// Verify transaction validity
    pub fn verify(&self) -> anyhow::Result<bool> {
        let validator = crate::transaction::validation::TransactionValidator::new();
        Ok(validator.validate_transaction(self).is_ok())
    }

    /// Get the transaction ID (hash)
    pub fn id(&self) -> Hash {
        self.hash()
    }

    /// Check if this is a coinbase transaction
    /// Note: ZHTP uses native token system, not Bitcoin-style coinbase
    pub fn is_coinbase(&self) -> bool {
        false
    }

    /// Get the total input value (if known)
    /// In a zero-knowledge system, amounts are hidden
    pub fn total_input_value(&self) -> Option<u64> {
        // In ZK system, amounts are hidden by commitments
        // This would require additional proof verification
        None
    }

    /// Get the total output value (if known)
    /// In a zero-knowledge system, amounts are hidden
    pub fn total_output_value(&self) -> Option<u64> {
        // In ZK system, amounts are hidden by commitments
        // This would require additional proof verification
        None
    }

    /// Check if transaction has identity data
    pub fn has_identity_data(&self) -> bool {
        self.identity_data.is_some()
    }

    /// Get the size of the transaction in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self).map(|data| data.len()).unwrap_or(0)
    }

    /// Check if transaction is empty (no inputs or outputs)
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty() && self.outputs.is_empty()
    }
}

impl TransactionInput {
    /// Create a new transaction input
    pub fn new(
        previous_output: Hash,
        output_index: u32,
        nullifier: Hash,
        zk_proof: ZkTransactionProof,
    ) -> Self {
        Self {
            previous_output,
            output_index,
            nullifier,
            zk_proof,
        }
    }

    /// Get the outpoint (previous_output + output_index)
    pub fn outpoint(&self) -> (Hash, u32) {
        (self.previous_output, self.output_index)
    }
}

impl TransactionOutput {
    /// Create a new transaction output
    pub fn new(
        commitment: Hash,
        note: Hash,
        recipient: PublicKey,
    ) -> Self {
        Self {
            commitment,
            note,
            recipient,
        }
    }

    /// Check if this output is to a specific recipient
    pub fn is_to_recipient(&self, recipient: &PublicKey) -> bool {
        &self.recipient == recipient
    }
}

impl IdentityTransactionData {
    /// Create new identity transaction data
    pub fn new(
        did: String,
        display_name: String,
        public_key: Vec<u8>,
        ownership_proof: Vec<u8>,
        identity_type: String,
        did_document_hash: Hash,
        registration_fee: u64,
        dao_fee: u64,
    ) -> Self {
        Self {
            did,
            display_name,
            public_key,
            ownership_proof,
            identity_type,
            did_document_hash,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            registration_fee,
            dao_fee,
        }
    }

    /// Get total fees (registration + DAO)
    pub fn total_fees(&self) -> u64 {
        self.registration_fee + self.dao_fee
    }

    /// Check if this is a revoked identity
    pub fn is_revoked(&self) -> bool {
        self.identity_type == "revoked"
    }
}
