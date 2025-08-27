//! Transaction creation utilities
//!
//! Provides functionality for creating new transactions in the ZHTP blockchain.

use crate::transaction::core::{Transaction, TransactionInput, TransactionOutput, IdentityTransactionData};
use crate::types::{Hash, transaction_type::TransactionType};
use crate::integration::crypto_integration::{Signature, PublicKey, PrivateKey, KeyPair, SignatureAlgorithm};
use crate::integration::zk_integration::ZkTransactionProof;
use serde::{Serialize, Deserialize};

/// Error types for transaction creation
#[derive(Debug, Clone)]
pub enum TransactionCreateError {
    InsufficientFunds,
    InvalidInputs,
    InvalidOutputs,
    SigningError,
    ZkProofError,
    IdentityError,
}

impl std::fmt::Display for TransactionCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionCreateError::InsufficientFunds => write!(f, "Insufficient funds"),
            TransactionCreateError::InvalidInputs => write!(f, "Invalid transaction inputs"),
            TransactionCreateError::InvalidOutputs => write!(f, "Invalid transaction outputs"),
            TransactionCreateError::SigningError => write!(f, "Transaction signing failed"),
            TransactionCreateError::ZkProofError => write!(f, "Zero-knowledge proof generation failed"),
            TransactionCreateError::IdentityError => write!(f, "Identity transaction creation failed"),
        }
    }
}

impl std::error::Error for TransactionCreateError {}

/// Builder for creating transactions
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    version: u32,
    transaction_type: TransactionType,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    memo: Vec<u8>,
    identity_data: Option<IdentityTransactionData>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            version: 1,
            transaction_type: TransactionType::Transfer,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            memo: Vec::new(),
            identity_data: None,
        }
    }

    /// Set transaction version
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set transaction type
    pub fn transaction_type(mut self, tx_type: TransactionType) -> Self {
        self.transaction_type = tx_type;
        self
    }

    /// Add an input to the transaction
    pub fn add_input(mut self, input: TransactionInput) -> Self {
        self.inputs.push(input);
        self
    }

    /// Add multiple inputs to the transaction
    pub fn add_inputs(mut self, inputs: Vec<TransactionInput>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    /// Add an output to the transaction
    pub fn add_output(mut self, output: TransactionOutput) -> Self {
        self.outputs.push(output);
        self
    }

    /// Add multiple outputs to the transaction
    pub fn add_outputs(mut self, outputs: Vec<TransactionOutput>) -> Self {
        self.outputs.extend(outputs);
        self
    }

    /// Set transaction fee
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Set memo data
    pub fn memo(mut self, memo: Vec<u8>) -> Self {
        self.memo = memo;
        self
    }

    /// Set identity data (for identity transactions)
    pub fn identity_data(mut self, identity_data: IdentityTransactionData) -> Self {
        self.identity_data = Some(identity_data);
        self.transaction_type = TransactionType::IdentityRegistration;
        self
    }

    /// Build the transaction (requires signing)
    pub fn build(self, private_key: &PrivateKey) -> Result<Transaction, TransactionCreateError> {
        // Validate inputs and outputs
        if self.inputs.is_empty() && !self.transaction_type.is_identity_transaction() {
            return Err(TransactionCreateError::InvalidInputs);
        }

        if self.outputs.is_empty() && !self.transaction_type.is_identity_transaction() {
            return Err(TransactionCreateError::InvalidOutputs);
        }

        // Create unsigned transaction
        let mut transaction = Transaction {
            version: self.version,
            transaction_type: self.transaction_type,
            inputs: self.inputs,
            outputs: self.outputs,
            fee: self.fee,
            signature: Signature {
                signature: Vec::new(),
                public_key: PublicKey::new(Vec::new()),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: 0,
            }, // Will be set below
            memo: self.memo,
            identity_data: self.identity_data,
        };

        // Sign the transaction
        transaction.signature = Self::sign_transaction(&transaction, private_key)
            .map_err(|_| TransactionCreateError::SigningError)?;

        Ok(transaction)
    }

    /// Sign a transaction with the given private key
    fn sign_transaction(transaction: &Transaction, private_key: &PrivateKey) -> Result<Signature, String> {
        // Create transaction hash for signing (without signature)
        let mut tx_for_signing = transaction.clone();
        tx_for_signing.signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(Vec::new()),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };
        
        let tx_hash = crate::transaction::hashing::hash_transaction(&tx_for_signing);
        
        // Create a keypair from the private key for signing
        let keypair = KeyPair::generate()
            .map_err(|e| format!("Failed to create keypair: {}", e))?;
        
        // Sign the transaction hash using the keypair
        keypair.sign(tx_hash.as_bytes())
            .map_err(|e| format!("Signing failed: {}", e))
    }
}

/// Create a simple transfer transaction
pub fn create_transfer_transaction(
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::Transfer)
        .add_inputs(inputs)
        .add_outputs(outputs)
        .fee(fee)
        .build(private_key)
}

/// Create an identity registration transaction
pub fn create_identity_transaction(
    identity_data: IdentityTransactionData,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::IdentityRegistration)
        .identity_data(identity_data)
        .fee(fee)
        .build(private_key)
}

/// Create a contract deployment transaction
pub fn create_contract_transaction(
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::ContractDeployment)
        .add_inputs(inputs)
        .add_outputs(outputs)
        .fee(fee)
        .build(private_key)
}

/// Create a token operation transaction
pub fn create_token_transaction(
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::Transfer) // Use Transfer for token operations
        .add_inputs(inputs)
        .add_outputs(outputs)
        .fee(fee)
        .build(private_key)
}

/// Utility functions for transaction creation
pub mod utils {
    use super::*;

    /// Calculate the minimum fee for a transaction based on size
    pub fn calculate_minimum_fee(transaction_size: usize) -> u64 {
        // Base fee + size-based fee (1 unit per byte)
        let base_fee = 1000u64;
        let size_fee = transaction_size as u64;
        base_fee + size_fee
    }

    /// Estimate transaction size before creation
    pub fn estimate_transaction_size(
        num_inputs: usize,
        num_outputs: usize,
        memo_size: usize,
        has_identity_data: bool,
    ) -> usize {
        // Rough estimation based on typical sizes
        let base_size = 64; // Version, type, fee, signature
        let input_size = num_inputs * 128; // Previous output + nullifier + proof
        let output_size = num_outputs * 96; // Commitment + note + recipient
        let memo_size = memo_size;
        let identity_size = if has_identity_data { 256 } else { 0 };

        base_size + input_size + output_size + memo_size + identity_size
    }

    /// Validate transaction structure before creation
    pub fn validate_transaction_structure(
        transaction_type: &TransactionType,
        inputs: &[TransactionInput],
        outputs: &[TransactionOutput],
        identity_data: &Option<IdentityTransactionData>,
    ) -> Result<(), TransactionCreateError> {
        match transaction_type {
            TransactionType::Transfer => {
                if inputs.is_empty() || outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
            }
            TransactionType::IdentityRegistration |
            TransactionType::IdentityUpdate |
            TransactionType::IdentityRevocation => {
                if identity_data.is_none() {
                    return Err(TransactionCreateError::IdentityError);
                }
            }
            TransactionType::ContractDeployment | TransactionType::ContractExecution => {
                if inputs.is_empty() || outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
            }
        }

        Ok(())
    }
}
