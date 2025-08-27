//! Transaction validation logic
//!
//! Provides comprehensive validation for ZHTP blockchain transactions.

use crate::transaction::core::{Transaction, TransactionInput, TransactionOutput, IdentityTransactionData};
use crate::types::{Hash, transaction_type::TransactionType};
use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
use crate::integration::zk_integration::{ZkTransactionProof, verify_transaction_proof, is_valid_proof_structure};
use serde::{Serialize, Deserialize};

/// Transaction validation error types
#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidSignature,
    InvalidZkProof,
    DoubleSpend,
    InvalidAmount,
    InvalidFee,
    InvalidTransaction,
    InvalidIdentityData,
    InvalidInputs,
    InvalidOutputs,
    MissingRequiredData,
    InvalidTransactionType,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidSignature => write!(f, "Invalid transaction signature"),
            ValidationError::InvalidZkProof => write!(f, "Invalid zero-knowledge proof"),
            ValidationError::DoubleSpend => write!(f, "Double spend detected"),
            ValidationError::InvalidAmount => write!(f, "Invalid transaction amount"),
            ValidationError::InvalidFee => write!(f, "Invalid transaction fee"),
            ValidationError::InvalidTransaction => write!(f, "Invalid transaction structure"),
            ValidationError::InvalidIdentityData => write!(f, "Invalid identity data"),
            ValidationError::InvalidInputs => write!(f, "Invalid transaction inputs"),
            ValidationError::InvalidOutputs => write!(f, "Invalid transaction outputs"),
            ValidationError::MissingRequiredData => write!(f, "Missing required transaction data"),
            ValidationError::InvalidTransactionType => write!(f, "Invalid transaction type"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Transaction validation result
pub type ValidationResult = Result<(), ValidationError>;

/// Transaction validator with state context
pub struct TransactionValidator {
    // Note: In real implementation, this would contain references to
    // blockchain state, UTXO set, nullifier set, etc.
}

impl TransactionValidator {
    /// Create a new transaction validator
    pub fn new() -> Self {
        Self {}
    }

    /// Validate a transaction completely
    pub fn validate_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Check if this is a system transaction (empty inputs = coinbase-style)
        let is_system_transaction = transaction.inputs.is_empty();

        // Basic structure validation
        self.validate_basic_structure(transaction)?;

        // Type-specific validation
        match transaction.transaction_type {
            TransactionType::Transfer => {
                if !is_system_transaction {
                    self.validate_transfer_transaction(transaction)?;
                }
                // System transactions with Transfer type are allowed (UBI/rewards)
            },
            TransactionType::IdentityRegistration => self.validate_identity_transaction(transaction)?,
            TransactionType::IdentityUpdate => self.validate_identity_transaction(transaction)?,
            TransactionType::IdentityRevocation => self.validate_identity_transaction(transaction)?,
            TransactionType::ContractDeployment => self.validate_contract_transaction(transaction)?,
            TransactionType::ContractExecution => self.validate_contract_transaction(transaction)?,
        }

        // Signature validation (always required)
        self.validate_signature(transaction)?;

        // Zero-knowledge proof validation (skip for system transactions)
        if !is_system_transaction {
            self.validate_zk_proofs(transaction)?;
        }

        // Economic validation (modified for system transactions)
        self.validate_economics_with_system_check(transaction, is_system_transaction)?;

        Ok(())
    }

    /// Validate basic transaction structure
    fn validate_basic_structure(&self, transaction: &Transaction) -> ValidationResult {
        // Check version
        if transaction.version == 0 {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check transaction size limits
        if transaction.size() > MAX_TRANSACTION_SIZE {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check memo size
        if transaction.memo.len() > MAX_MEMO_SIZE {
            return Err(ValidationError::InvalidTransaction);
        }

        Ok(())
    }

    /// Validate transfer transaction
    fn validate_transfer_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Allow empty inputs for system transactions (UBI, rewards, minting)
        // System transactions are identified by having a genesis/zero input
        let is_system_transaction = transaction.inputs.is_empty() || 
            transaction.inputs.iter().all(|input| {
                input.previous_output == Hash::default() && 
                input.nullifier != Hash::default() // Must have unique nullifier even for system tx
            });

        if !is_system_transaction && transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }

        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Validate inputs (only if not system transaction)
        if !is_system_transaction {
            for input in &transaction.inputs {
                self.validate_transaction_input(input)?;
            }
        }

        // Validate outputs
        for output in &transaction.outputs {
            self.validate_transaction_output(output)?;
        }

        Ok(())
    }

    /// Validate identity transaction
    fn validate_identity_transaction(&self, transaction: &Transaction) -> ValidationResult {
        let identity_data = transaction.identity_data.as_ref()
            .ok_or(ValidationError::MissingRequiredData)?;

        self.validate_identity_data(identity_data)?;

        // Identity transactions should have minimal inputs/outputs
        // The main logic is handled by zhtp-identity package
        
        Ok(())
    }

    /// Validate contract transaction
    fn validate_contract_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Contract validation is handled by zhtp-contracts package
        // Here we just validate basic structure
        
        if transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }

        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate token transaction
    fn validate_token_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Token validation is handled by zhtp-economics package
        // Here we just validate basic structure
        
        // System transactions (empty inputs) are valid for UBI/rewards
        if transaction.inputs.is_empty() {
            // This is a system transaction - only validate outputs
            if transaction.outputs.is_empty() {
                return Err(ValidationError::InvalidOutputs);
            }
            return Ok(());
        }

        // Regular transactions need both inputs and outputs
        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate transaction signature
    fn validate_signature(&self, transaction: &Transaction) -> ValidationResult {
        // Create transaction hash for verification (without signature)
        let mut tx_for_verification = transaction.clone();
        tx_for_verification.signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(Vec::new()),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };
        
        let _tx_hash = tx_for_verification.hash();
        
        // For validation, we need the public key from the transaction
        // In a full implementation, this would come from the UTXO being spent
        // For now, we verify the signature structure is valid
        
        if transaction.signature.signature.is_empty() {
            return Err(ValidationError::InvalidSignature);
        }

        // Note: Full signature verification requires the public key
        // This would be extracted from the previous transaction output
        // or provided in the zero-knowledge proof
        
        Ok(())
    }

    /// Validate zero-knowledge proofs for all inputs
    fn validate_zk_proofs(&self, transaction: &Transaction) -> ValidationResult {
        for input in &transaction.inputs {
            if !verify_transaction_proof(&input.zk_proof) {
                return Err(ValidationError::InvalidZkProof);
            }
        }

        Ok(())
    }

    /// Validate economic aspects (fees, amounts) with system transaction support
    fn validate_economics_with_system_check(&self, transaction: &Transaction, is_system_transaction: bool) -> ValidationResult {
        if is_system_transaction {
            // System transactions are fee-free and create new money
            if transaction.fee != 0 {
                return Err(ValidationError::InvalidFee);
            }
            // System transactions don't need fee validation
            return Ok(());
        }

        // Regular transaction fee validation
        let min_fee = calculate_minimum_fee(transaction.size());
        if transaction.fee < min_fee {
            return Err(ValidationError::InvalidFee);
        }

        // Economic validation is handled by zhtp-economics package
        // Here we just check basic fee requirements

        Ok(())
    }

    /// Validate economic aspects (fees, amounts) - legacy method
    fn validate_economics(&self, transaction: &Transaction) -> ValidationResult {
        // Check minimum fee
        let min_fee = calculate_minimum_fee(transaction.size());
        if transaction.fee < min_fee {
            return Err(ValidationError::InvalidFee);
        }

        // Economic validation is handled by zhtp-economics package
        // Here we just check basic fee requirements

        Ok(())
    }

    /// Validate individual transaction input
    fn validate_transaction_input(&self, input: &TransactionInput) -> ValidationResult {
        // Check nullifier is not zero (unless this is a system transaction input)
        if input.nullifier == Hash::default() {
            return Err(ValidationError::InvalidInputs);
        }

        // Check previous output reference (system transactions can have Hash::default())
        // System transactions are identified by having Hash::default() previous_output with valid nullifier
        if input.previous_output == Hash::default() && input.nullifier != Hash::default() {
            // This might be a system transaction input - allow it
            return Ok(());
        }

        if input.previous_output == Hash::default() {
            return Err(ValidationError::InvalidInputs);
        }

        // Note: Double spend checking would require access to nullifier set
        // This is handled at the blockchain level

        Ok(())
    }

    /// Validate individual transaction output
    fn validate_transaction_output(&self, output: &TransactionOutput) -> ValidationResult {
        // Check commitment is not zero
        if output.commitment == Hash::default() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Check note is not zero
        if output.note == Hash::default() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Check recipient public key is valid
        if output.recipient.dilithium_pk.is_empty() && output.recipient.ed25519_pk.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate identity transaction data
    fn validate_identity_data(&self, identity_data: &IdentityTransactionData) -> ValidationResult {
        // Check DID format
        if identity_data.did.is_empty() || !identity_data.did.starts_with("did:zhtp:") {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check display name
        if identity_data.display_name.is_empty() || identity_data.display_name.len() > 64 {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check public key
        if identity_data.public_key.is_empty() {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check ownership proof
        if identity_data.ownership_proof.is_empty() {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check identity type
        let valid_types = ["human", "organization", "device", "service", "revoked"];
        if !valid_types.contains(&identity_data.identity_type.as_str()) {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check fees
        if identity_data.registration_fee == 0 {
            return Err(ValidationError::InvalidFee);
        }

        Ok(())
    }
}

impl Default for TransactionValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate minimum fee based on transaction size
fn calculate_minimum_fee(transaction_size: usize) -> u64 {
    // Base fee + size-based fee (from creation module)
    crate::transaction::creation::utils::calculate_minimum_fee(transaction_size)
}

/// Constants for validation
const MAX_TRANSACTION_SIZE: usize = 1_048_576; // 1 MB
const MAX_MEMO_SIZE: usize = 1024; // 1 KB

/// Validation utility functions
pub mod utils {
    use super::*;

    /// Quick validation for transaction basic structure
    pub fn quick_validate(transaction: &Transaction) -> bool {
        let validator = TransactionValidator::new();
        validator.validate_basic_structure(transaction).is_ok()
    }

    /// Validate transaction type consistency
    pub fn validate_type_consistency(transaction: &Transaction) -> bool {
        match transaction.transaction_type {
            TransactionType::IdentityRegistration | 
            TransactionType::IdentityUpdate | 
            TransactionType::IdentityRevocation => transaction.identity_data.is_some(),
            TransactionType::Transfer | 
            TransactionType::ContractDeployment | 
            TransactionType::ContractExecution => {
                !transaction.inputs.is_empty() && !transaction.outputs.is_empty()
            }
        }
    }

    /// Check if transaction has valid zero-knowledge structure
    pub fn has_valid_zk_structure(transaction: &Transaction) -> bool {
        // All inputs must have nullifiers and ZK proofs
        transaction.inputs.iter().all(|input| {
            input.nullifier != Hash::default() && 
            is_valid_proof_structure(&input.zk_proof)
        })
    }

    /// Validate transaction against current mempool rules
    pub fn validate_mempool_rules(transaction: &Transaction) -> ValidationResult {
        // Check transaction size
        if transaction.size() > MAX_TRANSACTION_SIZE {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check fee rate
        let fee_rate = transaction.fee as f64 / transaction.size() as f64;
        if fee_rate < 1.0 {
            return Err(ValidationError::InvalidFee);
        }

        Ok(())
    }
}
