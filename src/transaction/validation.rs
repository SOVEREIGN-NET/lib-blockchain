//! Transaction validation logic
//!
//! Provides comprehensive validation for ZHTP blockchain transactions.

use crate::transaction::core::{Transaction, TransactionInput, TransactionOutput, IdentityTransactionData};
use crate::types::{Hash, transaction_type::TransactionType};
use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
use crate::integration::zk_integration::{verify_transaction_proof, is_valid_proof_structure};

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
    UnregisteredSender,
    InvalidMemo,
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
            ValidationError::UnregisteredSender => write!(f, "Transaction from unregistered sender identity"),
            ValidationError::InvalidMemo => write!(f, "Invalid or missing transaction memo"),
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

/// Transaction validator with blockchain state access for identity verification
pub struct StatefulTransactionValidator<'a> {
    /// Reference to blockchain state for identity verification
    blockchain: Option<&'a crate::blockchain::Blockchain>,
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
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
            TransactionType::UbiDistribution => {
                // UBI distribution is a token transaction - validate with proper token logic
                self.validate_token_transaction(transaction)?;
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
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

    /// Validate a transaction with explicit system transaction flag
    pub fn validate_transaction_with_system_flag(&self, transaction: &Transaction, is_system_transaction: bool) -> ValidationResult {
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
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
            TransactionType::UbiDistribution => {
                // UBI distribution is a token transaction - validate with proper token logic
                self.validate_token_transaction(transaction)?;
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
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

        // Check if this is a system transaction (empty inputs)
        let is_system_transaction = transaction.inputs.is_empty();
        
        self.validate_identity_data(identity_data, is_system_transaction)?;

        // Identity transactions should have minimal inputs/outputs
        // The main logic is handled by lib-identity package
        
        Ok(())
    }

    /// Validate contract transaction
    fn validate_contract_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Contract validation is handled by lib-contracts package
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
        // Token validation is handled by lib-economy package
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

    /// Validate transaction signature using proper cryptographic verification
    fn validate_signature(&self, transaction: &Transaction) -> ValidationResult {
        use lib_crypto::verification::verify_signature;
        
        // Create transaction hash for verification (without signature)
        let mut tx_for_verification = transaction.clone();
        tx_for_verification.signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(Vec::new()),
            algorithm: transaction.signature.algorithm.clone(), // Use the same algorithm as the actual signature
            timestamp: 0,
        };
        
        let tx_hash = tx_for_verification.hash();
        
        // Get signature data
        let signature_bytes = &transaction.signature.signature;
        let public_key_bytes = transaction.signature.public_key.as_bytes();
        
        if signature_bytes.is_empty() {
            return Err(ValidationError::InvalidSignature);
        }
        
        if public_key_bytes.is_empty() {
            return Err(ValidationError::InvalidSignature);
        }
        
        // Use lib-crypto for signature verification
        match verify_signature(tx_hash.as_bytes(), signature_bytes, &public_key_bytes) {
            Ok(is_valid) => {
                if !is_valid {
                    return Err(ValidationError::InvalidSignature);
                }
            },
            Err(_) => {
                return Err(ValidationError::InvalidSignature);
            }
        }
        
        // Verify signature algorithm is supported
        match transaction.signature.algorithm {
            SignatureAlgorithm::Dilithium2 | 
            SignatureAlgorithm::Dilithium5 => {
                // Supported algorithms
            },
            _ => {
                return Err(ValidationError::InvalidSignature);
            }
        }
        
        // Verify signature timestamp is reasonable (not too old or in future)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let signature_time = transaction.signature.timestamp;
        
        // Allow signatures up to 1 hour old and 5 minutes in future
        const MAX_SIGNATURE_AGE: u64 = 3600; // 1 hour
        const MAX_FUTURE_TIME: u64 = 300;    // 5 minutes
        
        if signature_time + MAX_SIGNATURE_AGE < current_time {
            return Err(ValidationError::InvalidSignature);
        }
        
        if signature_time > current_time + MAX_FUTURE_TIME {
            return Err(ValidationError::InvalidSignature);
        }

        Ok(())
    }

    /// Validate zero-knowledge proofs for all inputs using real ZK verification
    fn validate_zk_proofs(&self, transaction: &Transaction) -> ValidationResult {
        use lib_proofs::ZkTransactionProof;
        
        println!("🚨 DEBUG: Starting ZK proof validation for {} transaction inputs", transaction.inputs.len());
        log::info!("🔍 Starting ZK proof validation for {} transaction inputs", transaction.inputs.len());
        
        for (i, input) in transaction.inputs.iter().enumerate() {
            println!("🚨 DEBUG: Validating ZK proof for input {}", i);
            log::info!("🔍 Validating ZK proof for input {}", i);
            
            // First check if the proof structure is valid
            if !is_valid_proof_structure(&input.zk_proof) {
                println!("🚨 DEBUG: Input {}: Invalid proof structure", i);
                log::error!("❌ Input {}: Invalid proof structure", i);
                return Err(ValidationError::InvalidZkProof);
            }
            println!("🚨 DEBUG: Input {}: Proof structure valid", i);
            log::info!("✅ Input {}: Proof structure valid", i);
            
            // Use the proper ZK verification from lib-proofs
            match ZkTransactionProof::verify_transaction(&input.zk_proof) {
                Ok(is_valid) => {
                    if !is_valid {
                        log::error!("❌ Input {}: ZkTransactionProof verification failed", i);
                        return Err(ValidationError::InvalidZkProof);
                    }
                    log::info!("✅ Input {}: ZkTransactionProof verification passed", i);
                },
                Err(e) => {
                    log::error!("❌ Input {}: ZK verification failed - NO FALLBACKS ALLOWED: {:?}", i, e);
                    return Err(ValidationError::InvalidZkProof);
                }
            }
            
            // Additional ZK proof validations
            log::info!("🔍 Input {}: Validating nullifier proof", i);
            self.validate_nullifier_proof(input)?;
            log::info!("✅ Input {}: Nullifier proof valid", i);
            
            log::info!("🔍 Input {}: Validating amount range proof", i);
            self.validate_amount_range_proof(input)?;
            log::info!("✅ Input {}: Amount range proof valid", i);
        }

        log::info!("✅ All ZK proofs validated successfully");
        Ok(())
    }
    
    /// Validate nullifier proof to prevent double spending
    fn validate_nullifier_proof(&self, input: &TransactionInput) -> ValidationResult {
        // Verify that the nullifier proof is cryptographically sound
        if let Some(plonky2_proof) = &input.zk_proof.nullifier_proof.plonky2_proof {
            // Use real Plonky2 verification if available
            if let Ok(zk_system) = lib_proofs::ZkProofSystem::new() {
                match zk_system.verify_range(plonky2_proof) {
                    Ok(is_valid) => {
                        if !is_valid {
                            return Err(ValidationError::InvalidZkProof);
                        }
                    },
                    Err(e) => {
                        // NO FALLBACKS - fail hard if ZK verification fails
                        log::error!("❌ Nullifier ZK verification failed - no fallbacks allowed: {:?}", e);
                        return Err(ValidationError::InvalidZkProof);
                    }
                }
            }
        } else {
            // NO FALLBACKS - require Plonky2 proofs only
            log::error!("❌ Nullifier proof missing Plonky2 verification - no fallbacks allowed");
            return Err(ValidationError::InvalidZkProof);
        }
        
        Ok(())
    }
    
    /// Validate amount range proof to ensure positive amounts
    fn validate_amount_range_proof(&self, input: &TransactionInput) -> ValidationResult {
        println!("🚨 DEBUG: validate_amount_range_proof starting");
        log::info!("🔍 validate_amount_range_proof starting");
        
        // Verify that the amount is within valid range (positive, not exceeding max supply)
        if let Some(plonky2_proof) = &input.zk_proof.amount_proof.plonky2_proof {
            println!("🚨 DEBUG: Found Plonky2 amount proof for range validation");
            println!("🚨 DEBUG: Amount proof system: '{}'", plonky2_proof.proof_system);
            log::info!("✅ Found Plonky2 amount proof for range validation");
            log::info!("🔍 Amount proof system: '{}'", plonky2_proof.proof_system);
            
            // Use real Plonky2 verification if available
            if let Ok(zk_system) = lib_proofs::ZkProofSystem::new() {
                println!("🚨 DEBUG: ZkProofSystem initialized for range validation");
                log::info!("✅ ZkProofSystem initialized for range validation");
                
                // Check if this is a transaction proof or range proof and use appropriate verification
                match plonky2_proof.proof_system.as_str() {
                    "ZHTP-Optimized-Range" => {
                        println!("🚨 DEBUG: Using verify_range for range proof");
                        log::info!("🔍 Using verify_range for range proof");
                        
                        match zk_system.verify_range(plonky2_proof) {
                            Ok(is_valid) => {
                                println!("🚨 DEBUG: Range verification result: {}", is_valid);
                                log::info!("🔍 Range verification result: {}", is_valid);
                                
                                if !is_valid {
                                    println!("🚨 DEBUG: Range proof INVALID - returning error");
                                    log::error!("❌ Range proof INVALID - returning error");
                                    return Err(ValidationError::InvalidZkProof);
                                } else {
                                    println!("🚨 DEBUG: Range proof VALID");
                                    log::info!("✅ Range proof VALID");
                                }
                            },
                            Err(e) => {
                                println!("🚨 DEBUG: Range verification error: {:?}", e);
                                log::error!("❌ Range verification error: {:?}", e);
                                return Err(ValidationError::InvalidZkProof);
                            }
                        }
                    },
                    "ZHTP-Optimized-Transaction" | "Plonky2" => {
                        println!("🚨 DEBUG: Using verify_transaction for transaction proof");
                        log::info!("🔍 Using verify_transaction for transaction proof");
                        
                        match zk_system.verify_transaction(plonky2_proof) {
                            Ok(is_valid) => {
                                println!("🚨 DEBUG: Transaction verification result: {}", is_valid);
                                log::info!("🔍 Transaction verification result: {}", is_valid);
                                
                                if !is_valid {
                                    println!("🚨 DEBUG: Transaction proof INVALID - returning error");
                                    log::error!("❌ Transaction proof INVALID - returning error");
                                    return Err(ValidationError::InvalidZkProof);
                                } else {
                                    println!("🚨 DEBUG: Transaction proof VALID");
                                    log::info!("✅ Transaction proof VALID");
                                }
                            },
                            Err(e) => {
                                println!("🚨 DEBUG: Transaction verification error: {:?}", e);
                                log::error!("❌ Transaction verification error: {:?}", e);
                                return Err(ValidationError::InvalidZkProof);
                            }
                        }
                    },
                    _ => {
                        println!("🚨 DEBUG: Unknown proof system: '{}'", plonky2_proof.proof_system);
                        log::error!("❌ Unknown proof system: '{}'", plonky2_proof.proof_system);
                        return Err(ValidationError::InvalidZkProof);
                    }
                }
            } else {
                println!("🚨 DEBUG: Failed to initialize ZkProofSystem");
                log::error!("❌ Failed to initialize ZkProofSystem");
                return Err(ValidationError::InvalidZkProof);
            }
        } else {
            println!("🚨 DEBUG: No Plonky2 proof found - NO FALLBACKS ALLOWED");
            log::error!("❌ Amount proof missing Plonky2 verification - no fallbacks allowed");
            return Err(ValidationError::InvalidZkProof);
        }
        
        println!("🚨 DEBUG: validate_amount_range_proof completed successfully");
        log::info!("✅ validate_amount_range_proof completed successfully");
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
        println!("🔍 FEE VALIDATION DEBUG:");
        println!("   Transaction size: {} bytes", transaction.size());
        println!("   Calculated minimum fee: {} ZHTP", min_fee);
        println!("   Actual transaction fee: {} ZHTP", transaction.fee);
        if transaction.fee < min_fee {
            println!("❌ FEE VALIDATION FAILED: {} < {}", transaction.fee, min_fee);
            return Err(ValidationError::InvalidFee);
        }
        println!("✅ FEE VALIDATION PASSED");

        // Economic validation is handled by lib-economy package
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
        if output.recipient.dilithium_pk.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate identity transaction data
    fn validate_identity_data(&self, identity_data: &IdentityTransactionData, is_system_transaction: bool) -> ValidationResult {
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
        let valid_types = ["human", "organization", "device", "service", "validator", "revoked"];
        if !valid_types.contains(&identity_data.identity_type.as_str()) {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check fees - allow zero fees for system transactions
        if !is_system_transaction && identity_data.registration_fee == 0 {
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

impl<'a> StatefulTransactionValidator<'a> {
    /// Create a new stateful transaction validator with blockchain access
    pub fn new(blockchain: &'a crate::blockchain::Blockchain) -> Self {
        Self { 
            blockchain: Some(blockchain)
        }
    }

    /// Create a stateless validator (no identity verification)
    pub fn stateless() -> Self {
        Self {
            blockchain: None,
        }
    }

    /// Validate a transaction with full state context including identity verification
    pub fn validate_transaction_with_state(&self, transaction: &Transaction) -> ValidationResult {
        // Check if this is a system transaction (empty inputs = coinbase-style)
        let is_system_transaction = transaction.inputs.is_empty();

        // Create a stateless validator for basic checks
        let stateless_validator = TransactionValidator::new();

        // Basic structure validation
        stateless_validator.validate_basic_structure(transaction)?;

        // Type-specific validation
        match transaction.transaction_type {
            TransactionType::Transfer => {
                if !is_system_transaction {
                    stateless_validator.validate_transfer_transaction(transaction)?;
                }
                // System transactions with Transfer type are allowed (UBI/rewards)
            },
            TransactionType::IdentityRegistration => stateless_validator.validate_identity_transaction(transaction)?,
            TransactionType::IdentityUpdate => stateless_validator.validate_identity_transaction(transaction)?,
            TransactionType::IdentityRevocation => stateless_validator.validate_identity_transaction(transaction)?,
            TransactionType::ContractDeployment => stateless_validator.validate_contract_transaction(transaction)?,
            TransactionType::ContractExecution => stateless_validator.validate_contract_transaction(transaction)?,
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload | TransactionType::UbiDistribution => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
        }

        // 🔥 CRITICAL FIX: Verify sender identity exists on blockchain
        // This is the missing check that was allowing transactions from non-existent identities
        if !is_system_transaction && transaction.transaction_type != TransactionType::IdentityRegistration {
            self.validate_sender_identity_exists(transaction)?;
        }

        // Signature validation (always required)
        stateless_validator.validate_signature(transaction)?;

        // Zero-knowledge proof validation (skip for system transactions)
        if !is_system_transaction {
            stateless_validator.validate_zk_proofs(transaction)?;
        }

        // Economic validation (modified for system transactions)
        stateless_validator.validate_economics_with_system_check(transaction, is_system_transaction)?;

        Ok(())
    }

    /// CRITICAL FIX: Verify that the sender's identity exists on the blockchain
    /// This prevents transactions from non-existent or unregistered identities
    fn validate_sender_identity_exists(&self, transaction: &Transaction) -> ValidationResult {
        // If we don't have blockchain access, skip this check (backward compatibility)
        let blockchain = match self.blockchain {
            Some(blockchain) => blockchain,
            None => {
                tracing::warn!("⚠️ SECURITY WARNING: Identity verification skipped - no blockchain state available");
                return Ok(());
            }
        };

        // Extract the public key from the transaction signature
        let sender_public_key = transaction.signature.public_key.as_bytes();
        
        if sender_public_key.is_empty() {
            tracing::error!("❌ SECURITY: Transaction has empty public key");
            return Err(ValidationError::InvalidSignature);
        }

        // Search through all registered identities to find one with matching public key
        let mut identity_found = false;
        for (did, identity_data) in blockchain.get_all_identities() {
            if identity_data.public_key == sender_public_key {
                // Check if identity is not revoked
                if identity_data.identity_type == "revoked" {
                    tracing::error!("❌ SECURITY: Transaction from revoked identity: {}", did);
                    return Err(ValidationError::InvalidTransaction);
                }
                
                tracing::info!("✅ SECURITY: Sender identity verified: {} ({})", 
                    identity_data.display_name, did);
                identity_found = true;
                break;
            }
        }

        if !identity_found {
            tracing::error!("❌ SECURITY CRITICAL: Transaction from unregistered identity!");
            tracing::error!("❌ Public key: {:02x?}", sender_public_key);
            tracing::error!("❌ This transaction should be REJECTED - sender identity does not exist on blockchain");
            
            // Log all registered identities for debugging
            tracing::info!("🔍 DEBUG: Currently registered identities:");
            for (did, identity_data) in blockchain.get_all_identities() {
                tracing::info!("   - {} ({}): {:02x?}", 
                    identity_data.display_name, 
                    did, 
                    &identity_data.public_key[..std::cmp::min(16, identity_data.public_key.len())]);
            }
            
            return Err(ValidationError::UnregisteredSender);
        }

        Ok(())
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
            },
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload | TransactionType::UbiDistribution => {
                // Audit transactions should have memo data but no strict input/output requirements
                !transaction.memo.is_empty()
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
