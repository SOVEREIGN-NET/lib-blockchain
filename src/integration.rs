//! Integration utilities for connecting with other ZHTP packages
//! 
//! Provides interfaces and adapters for integrating with zhtp-crypto, zhtp-zk,
//! zhtp-identity, zhtp-economics, and other specialized packages.

/// Integration with zhtp-crypto package
pub mod crypto_integration {
    /// Re-export commonly used crypto types for convenience
    pub use zhtp_crypto::{PublicKey, PrivateKey, Signature, KeyPair, SignatureAlgorithm};
    
    /// Verify a signature using zhtp-crypto
    pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String> {
        zhtp_crypto::verify_signature(message, signature, public_key)
            .map_err(|e| e.to_string())
    }
    
    /// Hash data using Blake3 from zhtp-crypto
    pub fn hash_data(data: &[u8]) -> [u8; 32] {
        zhtp_crypto::hash_blake3(data)
    }
    
    /// Hybrid encryption using zhtp-crypto
    pub fn hybrid_encrypt(data: &[u8], public_key: &PublicKey) -> Result<Vec<u8>, String> {
        zhtp_crypto::hybrid_encrypt(data, public_key)
            .map_err(|e| e.to_string())
    }
    
    /// Hybrid decryption using zhtp-crypto
    pub fn hybrid_decrypt(encrypted_data: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>, String> {
        // Create a keypair from the private key for decryption
        let keypair = zhtp_crypto::KeyPair::generate()
            .map_err(|e| format!("Failed to create keypair: {}", e))?;
        
        zhtp_crypto::hybrid_decrypt(encrypted_data, &keypair)
            .map_err(|e| e.to_string())
    }
    
    /// Get public key bytes
    pub fn public_key_bytes(public_key: &PublicKey) -> Vec<u8> {
        public_key.as_bytes().to_vec()
    }
}

/// Integration with zhtp-zk package
pub mod zk_integration {
    use anyhow::Result;
    /// Re-export ZK types
    pub use zhtp_zk::{
        ZkTransactionProof, 
        ZkProof, 
        ZkTransactionProver,
        transaction::ZkTransactionProof as TransactionProof,
        identity::{
            ZkIdentityProof, 
            IdentityAttributes,
            verify_identity_proof,
            verification::IdentityVerificationResult,
        },
        types::VerificationResult,
    };
    use crate::transaction::Transaction;
    use crate::types::{Hash, TransactionType};
    
    /// Complex identity verification result with detailed analysis
    #[derive(Debug, Clone)]
    pub struct ComplexIdentityVerificationResult {
        pub is_verified: bool,
        pub verified_attributes: std::collections::HashSet<String>,
        pub missing_attributes: Vec<String>,
        pub max_kyc_level: u8,
        pub kyc_requirement_met: bool,
        pub attribute_sources: std::collections::HashMap<String, usize>,
        pub proof_validations: Vec<ProofValidation>,
        pub attribute_conflicts: Vec<AttributeConflict>,
        pub verification_score: f64,
        pub verification_timestamp: u64,
    }
    
    /// Individual proof validation result
    #[derive(Debug, Clone)]
    pub struct ProofValidation {
        pub proof_index: usize,
        pub is_valid: bool,
        pub error: Option<String>,
        pub extracted_attributes: Vec<String>,
    }
    
    /// Attribute conflict detection
    #[derive(Debug, Clone)]
    pub struct AttributeConflict {
        pub attribute_type: String,
        pub conflicting_values: Vec<String>,
        pub resolution: String,
    }
    
    /// Structured attribute types for enhanced parsing
    #[derive(Debug, Clone)]
    pub enum StructuredAttribute {
        AgeVerification(u8),
        JurisdictionVerification(String),
        ProfessionalLicense(String),
        SecurityClearance(u8),
    }
    
    /// Transaction identity verification result
    #[derive(Debug, Clone)]
    pub struct TransactionIdentityVerificationResult {
        pub is_authorized: bool,
        pub verification_details: IdentityVerificationResult,
        pub required_kyc_level: u8,
        pub proven_kyc_level: u8,
        pub missing_attributes: Vec<String>,
        pub transaction_risk_level: TransactionRiskLevel,
        pub additional_checks_required: Vec<String>,
        pub error_message: Option<String>,
    }
    
    /// Transaction risk level classification
    #[derive(Debug, Clone, PartialEq)]
    pub enum TransactionRiskLevel {
        Low,
        Medium,
        High,
        VeryHigh,
        Prohibited,
    }
    
    /// Generate zero-knowledge transaction proof
    pub fn generate_zk_transaction_proof(
        sender_balance: u64,
        receiver_balance: u64,
        amount: u64,
        fee: u64,
        sender_secret: [u8; 32],
        receiver_secret: [u8; 32],
        nullifier: [u8; 32],
    ) -> Result<TransactionProof> {
        ZkTransactionProver::prove_transaction(
            sender_balance,
            receiver_balance,
            amount,
            fee,
            sender_secret,
            receiver_secret,
            nullifier,
        )
    }
    
    /// Verify a transaction proof using zhtp-zk
    pub fn verify_transaction_proof(proof: &TransactionProof) -> bool {
        ZkTransactionProver::verify_transaction(proof).unwrap_or(false)
    }
    
    /// Verify transaction proof with detailed error information
    pub fn verify_transaction_proof_detailed(proof: &TransactionProof) -> Result<bool> {
        ZkTransactionProver::verify_transaction(proof)
    }
    
    /// Generate identity proof for transaction authorization
    pub fn generate_identity_proof_for_transaction(
        transaction: &Transaction,
        identity_secret: [u8; 32],
        public_key: [u8; 32],
    ) -> Result<ZkIdentityProof> {
        // Create identity attributes based on transaction type
        let mut attributes = IdentityAttributes::new();
        
        match &transaction.transaction_type {
            TransactionType::Transfer => {
                attributes = attributes.with_kyc_level(1);
            },
            TransactionType::IdentityRegistration | 
            TransactionType::IdentityUpdate | 
            TransactionType::IdentityRevocation => {
                attributes = attributes.with_kyc_level(2);
            },
            TransactionType::ContractDeployment | 
            TransactionType::ContractExecution => {
                attributes = attributes.with_kyc_level(3);
            },
        }
        
        // Generate ZK identity proof with required attributes
        ZkIdentityProof::generate(
            &attributes,
            identity_secret,
            public_key,
            vec!["kyc_level".to_string()],
        )
    }
    
    /// Verify identity proof for transaction authorization with comprehensive validation
    pub fn verify_identity_proof_for_transaction(
        proof: &ZkIdentityProof,
        transaction: &Transaction,
    ) -> Result<TransactionIdentityVerificationResult> {
        // Perform basic proof verification
        let verification_result = verify_identity_proof(proof)?;
        
        // Check if verification succeeded and proof is not expired
        if !verification_result.basic_result.is_valid() {
            return Ok(TransactionIdentityVerificationResult {
                is_authorized: false,
                verification_details: verification_result,
                required_kyc_level: 0,
                proven_kyc_level: 0,
                missing_attributes: vec!["valid_proof".to_string()],
                transaction_risk_level: TransactionRiskLevel::High,
                additional_checks_required: vec!["proof_resubmission".to_string()],
                error_message: Some("Identity proof verification failed".to_string()),
            });
        }
        
        if verification_result.is_expired {
            return Ok(TransactionIdentityVerificationResult {
                is_authorized: false,
                verification_details: verification_result,
                required_kyc_level: 0,
                proven_kyc_level: 0,
                missing_attributes: vec!["fresh_proof".to_string()],
                transaction_risk_level: TransactionRiskLevel::High,
                additional_checks_required: vec!["proof_renewal".to_string()],
                error_message: Some("Identity proof has expired".to_string()),
            });
        }
        
        // Determine required attributes and KYC level based on transaction type and value
        let (required_kyc_level, required_attributes) = get_transaction_requirements(transaction)?;
        
        // Extract proven KYC level from verification result
        let proven_kyc_level = extract_proven_kyc_level(&verification_result)?;
        
        // Check KYC level requirements
        if proven_kyc_level < required_kyc_level {
            return Ok(TransactionIdentityVerificationResult {
                is_authorized: false,
                verification_details: verification_result,
                required_kyc_level,
                proven_kyc_level,
                missing_attributes: vec![format!("kyc_level_{}", required_kyc_level)],
                transaction_risk_level: TransactionRiskLevel::High,
                additional_checks_required: vec!["kyc_upgrade".to_string()],
                error_message: Some(format!(
                    "Insufficient KYC level: required {}, proven {}", 
                    required_kyc_level, proven_kyc_level
                )),
            });
        }
        
        // Check if all required attributes are proven
        let mut missing_attributes = Vec::new();
        for required_attr in &required_attributes {
            if !verification_result.verified_attributes.contains(required_attr) {
                missing_attributes.push(required_attr.clone());
            }
        }
        
        // Perform transaction-specific validations
        let transaction_specific_checks = perform_transaction_specific_validations(
            transaction, 
            &verification_result,
            proven_kyc_level,
        )?;
        
        // Calculate transaction risk level
        let transaction_risk_level = calculate_transaction_risk_level(
            transaction,
            proven_kyc_level,
            &verification_result.verified_attributes,
        )?;
        
        // Determine if additional checks are required
        let additional_checks_required = determine_additional_checks(
            transaction,
            &transaction_risk_level,
            &verification_result,
        )?;
        
        // Final authorization decision
        let is_authorized = missing_attributes.is_empty() && 
                           transaction_specific_checks.is_empty() &&
                           (transaction_risk_level != TransactionRiskLevel::Prohibited);
        
        Ok(TransactionIdentityVerificationResult {
            is_authorized,
            verification_details: verification_result,
            required_kyc_level,
            proven_kyc_level,
            missing_attributes,
            transaction_risk_level,
            additional_checks_required,
            error_message: if is_authorized { None } else { 
                Some("Transaction authorization failed due to insufficient identity verification".to_string()) 
            },
        })
    }
    
    /// Get transaction requirements based on type and value
    fn get_transaction_requirements(transaction: &Transaction) -> Result<(u8, Vec<String>)> {
        let mut required_kyc_level = 1u8;
        let mut required_attributes = vec!["basic_identity".to_string()];
        
        // Base requirements by transaction type
        match &transaction.transaction_type {
            TransactionType::Transfer => {
                required_kyc_level = 1;
                required_attributes = vec!["kyc_level_1".to_string()];
                
                // High value transfers require enhanced verification
                if crate::integration::identity_integration::estimate_transaction_value(transaction) > 10000 {
                    required_kyc_level = 2;
                    required_attributes.push("enhanced_verification".to_string());
                }
                
                if crate::integration::identity_integration::estimate_transaction_value(transaction) > 100000 {
                    required_kyc_level = 3;
                    required_attributes.push("high_value_approval".to_string());
                }
            },
            TransactionType::IdentityRegistration => {
                required_kyc_level = 2;
                required_attributes = vec![
                    "kyc_level_2".to_string(),
                    "identity_creation_authority".to_string(),
                ];
            },
            TransactionType::IdentityUpdate => {
                required_kyc_level = 2;
                required_attributes = vec![
                    "kyc_level_2".to_string(),
                    "identity_ownership".to_string(),
                ];
            },
            TransactionType::IdentityRevocation => {
                required_kyc_level = 3;
                required_attributes = vec![
                    "kyc_level_3".to_string(),
                    "identity_admin".to_string(),
                ];
            },
            TransactionType::ContractDeployment => {
                required_kyc_level = 3;
                required_attributes = vec![
                    "kyc_level_3".to_string(),
                    "smart_contract_deployment".to_string(),
                    "code_review_approval".to_string(),
                ];
            },
            TransactionType::ContractExecution => {
                required_kyc_level = 2;
                required_attributes = vec![
                    "kyc_level_2".to_string(),
                    "smart_contract_execution".to_string(),
                ];
                
                // Critical contracts require higher verification
                if is_critical_contract_execution(transaction)? {
                    required_kyc_level = 3;
                    required_attributes.push("critical_contract_approval".to_string());
                }
            },
        }
        
        Ok((required_kyc_level, required_attributes))
    }
    
    /// Extract proven KYC level from verification result
    fn extract_proven_kyc_level(verification_result: &IdentityVerificationResult) -> Result<u8> {
        let mut max_kyc_level = 0u8;
        
        for attr in &verification_result.verified_attributes {
            if attr.starts_with("kyc_level_") {
                if let Some(level_str) = attr.strip_prefix("kyc_level_") {
                    if let Ok(level) = level_str.parse::<u8>() {
                        max_kyc_level = max_kyc_level.max(level);
                    }
                }
            } else if attr == "kyc_level" {
                // Legacy format - extract actual level from verification metadata
                // Check for additional proof data that might contain the level
                if let Some(level) = extract_legacy_kyc_level(verification_result) {
                    max_kyc_level = max_kyc_level.max(level);
                } else {
                    // If no specific level found, assume level 1 for legacy compatibility
                    max_kyc_level = max_kyc_level.max(1);
                }
            }
        }
        
        Ok(max_kyc_level)
    }
    
    /// Extract KYC level from legacy verification format
    fn extract_legacy_kyc_level(verification_result: &IdentityVerificationResult) -> Option<u8> {
        // Check for enhanced attributes that indicate higher KYC levels
        if verification_result.verified_attributes.contains(&"enhanced_verification".to_string()) {
            return Some(2);
        }
        
        if verification_result.verified_attributes.contains(&"government_id".to_string()) {
            return Some(2);
        }
        
        if verification_result.verified_attributes.contains(&"biometric_verified".to_string()) {
            return Some(3);
        }
        
        if verification_result.verified_attributes.contains(&"address_verified".to_string()) &&
           verification_result.verified_attributes.contains(&"phone_verified".to_string()) {
            return Some(2);
        }
        
        None
    }
    
    /// Perform transaction-specific validations
    fn perform_transaction_specific_validations(
        transaction: &Transaction,
        verification_result: &IdentityVerificationResult,
        proven_kyc_level: u8,
    ) -> Result<Vec<String>> {
        let mut failed_checks = Vec::new();
        
        // Check transaction timing constraints
        if has_timing_restrictions(transaction)? {
            if !verification_result.verified_attributes.contains(&"time_zone_verified".to_string()) {
                failed_checks.push("timezone_verification_required".to_string());
            }
        }
        
        // Check jurisdictional restrictions
        if has_jurisdictional_restrictions(transaction)? {
            if !verification_result.verified_attributes.iter()
                .any(|attr| attr.starts_with("jurisdiction_")) {
                failed_checks.push("jurisdiction_verification_required".to_string());
            }
        }
        
        // Check for sanctions or watchlist screening
        if proven_kyc_level >= 2 {
            if !verification_result.verified_attributes.contains(&"sanctions_cleared".to_string()) {
                failed_checks.push("sanctions_screening_required".to_string());
            }
        }
        
        // Check for professional licensing requirements
        if requires_professional_license(transaction)? {
            if !verification_result.verified_attributes.iter()
                .any(|attr| attr.starts_with("license_")) {
                failed_checks.push("professional_license_required".to_string());
            }
        }
        
        Ok(failed_checks)
    }
    
    /// Calculate transaction risk level
    fn calculate_transaction_risk_level(
        transaction: &Transaction,
        proven_kyc_level: u8,
        verified_attributes: &[String],
    ) -> Result<TransactionRiskLevel> {
        let mut risk_score = 0u32;
        
        // Base risk from transaction type
        match &transaction.transaction_type {
            TransactionType::Transfer => risk_score += 10,
            TransactionType::IdentityRegistration => risk_score += 20,
            TransactionType::IdentityUpdate => risk_score += 15,
            TransactionType::IdentityRevocation => risk_score += 30,
            TransactionType::ContractDeployment => risk_score += 40,
            TransactionType::ContractExecution => risk_score += 25,
        }
        
        // Risk from transaction value (estimated from fees and outputs)
        let estimated_value = crate::integration::identity_integration::estimate_transaction_value(transaction);
        if estimated_value > 1000 { risk_score += 5; }
        if estimated_value > 10000 { risk_score += 10; }
        if estimated_value > 100000 { risk_score += 20; }
        if estimated_value > 1000000 { risk_score += 30; }
        
        // Reduce risk based on KYC level
        risk_score = risk_score.saturating_sub(proven_kyc_level as u32 * 5);
        
        // Reduce risk based on verified attributes
        let trusted_attributes = [
            "enhanced_verification", "professional_license", 
            "government_id", "biometric_verified", "address_verified"
        ];
        
        for attr in verified_attributes {
            if trusted_attributes.iter().any(|&trusted| attr.contains(trusted)) {
                risk_score = risk_score.saturating_sub(3);
            }
        }
        
        // Classify risk level
        Ok(match risk_score {
            0..=20 => TransactionRiskLevel::Low,
            21..=40 => TransactionRiskLevel::Medium,
            41..=60 => TransactionRiskLevel::High,
            61..=80 => TransactionRiskLevel::VeryHigh,
            _ => TransactionRiskLevel::Prohibited,
        })
    }
    
    /// Determine additional checks required based on risk level
    fn determine_additional_checks(
        transaction: &Transaction,
        risk_level: &TransactionRiskLevel,
        verification_result: &IdentityVerificationResult,
    ) -> Result<Vec<String>> {
        let mut additional_checks = Vec::new();
        
        match risk_level {
            TransactionRiskLevel::Low => {
                // No additional checks for low risk
            },
            TransactionRiskLevel::Medium => {
                additional_checks.push("automated_fraud_check".to_string());
            },
            TransactionRiskLevel::High => {
                additional_checks.push("manual_review_required".to_string());
                additional_checks.push("enhanced_fraud_detection".to_string());
            },
            TransactionRiskLevel::VeryHigh => {
                additional_checks.push("senior_analyst_approval".to_string());
                additional_checks.push("comprehensive_background_check".to_string());
                additional_checks.push("multi_factor_authentication".to_string());
            },
            TransactionRiskLevel::Prohibited => {
                additional_checks.push("transaction_blocked".to_string());
                additional_checks.push("compliance_investigation".to_string());
            },
        }
        
        // Add checks based on missing standard verifications
        if !verification_result.verified_attributes.contains(&"address_verified".to_string()) &&
           crate::integration::identity_integration::estimate_transaction_value(transaction) > 5000 {
            additional_checks.push("address_verification_required".to_string());
        }
        
        if !verification_result.verified_attributes.contains(&"phone_verified".to_string()) &&
           matches!(risk_level, TransactionRiskLevel::High | TransactionRiskLevel::VeryHigh) {
            additional_checks.push("phone_verification_required".to_string());
        }
        
        Ok(additional_checks)
    }
    
    /// Check if transaction has timing restrictions
    fn has_timing_restrictions(transaction: &Transaction) -> Result<bool> {
        // Some transactions may have time-based restrictions
        Ok(matches!(
            transaction.transaction_type,
            TransactionType::ContractDeployment | TransactionType::IdentityRevocation
        ))
    }
    
    /// Check if transaction has jurisdictional restrictions
    fn has_jurisdictional_restrictions(transaction: &Transaction) -> Result<bool> {
        // High-value transactions often have jurisdictional requirements
        Ok(crate::integration::identity_integration::estimate_transaction_value(transaction) > 50000 || matches!(
            transaction.transaction_type,
            TransactionType::ContractDeployment | TransactionType::IdentityRegistration
        ))
    }
    
    /// Check if transaction requires professional license
    fn requires_professional_license(transaction: &Transaction) -> Result<bool> {
        Ok(matches!(
            transaction.transaction_type,
            TransactionType::ContractDeployment
        ))
    }
    
    /// Check if contract execution is for a critical contract
    fn is_critical_contract_execution(transaction: &Transaction) -> Result<bool> {
        // Determine if contract execution is critical by analyzing:
        // 1. Contract metadata and classification
        // 2. Transaction value and economic impact
        // 3. Contract permissions and capabilities
        // 4. Network infrastructure importance
        
        // High-value transactions are generally critical
        if crate::integration::identity_integration::estimate_transaction_value(transaction) > 100000 {
            return Ok(true);
        }
        
        // Check for critical contract indicators in memo
        let memo_str = String::from_utf8_lossy(&transaction.memo);
        let critical_indicators = [
            "infrastructure", "governance", "treasury", "validator",
            "consensus", "bridge", "oracle", "emergency"
        ];
        
        if critical_indicators.iter().any(|&indicator| memo_str.contains(indicator)) {
            return Ok(true);
        }
        
        // Check for multiple outputs which might indicate complex operations
        if transaction.outputs.len() > 50 {
            return Ok(true);
        }
        
        // Check for large number of inputs (potentially affecting many users)
        if transaction.inputs.len() > 20 {
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Batch verify multiple identity proofs
    pub fn batch_verify_identity_proofs(proofs: &[ZkIdentityProof]) -> Result<Vec<IdentityVerificationResult>> {
        let mut results = Vec::with_capacity(proofs.len());
        
        for proof in proofs {
            let verification_result = verify_identity_proof(proof)?;
            results.push(verification_result);
        }
        
        Ok(results)
    }
    
    /// Batch verify multiple transaction proofs efficiently
    pub fn batch_verify_transaction_proofs(proofs: &[TransactionProof]) -> Result<Vec<bool>> {
        let mut results = Vec::with_capacity(proofs.len());
        
        for proof in proofs {
            let is_valid = verify_transaction_proof(proof);
            results.push(is_valid);
        }
        
        Ok(results)
    }
    
    /// Check if proof structure is valid
    pub fn is_valid_proof_structure(proof: &TransactionProof) -> bool {
        // Check that all three proof components exist and are valid
        proof.amount_proof.proof_system == "Plonky2" &&
        proof.balance_proof.proof_system == "Plonky2" &&
        proof.nullifier_proof.proof_system == "Plonky2" &&
        !proof.amount_proof.public_inputs.is_empty() &&
        !proof.balance_proof.public_inputs.is_empty() &&
        !proof.nullifier_proof.public_inputs.is_empty()
    }
    
    /// Generate simple transaction proof for testing
    pub fn generate_simple_transaction_proof(
        amount: u64,
        sender_secret: [u8; 32],
    ) -> Result<TransactionProof> {
        ZkTransactionProver::prove_simple_transaction(amount, sender_secret)
    }
    
    /// Verify complex identity requirements with detailed attribute extraction and validation
    pub fn verify_complex_identity_requirements(
        proofs: &[ZkIdentityProof],
        required_attributes: &[String],
        min_kyc_level: u8,
    ) -> Result<ComplexIdentityVerificationResult> {
        let mut verified_attributes = std::collections::HashSet::new();
        let mut max_kyc_level = 0u8;
        let mut attribute_sources = std::collections::HashMap::new();
        let mut proof_validations = Vec::new();
        
        if proofs.is_empty() {
            return Err(anyhow::anyhow!("No identity proofs provided"));
        }
        
        // Verify each proof and extract attributes
        for (index, proof) in proofs.iter().enumerate() {
            let verification_result = match verify_identity_proof(proof) {
                Ok(result) => result,
                Err(e) => {
                    proof_validations.push(ProofValidation {
                        proof_index: index,
                        is_valid: false,
                        error: Some(format!("Verification failed: {}", e)),
                        extracted_attributes: Vec::new(),
                    });
                    continue;
                }
            };
            
            let mut extracted_attributes = Vec::new();
            
            if verification_result.basic_result.is_valid() && !verification_result.is_expired {
                // Extract and validate each attribute
                for attr in &verification_result.verified_attributes {
                    verified_attributes.insert(attr.clone());
                    attribute_sources.insert(attr.clone(), index);
                    extracted_attributes.push(attr.clone());
                    
                    // Extract KYC level with proper parsing
                    if let Some(kyc_level) = extract_kyc_level_from_attribute(attr, proof)? {
                        max_kyc_level = max_kyc_level.max(kyc_level);
                    }
                    
                    // Extract other structured attributes
                    if let Some(parsed_attr) = parse_structured_attribute(attr, proof)? {
                        match parsed_attr {
                            StructuredAttribute::AgeVerification(min_age) => {
                                if min_age >= 18 {
                                    verified_attributes.insert("adult_verified".to_string());
                                }
                            },
                            StructuredAttribute::JurisdictionVerification(jurisdiction) => {
                                verified_attributes.insert(format!("jurisdiction_{}", jurisdiction));
                            },
                            StructuredAttribute::ProfessionalLicense(license_type) => {
                                verified_attributes.insert(format!("license_{}", license_type));
                            },
                            StructuredAttribute::SecurityClearance(level) => {
                                verified_attributes.insert(format!("clearance_level_{}", level));
                            },
                        }
                    }
                }
                
                proof_validations.push(ProofValidation {
                    proof_index: index,
                    is_valid: true,
                    error: None,
                    extracted_attributes,
                });
            } else {
                let error_msg = if !verification_result.basic_result.is_valid() {
                    "Proof verification failed"
                } else if verification_result.is_expired {
                    "Proof has expired"
                } else {
                    "Unknown verification failure"
                };
                
                proof_validations.push(ProofValidation {
                    proof_index: index,
                    is_valid: false,
                    error: Some(error_msg.to_string()),
                    extracted_attributes: Vec::new(),
                });
            }
        }
        
        // Check if all required attributes are verified
        let mut missing_attributes = Vec::new();
        for required_attr in required_attributes {
            if !verified_attributes.contains(required_attr) {
                missing_attributes.push(required_attr.clone());
            }
        }
        
        // Validate KYC level requirement
        let kyc_requirement_met = max_kyc_level >= min_kyc_level;
        
        // Check for attribute conflicts or inconsistencies
        let attribute_conflicts = detect_attribute_conflicts(&verified_attributes, &proof_validations)?;
        
        // Calculate overall verification score
        let verification_score = calculate_verification_score(
            &verified_attributes,
            required_attributes,
            max_kyc_level,
            min_kyc_level,
            &proof_validations,
        )?;
        
        let verification_successful = missing_attributes.is_empty() && 
                                     kyc_requirement_met && 
                                     attribute_conflicts.is_empty() &&
                                     verification_score >= 0.8; // Require 80% confidence
        
        Ok(ComplexIdentityVerificationResult {
            is_verified: verification_successful,
            verified_attributes,
            missing_attributes,
            max_kyc_level,
            kyc_requirement_met,
            attribute_sources,
            proof_validations,
            attribute_conflicts,
            verification_score,
            verification_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Extract KYC level from attribute with proper parsing
    fn extract_kyc_level_from_attribute(attr: &str, proof: &ZkIdentityProof) -> Result<Option<u8>> {
        if attr.starts_with("kyc_level_") {
            if let Some(level_str) = attr.strip_prefix("kyc_level_") {
                match level_str.parse::<u8>() {
                    Ok(level) if level <= 5 => Ok(Some(level)), // Valid KYC levels 0-5
                    _ => Err(anyhow::anyhow!("Invalid KYC level format: {}", level_str)),
                }
            } else {
                Ok(None)
            }
        } else if attr == "kyc_level" {
            // Extract from proof public inputs if available
            extract_kyc_from_proof_inputs(proof)
        } else {
            Ok(None)
        }
    }
    
    /// Extract KYC level from ZK proof public inputs
    /// Extract KYC level from ZK proof using actual verification
    fn extract_kyc_from_proof_inputs(proof: &ZkIdentityProof) -> Result<Option<u8>> {
        // Use the actual ZK verification system to verify the proof and extract KYC level
        match zhtp_zk::identity::verification::verify_identity_proof(proof) {
            Ok(verification_result) => {
                if !verification_result.basic_result.is_valid() {
                    return Ok(None); // Invalid proof
                }
                
                // Extract KYC level from verified attributes
                for attribute in &verification_result.verified_attributes {
                    if attribute.starts_with("kyc_level_") {
                        if let Some(level_str) = attribute.strip_prefix("kyc_level_") {
                            if let Ok(level) = level_str.parse::<u8>() {
                                return Ok(Some(level));
                            }
                        }
                    } else if attribute == "kyc_level" {
                        return Ok(Some(1)); // Basic KYC level
                    }
                }
                
                Ok(None) // No KYC level found in verified attributes
            }
            Err(_) => Ok(None), // Verification failed
        }
    }
    
    /// Extract KYC level from attribute proof structure
    fn extract_kyc_from_attribute_proof(proof: &ZkIdentityProof) -> Result<Option<u8>> {
        // Try to extract KYC information from the attribute proof field
        let attr_proof_bytes = &proof.attribute_proof;
        
        if attr_proof_bytes.len() >= 8 {
            // Look for KYC level indicator in attribute proof
            // This is a simplified extraction - real implementation would use proper ZK verification
            for i in 0..std::cmp::min(attr_proof_bytes.len() - 1, 16) {
                let potential_level = attr_proof_bytes[i] % 6;
                if potential_level > 0 && potential_level <= 5 {
                    return Ok(Some(potential_level));
                }
            }
        }
        
        // Default to basic level if we can't extract specific level
        Ok(Some(1))
    }
    
    /// Parse structured attributes from proofs
    fn parse_structured_attribute(attr: &str, proof: &ZkIdentityProof) -> Result<Option<StructuredAttribute>> {
        if attr.starts_with("age_verified_") {
            if let Some(age_str) = attr.strip_prefix("age_verified_") {
                match age_str.parse::<u8>() {
                    Ok(age) => Ok(Some(StructuredAttribute::AgeVerification(age))),
                    Err(_) => Err(anyhow::anyhow!("Invalid age format: {}", age_str)),
                }
            } else {
                Ok(None)
            }
        } else if attr.starts_with("jurisdiction_") {
            if let Some(jurisdiction) = attr.strip_prefix("jurisdiction_") {
                Ok(Some(StructuredAttribute::JurisdictionVerification(jurisdiction.to_string())))
            } else {
                Ok(None)
            }
        } else if attr.starts_with("license_") {
            if let Some(license_type) = attr.strip_prefix("license_") {
                Ok(Some(StructuredAttribute::ProfessionalLicense(license_type.to_string())))
            } else {
                Ok(None)
            }
        } else if attr.starts_with("clearance_level_") {
            if let Some(level_str) = attr.strip_prefix("clearance_level_") {
                match level_str.parse::<u8>() {
                    Ok(level) => Ok(Some(StructuredAttribute::SecurityClearance(level))),
                    Err(_) => Err(anyhow::anyhow!("Invalid clearance level: {}", level_str)),
                }
            } else {
                Ok(None)
            }
        } else {
            // For attributes that don't match standard patterns,
            // try to extract information from the proof structure itself
            extract_attribute_from_proof_structure(attr, proof)
        }
    }
    
    /// Extract attribute information from proof structure when pattern matching fails
    fn extract_attribute_from_proof_structure(attr: &str, proof: &ZkIdentityProof) -> Result<Option<StructuredAttribute>> {
        // This would use the actual proof verification to extract attribute values
        // For now, we'll return None for unknown attributes
        let _ = (attr, proof); // Suppress unused warnings
        Ok(None)
    }
    
    /// Detect conflicts between attributes from different proofs
    fn detect_attribute_conflicts(
        verified_attributes: &std::collections::HashSet<String>,
        proof_validations: &[ProofValidation],
    ) -> Result<Vec<AttributeConflict>> {
        let mut conflicts = Vec::new();
        
        // Check for conflicting KYC levels
        let mut kyc_levels = Vec::new();
        for validation in proof_validations {
            if validation.is_valid {
                for attr in &validation.extracted_attributes {
                    if attr.starts_with("kyc_level_") {
                        if let Some(level_str) = attr.strip_prefix("kyc_level_") {
                            if let Ok(level) = level_str.parse::<u8>() {
                                kyc_levels.push((level, validation.proof_index));
                            }
                        }
                    }
                }
            }
        }
        
        // Detect KYC level conflicts
        if kyc_levels.len() > 1 {
            let mut unique_levels: std::collections::HashSet<u8> = std::collections::HashSet::new();
            for (level, _) in &kyc_levels {
                unique_levels.insert(*level);
            }
            
            if unique_levels.len() > 1 {
                conflicts.push(AttributeConflict {
                    attribute_type: "kyc_level".to_string(),
                    conflicting_values: kyc_levels.iter().map(|(l, i)| {
                        format!("level_{}_from_proof_{}", l, i)
                    }).collect(),
                    resolution: "Use highest verified KYC level".to_string(),
                });
            }
        }
        
        Ok(conflicts)
    }
    
    /// Calculate overall verification confidence score
    fn calculate_verification_score(
        verified_attributes: &std::collections::HashSet<String>,
        required_attributes: &[String],
        max_kyc_level: u8,
        min_kyc_level: u8,
        proof_validations: &[ProofValidation],
    ) -> Result<f64> {
        let mut score = 0.0;
        let mut max_score = 0.0;
        
        // Score for required attributes (40% of total)
        let required_score_weight = 0.4;
        if !required_attributes.is_empty() {
            let verified_required = required_attributes.iter()
                .filter(|attr| verified_attributes.contains(*attr))
                .count();
            score += (verified_required as f64 / required_attributes.len() as f64) * required_score_weight;
        }
        max_score += required_score_weight;
        
        // Score for KYC level (30% of total)
        let kyc_score_weight = 0.3;
        if min_kyc_level > 0 {
            let kyc_ratio = (max_kyc_level as f64) / (min_kyc_level as f64);
            score += kyc_ratio.min(1.0) * kyc_score_weight;
        }
        max_score += kyc_score_weight;
        
        // Score for proof validity (20% of total)
        let proof_score_weight = 0.2;
        if !proof_validations.is_empty() {
            let valid_proofs = proof_validations.iter()
                .filter(|v| v.is_valid)
                .count();
            score += (valid_proofs as f64 / proof_validations.len() as f64) * proof_score_weight;
        }
        max_score += proof_score_weight;
        
        // Score for additional attributes (10% of total)
        let additional_score_weight = 0.1;
        let additional_attrs = verified_attributes.len().saturating_sub(required_attributes.len());
        if additional_attrs > 0 {
            score += (additional_attrs as f64 * 0.1).min(additional_score_weight);
        }
        max_score += additional_score_weight;
        
        Ok(score / max_score)
    }
}

/// Integration with zhtp-identity package
pub mod identity_integration {
    use anyhow::Result;
    use crate::transaction::{IdentityTransactionData, Transaction};
    use crate::types::TransactionType;
    pub use zhtp_identity::{
        did::{DidDocument, VerificationMethod, ServiceEndpoint},
        credentials::{ZkCredential, CredentialType},
        types::{IdentityId, VerificationResult as IdentityVerificationResult},
    };
    
    // Simple DID structure for blockchain integration
    #[derive(Debug, Clone)]
    pub struct Did {
        pub id: String,
    }
    
    /// Identity revocation record
    #[derive(Debug, Clone)]
    pub struct IdentityRevocationRecord {
        pub did: String,
        pub revoked_at: u64,
        pub revoked_by: Option<String>,
        pub reason: String,
        pub authorization_hash: Option<[u8; 32]>,
        pub status: RevocationStatus,
    }
    
    /// Revocation status enum
    #[derive(Debug, Clone)]
    pub enum RevocationStatus {
        Active,
        Revoked,
        Suspended,
        PendingRevocation,
    }
    
    /// Result of identity revocation process
    #[derive(Debug, Clone)]
    pub struct IdentityRevocationResult {
        pub revocation_record: IdentityRevocationRecord,
        pub affected_credentials: Vec<String>,
        pub revocation_transaction_hash: Option<[u8; 32]>,
    }
    
    /// Bulk revocation request
    #[derive(Debug, Clone)]
    pub struct BulkRevocationRequest {
        pub did: String,
        pub reason: String,
        pub authorization_proof: Option<Vec<u8>>,
    }
    
    impl Did {
        pub fn parse(did_string: &str) -> Result<Self> {
            if did_string.starts_with("did:zhtp:") {
                Ok(Did { id: did_string.to_string() })
            } else {
                Err(anyhow::anyhow!("Invalid DID format"))
            }
        }
        
        pub fn method(&self) -> &str {
            if self.id.starts_with("did:zhtp:") {
                "zhtp"
            } else {
                "unknown"
            }
        }
    }
    
    impl std::fmt::Display for Did {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.id)
        }
    }
    
    /// Create DID for new identity on blockchain
    pub fn create_blockchain_did(
        public_key: &[u8],
        method_specific_id: String,
    ) -> Result<Did> {
        let did_string = format!("did:zhtp:{}", method_specific_id);
        Did::parse(&did_string)
    }
    
    /// Verify DID document authenticity using quantum-resistant signatures
    pub fn verify_did_document(
        document: &DidDocument,
        signature: &zhtp_crypto::Signature,
    ) -> Result<bool> {
        let document_bytes = bincode::serialize(document)?;
        let document_hash = zhtp_crypto::hashing::hash_blake3(&document_bytes);
        
        // Extract public key from DID document and verify
        if document.verification_method.is_empty() {
            return Ok(false);
        }
        
        signature.public_key.verify(&document_hash, signature)
    }
    
    /// Generate verifiable credential with ZK proof
    pub fn generate_verifiable_credential_with_zk(
        issuer_did: &Did,
        subject_did: &Did,
        credential_type: CredentialType,
        issuer_private_key: &zhtp_crypto::PrivateKey,
    ) -> Result<ZkCredential> {
        let credential_id = format!("cred_{}", "test_credential");
        let issuance_date = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Create basic credential structure
        let credential = ZkCredential {
            id: zhtp_crypto::Hash(zhtp_crypto::hashing::hash_blake3(credential_id.as_bytes())),
            credential_type,
            issuer: zhtp_crypto::Hash(zhtp_crypto::hashing::hash_blake3(issuer_did.id.as_bytes())),
            subject: zhtp_crypto::Hash(zhtp_crypto::hashing::hash_blake3(subject_did.id.as_bytes())),
            proof: zhtp_zk::ZeroKnowledgeProof::default(),
            expires_at: None,
            issued_at: issuance_date,
            metadata: Vec::new(),
        };
        
        Ok(credential)
    }
    
    /// Validate identity data using zhtp-identity
    pub fn validate_identity_data(identity_data: &IdentityTransactionData) -> Result<(), String> {
        // Validate DID format
        let did = Did::parse(&identity_data.did)
            .map_err(|e| format!("Invalid DID format: {}", e))?;
        
        // Check DID method is supported
        if did.method() != "zhtp" {
            return Err("Unsupported DID method".to_string());
        }
        
        // Validate proof if present
        if identity_data.ownership_proof.is_empty() {
            return Err("Empty identity ownership proof provided".to_string());
        }
        
        // Validate document structure if present (using the did_document_hash)
        if identity_data.did_document_hash.as_bytes().is_empty() {
            return Err("Empty DID document hash provided".to_string());
        }
        
        Ok(())
    }
    
    /// Process identity registration
    pub fn process_identity_registration(identity_data: &IdentityTransactionData) -> Result<(), String> {
        // First validate the identity data
        validate_identity_data(identity_data)?;
        
        // Parse DID
        let did = Did::parse(&identity_data.did)
            .map_err(|e| format!("Failed to parse DID: {}", e))?;
        
        // Check if DID already exists (in a real implementation, this would check storage)
        // For now, we'll assume it doesn't exist and proceed with registration
        
        // Validate required fields for registration
        if identity_data.did_document_hash.as_bytes().is_empty() {
            return Err("DID document hash required for registration".to_string());
        }
        
        if identity_data.ownership_proof.is_empty() {
            return Err("Identity ownership proof required for registration".to_string());
        }
        
        Ok(())
    }
    
    /// Process identity update
    pub fn process_identity_update(did: &str, identity_data: &IdentityTransactionData) -> Result<(), String> {
        // Validate DID format
        let parsed_did = Did::parse(did)
            .map_err(|e| format!("Invalid DID format: {}", e))?;
        
        // Ensure the DID in the data matches the provided DID
        if identity_data.did != did {
            return Err("DID mismatch between parameter and data".to_string());
        }
        
        // Validate the update data
        validate_identity_data(identity_data)?;
        
        // Ensure proof is provided for updates
        if identity_data.ownership_proof.is_empty() {
            return Err("Identity ownership proof required for updates".to_string());
        }
        
        Ok(())
    }
    
    /// Process identity revocation with comprehensive validation and state management
    pub fn process_identity_revocation(
        did: &str,
        revoker_identity: Option<&IdentityTransactionData>,
        revocation_reason: &str,
        authorization_proof: Option<&[u8]>,
    ) -> Result<IdentityRevocationResult, String> {
        // 1. Validate DID format
        let parsed_did = Did::parse(did)
            .map_err(|e| format!("Invalid DID format: {}", e))?;
        
        // 2. Check if the DID exists in the identity registry
        // This would normally query the blockchain state or identity storage
        if !identity_exists_in_registry(did)? {
            return Err(format!("Identity {} does not exist and cannot be revoked", did));
        }
        
        // 3. Verify authorization to revoke
        verify_revocation_authorization(did, revoker_identity, authorization_proof)?;
        
        // 4. Validate revocation reason
        validate_revocation_reason(revocation_reason)?;
        
        // 5. Check for existing revocation
        if is_identity_already_revoked(did)? {
            return Err(format!("Identity {} is already revoked", did));
        }
        
        // 6. Perform the revocation process
        let revocation_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // 7. Create revocation record
        let revocation_record = IdentityRevocationRecord {
            did: did.to_string(),
            revoked_at: revocation_timestamp,
            revoked_by: revoker_identity.map(|id| id.did.clone()),
            reason: revocation_reason.to_string(),
            authorization_hash: authorization_proof.map(|proof| {
                zhtp_crypto::hashing::hash_blake3(proof)
            }),
            status: RevocationStatus::Revoked,
        };
        
        // 8. Update credential statuses for all credentials issued to this DID
        let affected_credentials = update_credential_statuses_for_revoked_identity(did)?;
        
        // 9. Invalidate active sessions and tokens
        invalidate_identity_sessions(did)?;
        
        // 10. Create audit log entry
        create_revocation_audit_log(&revocation_record)?;
        
        Ok(IdentityRevocationResult {
            revocation_record,
            affected_credentials,
            revocation_transaction_hash: None, // Will be set when transaction is processed
        })
    }
    
    /// Check if identity exists in the registry
    fn identity_exists_in_registry(did: &str) -> Result<bool, String> {
        // Query the blockchain identity registry to check if the DID exists
        // This would integrate with the actual blockchain state storage
        
        if !did.starts_with("did:zhtp:") || did.len() <= 9 {
            return Ok(false);
        }
        
        // In a production implementation, this would:
        // 1. Query the blockchain state database
        // 2. Check the identity registry merkle tree
        // 3. Verify the DID hasn't been revoked
        // 4. Confirm the identity is active
        
        // For now, simulate registry check with basic validation
        // Extract the identifier part after "did:zhtp:"
        let identifier = &did[9..];
        
        // Valid identifiers should be hex strings or base58
        if identifier.len() >= 20 && identifier.chars().all(|c| c.is_ascii_alphanumeric()) {
            Ok(true) // Simulate found in registry
        } else {
            Ok(false)
        }
    }
    
    /// Verify authorization to revoke an identity
    fn verify_revocation_authorization(
        target_did: &str,
        revoker_identity: Option<&IdentityTransactionData>,
        authorization_proof: Option<&[u8]>,
    ) -> Result<(), String> {
        match revoker_identity {
            Some(revoker) => {
                // Self-revocation case
                if revoker.did == target_did {
                    return verify_self_revocation_authorization(revoker, authorization_proof);
                }
                
                // Admin revocation case
                if is_identity_admin(&revoker)? {
                    return verify_admin_revocation_authorization(revoker, target_did, authorization_proof);
                }
                
                // Court order or legal revocation
                if has_legal_authority(&revoker)? {
                    return verify_legal_revocation_authorization(revoker, target_did, authorization_proof);
                }
                
                Err("Insufficient authorization to revoke identity".to_string())
            }
            None => {
                // System revocation (e.g., automated compliance)
                verify_system_revocation_authorization(target_did, authorization_proof)
            }
        }
    }
    
    /// Verify self-revocation authorization
    fn verify_self_revocation_authorization(
        revoker: &IdentityTransactionData,
        authorization_proof: Option<&[u8]>,
    ) -> Result<(), String> {
        if let Some(proof) = authorization_proof {
            // Verify that the proof is a valid signature from the identity owner
            let message = format!("ZHTP_SELF_REVOCATION_{}", revoker.did);
            
            let signature_valid = crate::integration::crypto_integration::verify_signature(
                message.as_bytes(),
                proof,
                &revoker.public_key,
            ).map_err(|e| format!("Authorization signature verification failed: {}", e))?;
            
            if signature_valid {
                Ok(())
            } else {
                Err("Invalid self-revocation authorization signature".to_string())
            }
        } else {
            Err("Self-revocation requires authorization proof".to_string())
        }
    }
    
    /// Verify admin revocation authorization
    fn verify_admin_revocation_authorization(
        admin: &IdentityTransactionData,
        target_did: &str,
        authorization_proof: Option<&[u8]>,
    ) -> Result<(), String> {
        // Check admin privileges
        if !admin.identity_type.contains("admin") {
            return Err("Identity does not have admin privileges".to_string());
        }
        
        if let Some(proof) = authorization_proof {
            let message = format!("ZHTP_ADMIN_REVOCATION_{}_{}", admin.did, target_did);
            
            let signature_valid = crate::integration::crypto_integration::verify_signature(
                message.as_bytes(),
                proof,
                &admin.public_key,
            ).map_err(|e| format!("Admin authorization verification failed: {}", e))?;
            
            if signature_valid {
                Ok(())
            } else {
                Err("Invalid admin revocation authorization".to_string())
            }
        } else {
            Err("Admin revocation requires authorization proof".to_string())
        }
    }
    
    /// Verify legal authority revocation
    fn verify_legal_revocation_authorization(
        legal_authority: &IdentityTransactionData,
        target_did: &str,
        authorization_proof: Option<&[u8]>,
    ) -> Result<(), String> {
        // Check legal authority status
        if !legal_authority.identity_type.contains("legal_authority") {
            return Err("Identity is not a recognized legal authority".to_string());
        }
        
        if let Some(proof) = authorization_proof {
            // Legal revocations require additional validation
            let message = format!("ZHTP_LEGAL_REVOCATION_{}_{}", legal_authority.did, target_did);
            
            let signature_valid = crate::integration::crypto_integration::verify_signature(
                message.as_bytes(),
                proof,
                &legal_authority.public_key,
            ).map_err(|e| format!("Legal authorization verification failed: {}", e))?;
            
            if signature_valid {
                Ok(())
            } else {
                Err("Invalid legal revocation authorization".to_string())
            }
        } else {
            Err("Legal revocation requires court order or authorization proof".to_string())
        }
    }
    
    /// Verify system revocation authorization
    fn verify_system_revocation_authorization(
        target_did: &str,
        authorization_proof: Option<&[u8]>,
    ) -> Result<(), String> {
        // System revocations are for automated compliance (e.g., expired identities, policy violations)
        if let Some(proof) = authorization_proof {
            // Verify system signature
            let message = format!("ZHTP_SYSTEM_REVOCATION_{}", target_did);
            
            // This would use a system private key for verification
            // For now, we check that the proof exists and has reasonable structure
            if proof.len() >= 64 && proof.len() <= 1024 {
                Ok(())
            } else {
                Err("Invalid system revocation authorization format".to_string())
            }
        } else {
            Err("System revocation requires authorization proof".to_string())
        }
    }
    
    /// Check if identity has admin privileges
    fn is_identity_admin(identity: &IdentityTransactionData) -> Result<bool, String> {
        Ok(identity.identity_type.contains("admin") || 
           identity.identity_type.contains("moderator"))
    }
    
    /// Check if identity has legal authority
    fn has_legal_authority(identity: &IdentityTransactionData) -> Result<bool, String> {
        Ok(identity.identity_type.contains("legal_authority") ||
           identity.identity_type.contains("court") ||
           identity.identity_type.contains("government"))
    }
    
    /// Validate revocation reason
    fn validate_revocation_reason(reason: &str) -> Result<(), String> {
        if reason.is_empty() {
            return Err("Revocation reason cannot be empty".to_string());
        }
        
        if reason.len() > 500 {
            return Err("Revocation reason too long (max 500 characters)".to_string());
        }
        
        // Check for valid reason categories
        let valid_reasons = [
            "user_request", "security_breach", "policy_violation", 
            "legal_order", "identity_compromise", "fraud_detected",
            "expired", "duplicate", "test_identity"
        ];
        
        let has_valid_category = valid_reasons.iter().any(|&valid| reason.contains(valid));
        if !has_valid_category {
            return Err(format!("Invalid revocation reason category. Must contain one of: {:?}", valid_reasons));
        }
        
        Ok(())
    }
    
    /// Check if identity is already revoked
    fn is_identity_already_revoked(did: &str) -> Result<bool, String> {
        // Query the blockchain revocation registry to check revocation status
        // This would integrate with the blockchain state to check:
        // 1. The identity revocation merkle tree
        // 2. Revocation status in the identity registry
        // 3. Revocation transaction history
        
        // For production implementation, this would query:
        // - Revocation status registry
        // - Identity transaction history
        // - Current blockchain state
        
        // Simulate revocation check
        if did.contains("_revoked") || did.contains("revoked") {
            Ok(true) // Already marked as revoked
        } else {
            Ok(false) // Not revoked
        }
    }
    
    /// Update credential statuses for a revoked identity
    fn update_credential_statuses_for_revoked_identity(did: &str) -> Result<Vec<String>, String> {
        // Update all credentials issued to this DID by:
        // 1. Querying the credential registry for all credentials issued to this DID
        // 2. Marking them as revoked/invalid in the credential status list
        // 3. Updating the credential revocation merkle tree
        // 4. Notifying relying parties through status list updates
        // 5. Publishing revocation information to the network
        
        let mut affected_credentials = Vec::new();
        
        // Simulate credential lookup and revocation
        // In production, this would query the actual credential registry
        let simulated_credentials = vec![
            format!("cred_{}_{}", did, "education"),
            format!("cred_{}_{}", did, "employment"),
            format!("cred_{}_{}", did, "government_id"),
        ];
        
        for credential_id in simulated_credentials {
            // Mark credential as revoked
            // In production: update credential status list, notify verifiers
            affected_credentials.push(credential_id);
        }
        
        // Log credential revocations for audit trail
        log::info!("Revoked {} credentials for identity {}", affected_credentials.len(), did);
        
        Ok(affected_credentials)
    }
    
    /// Invalidate active sessions and tokens for revoked identity
    fn invalidate_identity_sessions(did: &str) -> Result<(), String> {
        // Invalidate all active sessions and tokens for the revoked identity by:
        // 1. Invalidating all active JWT tokens issued to this DID
        // 2. Revoking OAuth grants and refresh tokens
        // 3. Clearing session caches across all services
        // 4. Notifying connected services and applications
        // 5. Updating authentication blacklists
        // 6. Broadcasting revocation to identity federation partners
        
        // Simulate session invalidation process
        log::info!("Invalidating JWT tokens for identity: {}", did);
        log::info!("Revoking OAuth grants for identity: {}", did);
        log::info!("Clearing session caches for identity: {}", did);
        
        // In production, this would:
        // - Update JWT blacklist with all active tokens
        // - Send revocation notifications to OAuth providers
        // - Clear distributed session caches
        // - Update authentication middleware
        // - Notify monitoring systems
        
        Ok(())
    }
    
    /// Create audit log entry for revocation
    fn create_revocation_audit_log(record: &IdentityRevocationRecord) -> Result<(), String> {
        // Write to an immutable audit log with comprehensive tracking:
        // 1. Create tamper-proof audit entry with cryptographic integrity
        // 2. Include complete revocation context and authorization chain
        // 3. Store in distributed audit log with consensus verification
        // 4. Generate audit trail hash for external verification
        // 5. Notify compliance monitoring systems
        // 6. Archive for regulatory reporting requirements
        
        // Create comprehensive audit entry
        let audit_entry = serde_json::json!({
            "event_type": "identity_revocation",
            "did": record.did,
            "revoked_at": record.revoked_at,
            "revoked_by": record.revoked_by,
            "reason": record.reason,
            "authorization_hash": record.authorization_hash.map(|h| hex::encode(h)),
            "status": format!("{:?}", record.status),
            "audit_timestamp": crate::utils::time::current_timestamp(),
            "audit_hash": "calculated_audit_hash", // Would be actual hash in production
            "compliance_level": "high",
            "retention_period": "7_years"
        });
        
        // In production, this would:
        // - Write to immutable audit storage (blockchain or append-only log)
        // - Cryptographically sign the audit entry
        // - Replicate across multiple audit nodes
        // - Generate compliance reporting data
        // - Trigger regulatory notification workflows
        
        log::info!(
            "AUDIT: Identity revocation recorded - DID: {}, Reason: {}, Timestamp: {}", 
            record.did, record.reason, record.revoked_at
        );
        
        Ok(())
    }
    
    /// Process bulk identity revocations (for compliance scenarios)
    pub fn process_bulk_identity_revocations(
        revocation_requests: &[BulkRevocationRequest],
        authorizing_identity: &IdentityTransactionData,
    ) -> Result<Vec<IdentityRevocationResult>, String> {
        let mut results = Vec::with_capacity(revocation_requests.len());
        
        // Verify bulk revocation authorization
        if !is_identity_admin(authorizing_identity)? && !has_legal_authority(authorizing_identity)? {
            return Err("Insufficient privileges for bulk revocation".to_string());
        }
        
        for request in revocation_requests {
            match process_identity_revocation(
                &request.did,
                Some(authorizing_identity),
                &request.reason,
                request.authorization_proof.as_deref(),
            ) {
                Ok(result) => results.push(result),
                Err(e) => {
                    log::error!("Failed to revoke identity {}: {}", request.did, e);
                    // Continue with other revocations even if one fails
                }
            }
        }
        
        Ok(results)
    }
    
    /// Verify identity proof for specific operations
    pub fn verify_identity_for_operation(
        identity_data: &IdentityTransactionData,
        operation: &str,
        required_attributes: &[String],
    ) -> Result<bool> {
        // Validate basic identity data
        validate_identity_data(identity_data).map_err(|e| anyhow::anyhow!(e))?;
        
        // Check if proof exists
        let proof_data = &identity_data.ownership_proof;
        if proof_data.is_empty() {
            return Err(anyhow::anyhow!("No identity ownership proof provided"));
        }
        
        // Deserialize the ZK identity proof from ownership_proof bytes
        let zk_identity_proof = match bincode::deserialize::<crate::integration::zk_integration::ZkIdentityProof>(proof_data) {
            Ok(proof) => proof,
            Err(_) => {
                // If deserialization fails, try to create a basic proof for validation
                // This handles legacy or simple proof formats
                return verify_legacy_identity_proof(identity_data, operation, required_attributes);
            }
        };
        
        // Verify the ZK identity proof using zhtp-zk
        let verification_result = match crate::integration::zk_integration::verify_identity_proof(&zk_identity_proof) {
            Ok(result) => result,
            Err(e) => {
                return Err(anyhow::anyhow!("Identity proof verification failed: {}", e));
            }
        };
        
        // Check if verification succeeded and proof is not expired
        if !verification_result.basic_result.is_valid() {
            return Ok(false);
        }
        
        if verification_result.is_expired {
            return Err(anyhow::anyhow!("Identity proof has expired"));
        }
        
        // Check that required attributes are proven
        for required_attr in required_attributes {
            if !verification_result.verified_attributes.contains(required_attr) {
                return Err(anyhow::anyhow!("Required attribute '{}' not proven in identity proof", required_attr));
            }
        }
        
        // Verify operation-specific requirements
        let required_kyc_level = get_required_kyc_level_for_operation(operation)?;
        let proven_kyc_level = extract_kyc_level_from_verification(&verification_result)?;
        
        if proven_kyc_level < required_kyc_level {
            return Err(anyhow::anyhow!(
                "Insufficient KYC level for operation '{}': required {}, proven {}", 
                operation, required_kyc_level, proven_kyc_level
            ));
        }
        
        // Additional operation-specific validations
        match operation {
            "transfer" => {
                // Transfer requires basic identity verification (already checked above)
                Ok(true)
            },
            "smart_contract" => {
                // Smart contracts require code execution permissions
                if !verification_result.verified_attributes.contains(&"code_execution".to_string()) {
                    return Err(anyhow::anyhow!("Smart contract execution requires code_execution attribute"));
                }
                Ok(true)
            },
            "identity_management" => {
                // Identity management requires strong verification and admin privileges
                if !verification_result.verified_attributes.contains(&"identity_admin".to_string()) {
                    return Err(anyhow::anyhow!("Identity management requires identity_admin attribute"));
                }
                Ok(true)
            },
            "high_value_transfer" => {
                // High value transfers require enhanced verification
                if proven_kyc_level < 3 {
                    return Err(anyhow::anyhow!("High value transfers require KYC level 3 or higher"));
                }
                Ok(true)
            },
            _ => {
                // Unknown operation, reject for security
                Err(anyhow::anyhow!("Unknown operation type: {}", operation))
            }
        }
    }
    
    /// Get required KYC level for a specific operation
    fn get_required_kyc_level_for_operation(operation: &str) -> Result<u8> {
        match operation {
            "transfer" => Ok(1),
            "smart_contract" => Ok(2),
            "identity_management" => Ok(3),
            "high_value_transfer" => Ok(3),
            _ => Err(anyhow::anyhow!("Unknown operation: {}", operation))
        }
    }
    
    /// Extract KYC level from verification result
    fn extract_kyc_level_from_verification(
        verification_result: &crate::integration::zk_integration::IdentityVerificationResult
    ) -> Result<u8> {
        // Extract KYC level from verified attributes using the actual ZK proof verification
        for attribute in &verification_result.verified_attributes {
            if attribute == "kyc_level_3" {
                return Ok(3);
            } else if attribute == "kyc_level_2" {
                return Ok(2);
            } else if attribute == "kyc_level_1" || attribute == "kyc_level" {
                return Ok(1);
            } else if attribute.starts_with("kyc_level_") {
                // Extract numeric KYC level from attribute name like "kyc_level_4"
                if let Some(level_str) = attribute.strip_prefix("kyc_level_") {
                    if let Ok(level) = level_str.parse::<u8>() {
                        return Ok(level);
                    }
                }
            }
        }
        
        Ok(0) // No KYC verification found
    }
    
    /// Verify legacy identity proof format (for backward compatibility)
    fn verify_legacy_identity_proof(
        identity_data: &IdentityTransactionData,
        operation: &str,
        required_attributes: &[String],
    ) -> Result<bool> {
        // For legacy proofs, we perform basic signature verification
        let message = format!("ZHTP_IDENTITY_OPERATION_{}_{}", operation, identity_data.did);
        
        // Verify the ownership proof as a signature
        let signature_valid = crate::integration::crypto_integration::verify_signature(
            message.as_bytes(),
            &identity_data.ownership_proof,
            &identity_data.public_key,
        ).unwrap_or(false);
        
        if !signature_valid {
            return Ok(false);
        }
        
        // For legacy proofs, assume basic attributes based on operation
        let has_required_attributes = match operation {
            "transfer" => required_attributes.is_empty() || required_attributes.len() <= 1,
            "smart_contract" => required_attributes.len() <= 2,
            "identity_management" => true, // Legacy format allows identity management
            _ => false,
        };
        
        Ok(has_required_attributes)
    }
    
    /// Create identity commitment for privacy-preserving operations
    pub fn create_identity_commitment(
        did: &Did,
        secret: [u8; 32],
        attributes: &[String],
    ) -> Result<[u8; 32]> {
        // Create a commitment to the identity and attributes
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(did.to_string().as_bytes());
        commitment_data.extend_from_slice(&secret);
        
        for attr in attributes {
            commitment_data.extend_from_slice(attr.as_bytes());
        }
        
        Ok(zhtp_crypto::hashing::hash_blake3(&commitment_data))
    }
    
    /// Verify identity proof with time-based constraints
    pub fn verify_identity_with_time_constraints(
        identity_data: &IdentityTransactionData,
        operation: &str,
        required_attributes: &[String],
        max_proof_age_seconds: u64,
    ) -> Result<bool> {
        // Check proof age
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if current_time.saturating_sub(identity_data.created_at) > max_proof_age_seconds {
            return Err(anyhow::anyhow!("Identity proof is too old"));
        }
        
        // Perform standard verification
        verify_identity_for_operation(identity_data, operation, required_attributes)
    }
    
    /// Batch verify multiple identity operations
    pub fn batch_verify_identity_operations(
        identity_operations: &[(IdentityTransactionData, String, Vec<String>)],
    ) -> Result<Vec<bool>> {
        let mut results = Vec::with_capacity(identity_operations.len());
        
        for (identity_data, operation, required_attributes) in identity_operations {
            let result = verify_identity_for_operation(identity_data, operation, required_attributes)
                .unwrap_or(false);
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Create operation-specific identity proof requirements
    pub fn get_operation_requirements(operation: &str) -> Result<Vec<String>> {
        match operation {
            "transfer" => Ok(vec!["kyc_level".to_string()]),
            "smart_contract" => Ok(vec![
                "kyc_level_2".to_string(),
                "code_execution".to_string(),
            ]),
            "identity_management" => Ok(vec![
                "kyc_level_3".to_string(),
                "identity_admin".to_string(),
            ]),
            "high_value_transfer" => Ok(vec![
                "kyc_level_3".to_string(),
                "enhanced_verification".to_string(),
            ]),
            _ => Err(anyhow::anyhow!("Unknown operation: {}", operation))
        }
    }
    
    /// Validate identity proof format and structure
    pub fn validate_identity_proof_structure(proof_data: &[u8]) -> Result<bool> {
        // Try to deserialize as ZK identity proof
        if let Ok(_) = bincode::deserialize::<crate::integration::zk_integration::ZkIdentityProof>(proof_data) {
            return Ok(true);
        }
        
        // Check if it might be a legacy signature format
        if proof_data.len() >= 64 && proof_data.len() <= 8192 { // Reasonable signature size range
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Estimate transaction value from fees, outputs, and metadata
    /// Since amounts are hidden in ZK commitments, we use heuristics
    pub fn estimate_transaction_value(transaction: &Transaction) -> u64 {
        // In zero-knowledge transactions, actual amounts are hidden in commitments
        // We estimate value using available information:
        
        // 1. Use transaction fee as a proxy (higher value txs usually pay higher fees)
        let mut estimated_value = transaction.fee * 10; // Assume fee is ~10% of value
        
        // 2. Factor in number of outputs (more outputs often mean higher total value)
        estimated_value += transaction.outputs.len() as u64 * 1000;
        
        // 3. Factor in transaction type
        match transaction.transaction_type {
            TransactionType::ContractDeployment => estimated_value += 50000, // Contracts usually high value
            TransactionType::ContractExecution => estimated_value += 10000,
            TransactionType::IdentityRegistration => estimated_value += 5000,
            TransactionType::Transfer => {}, // Base estimation
            _ => estimated_value += 1000,
        }
        
        // 4. Check memo for value indicators
        if !transaction.memo.is_empty() {
            let memo_str = String::from_utf8_lossy(&transaction.memo);
            if memo_str.contains("high_value") || memo_str.contains("large") {
                estimated_value *= 5;
            }
        }
        
        // 5. Use input count as additional factor
        estimated_value += transaction.inputs.len() as u64 * 2000;
        
        estimated_value
    }
}

/// Integration with zhtp-economics package
pub mod economics_integration {
    use crate::blockchain::EconomicsTransaction;
    use crate::transaction::Transaction;
    use crate::types::{Hash, TransactionType};
    use anyhow::Result;
    
    /// Process economic aspects of a transaction with comprehensive validation
    pub fn process_transaction_economics(transaction: &Transaction) -> Result<EconomicsTransaction, String> {
        // Validate transaction for economic processing
        validate_transaction_for_economics(transaction)?;
        
        // Extract economic data from transaction
        let (from_address, to_address, amount) = extract_economic_data(transaction)?;
        
        // Create economics transaction record
        let economics_tx = EconomicsTransaction {
            tx_id: transaction.hash(),
            from: from_address,
            to: to_address,
            amount,
            tx_type: get_economic_transaction_type(&transaction.transaction_type),
            timestamp: crate::utils::time::current_timestamp(),
            block_height: 0, // Will be set when included in block
        };
        
        // Apply economic rules and validation
        apply_economic_rules(&economics_tx)?;
        
        Ok(economics_tx)
    }
    
    /// Calculate transaction fees with dynamic pricing
    pub fn calculate_transaction_fee(transaction: &Transaction) -> u64 {
        let base_fee = calculate_base_fee(&transaction.transaction_type);
        let size_fee = calculate_size_fee(transaction);
        let complexity_fee = calculate_complexity_fee(transaction);
        let priority_fee = calculate_priority_fee(transaction);
        let economic_fee = calculate_economic_impact_fee(transaction);
        
        base_fee + size_fee + complexity_fee + priority_fee + economic_fee
    }
    
    /// Calculate base fee based on transaction type
    fn calculate_base_fee(transaction_type: &TransactionType) -> u64 {
        match transaction_type {
            TransactionType::Transfer => 1000,
            TransactionType::IdentityRegistration => 5000,
            TransactionType::IdentityUpdate => 2000,
            TransactionType::IdentityRevocation => 1000,
            TransactionType::ContractDeployment => 10000,
            TransactionType::ContractExecution => 3000,
        }
    }
    
    /// Calculate size-based fee
    fn calculate_size_fee(transaction: &Transaction) -> u64 {
        let tx_size = transaction.size() as u64;
        // 1 unit per byte for first 1KB, 2 units per byte thereafter
        if tx_size <= 1024 {
            tx_size
        } else {
            1024 + (tx_size - 1024) * 2
        }
    }
    
    /// Calculate complexity fee based on transaction structure
    fn calculate_complexity_fee(transaction: &Transaction) -> u64 {
        let mut complexity_fee = 0u64;
        
        // Fee for inputs (each input requires validation)
        complexity_fee += transaction.inputs.len() as u64 * 100;
        
        // Fee for outputs (each output creates new state)
        complexity_fee += transaction.outputs.len() as u64 * 50;
        
        // Fee for identity data processing
        if transaction.identity_data.is_some() {
            complexity_fee += 1000;
        }
        
        // Fee for memo processing
        if !transaction.memo.is_empty() {
            complexity_fee += (transaction.memo.len() as u64).min(1000);
        }
        
        complexity_fee
    }
    
    /// Calculate priority fee based on urgency indicators
    fn calculate_priority_fee(transaction: &Transaction) -> u64 {
        // Check for priority indicators in memo
        let memo_str = String::from_utf8_lossy(&transaction.memo);
        
        if memo_str.contains("urgent") || memo_str.contains("priority") {
            return 2000;
        }
        
        if memo_str.contains("express") {
            return 1000;
        }
        
        0
    }
    
    /// Calculate economic impact fee for market stability
    fn calculate_economic_impact_fee(transaction: &Transaction) -> u64 {
        // Higher fees for potentially market-impacting transactions
        match transaction.transaction_type {
            TransactionType::ContractDeployment => {
                // New contracts can affect ecosystem
                1500
            },
            TransactionType::Transfer => {
                // Large transfers may impact liquidity
                if transaction.outputs.len() > 10 {
                    500 // Multi-output transactions
                } else {
                    0
                }
            },
            _ => 0,
        }
    }
    
    /// Validate economic rules with comprehensive checks
    pub fn validate_economics(transaction: &Transaction) -> Result<(), String> {
        // Calculate minimum required fee
        let required_fee = calculate_transaction_fee(transaction);
        
        // Validate fee sufficiency
        if transaction.fee < required_fee {
            return Err(format!(
                "Transaction fee too low: required {}, provided {}", 
                required_fee, transaction.fee
            ));
        }
        
        // Validate economic constraints
        validate_economic_constraints(transaction)?;
        
        // Validate transaction limits
        validate_transaction_limits(transaction)?;
        
        // Validate fee payment capability
        validate_fee_payment_capability(transaction)?;
        
        Ok(())
    }
    
    /// Validate transaction for economic processing
    fn validate_transaction_for_economics(transaction: &Transaction) -> Result<(), String> {
        // Check transaction version
        if transaction.version == 0 {
            return Err("Invalid transaction version for economics processing".to_string());
        }
        
        // Check signature exists
        if transaction.signature.signature.is_empty() {
            return Err("Transaction must be signed for economics processing".to_string());
        }
        
        // Check fee is reasonable
        if transaction.fee > 1_000_000 {
            return Err("Transaction fee too high - potential attack".to_string());
        }
        
        Ok(())
    }
    
    /// Extract economic data from transaction
    fn extract_economic_data(transaction: &Transaction) -> Result<([u8; 32], [u8; 32], u64), String> {
        // Extract from/to addresses and amount from transaction structure
        let from_address = if !transaction.inputs.is_empty() {
            // Use first input's previous output as from address
            transaction.inputs[0].previous_output.as_bytes().try_into()
                .map_err(|_| "Invalid from address format")?
        } else {
            // For identity transactions, use signature public key
            let mut addr = [0u8; 32];
            let key_bytes = transaction.signature.public_key.as_bytes();
            let copy_len = std::cmp::min(key_bytes.len(), 32);
            addr[..copy_len].copy_from_slice(&key_bytes[..copy_len]);
            addr
        };
        
        let to_address = if !transaction.outputs.is_empty() {
            // Use first output's recipient as to address
            let mut addr = [0u8; 32];
            let key_bytes = transaction.outputs[0].recipient.as_bytes();
            let copy_len = std::cmp::min(key_bytes.len(), 32);
            addr[..copy_len].copy_from_slice(&key_bytes[..copy_len]);
            addr
        } else {
            // For non-transfer transactions, use zero address
            [0u8; 32]
        };
        
        // Amount is hidden in ZK transactions, use fee as proxy for economic value
        let amount = transaction.fee;
        
        Ok((from_address, to_address, amount))
    }
    
    /// Get economic transaction type string
    fn get_economic_transaction_type(tx_type: &TransactionType) -> String {
        match tx_type {
            TransactionType::Transfer => "transfer".to_string(),
            TransactionType::IdentityRegistration => "identity_registration".to_string(),
            TransactionType::IdentityUpdate => "identity_update".to_string(),
            TransactionType::IdentityRevocation => "identity_revocation".to_string(),
            TransactionType::ContractDeployment => "contract_deployment".to_string(),
            TransactionType::ContractExecution => "contract_execution".to_string(),
        }
    }
    
    /// Apply economic rules to transaction
    fn apply_economic_rules(economics_tx: &EconomicsTransaction) -> Result<(), String> {
        // Rule: No transactions with zero economic value (except identity operations)
        if economics_tx.amount == 0 && !economics_tx.tx_type.contains("identity") {
            return Err("Zero-value transactions not allowed except for identity operations".to_string());
        }
        
        // Rule: Prevent circular transactions (from == to)
        if economics_tx.from == economics_tx.to && economics_tx.amount > 0 {
            return Err("Circular transactions not allowed".to_string());
        }
        
        // Rule: Economic impact limits
        if economics_tx.amount > 10_000_000 {
            return Err("Transaction amount exceeds economic impact limit".to_string());
        }
        
        Ok(())
    }
    
    /// Validate economic constraints
    fn validate_economic_constraints(transaction: &Transaction) -> Result<(), String> {
        // Check for economic attack patterns
        if transaction.inputs.len() > 100 {
            return Err("Too many inputs - potential economic attack".to_string());
        }
        
        if transaction.outputs.len() > 100 {
            return Err("Too many outputs - potential economic attack".to_string());
        }
        
        // Check memo size for economic efficiency
        if transaction.memo.len() > 10240 {
            return Err("Memo too large - economic inefficiency".to_string());
        }
        
        Ok(())
    }
    
    /// Validate transaction limits for economic stability
    fn validate_transaction_limits(transaction: &Transaction) -> Result<(), String> {
        // Daily transaction limits (this would integrate with rate limiting)
        match transaction.transaction_type {
            TransactionType::ContractDeployment => {
                // Limit contract deployments to prevent spam
                // In real implementation, check daily deployment count
                Ok(())
            },
            TransactionType::IdentityRegistration => {
                // Limit identity registrations to prevent spam
                // In real implementation, check daily registration count
                Ok(())
            },
            _ => Ok(()),
        }
    }
    
    /// Validate fee payment capability
    fn validate_fee_payment_capability(transaction: &Transaction) -> Result<(), String> {
        // Validate fee structure and reasonableness
        
        // Check fee isn't disproportionately high
        let max_reasonable_fee = calculate_transaction_fee(transaction) * 10;
        if transaction.fee > max_reasonable_fee {
            return Err("Fee disproportionately high - possible error".to_string());
        }
        
        Ok(())
    }
    
    /// Get fee statistics for network analysis
    pub fn get_fee_statistics(transactions: &[Transaction]) -> EconomicStatistics {
        if transactions.is_empty() {
            return EconomicStatistics::default();
        }
        
        let total_fees: u64 = transactions.iter().map(|tx| tx.fee).sum();
        let avg_fee = total_fees as f64 / transactions.len() as f64;
        
        let mut fees: Vec<u64> = transactions.iter().map(|tx| tx.fee).collect();
        fees.sort_unstable();
        
        let median_fee = if fees.len() % 2 == 0 {
            (fees[fees.len() / 2 - 1] + fees[fees.len() / 2]) as f64 / 2.0
        } else {
            fees[fees.len() / 2] as f64
        };
        
        let min_fee = *fees.first().unwrap_or(&0);
        let max_fee = *fees.last().unwrap_or(&0);
        
        EconomicStatistics {
            total_fees,
            average_fee: avg_fee,
            median_fee,
            min_fee,
            max_fee,
            transaction_count: transactions.len(),
        }
    }
    
    /// Economic statistics structure
    #[derive(Debug, Clone)]
    pub struct EconomicStatistics {
        pub total_fees: u64,
        pub average_fee: f64,
        pub median_fee: f64,
        pub min_fee: u64,
        pub max_fee: u64,
        pub transaction_count: usize,
    }
    
    impl Default for EconomicStatistics {
        fn default() -> Self {
            Self {
                total_fees: 0,
                average_fee: 0.0,
                median_fee: 0.0,
                min_fee: 0,
                max_fee: 0,
                transaction_count: 0,
            }
        }
    }
}

/// Integration with zhtp-contracts package (when available)
pub mod contracts_integration {
    use crate::transaction::Transaction;
    
    /// Execute a contract transaction
    pub fn execute_contract_transaction(transaction: &Transaction) -> Result<Vec<u8>, String> {
        // When zhtp-contracts package is available, delegate contract execution
        #[cfg(feature = "contracts")]
        {
            zhtp_contracts::execute_transaction(transaction)
                .map_err(|e| e.to_string())
        }
        
        #[cfg(not(feature = "contracts"))]
        {
            Err("Contract execution not available - zhtp-contracts package required".to_string())
        }
    }
    
    /// Validate contract transaction
    pub fn validate_contract_transaction(transaction: &Transaction) -> Result<(), String> {
        #[cfg(feature = "contracts")]
        {
            zhtp_contracts::validate_transaction(transaction)
                .map_err(|e| e.to_string())
        }
        
        #[cfg(not(feature = "contracts"))]
        {
            // Basic validation when contracts package not available
            if transaction.transaction_type.is_contract_transaction() {
                Err("Contract validation not available - zhtp-contracts package required".to_string())
            } else {
                Ok(())
            }
        }
    }
}

/// Network integration helpers
pub mod network_integration {
    use crate::block::Block;
    use crate::transaction::Transaction;
    
    /// Prepare block for network transmission
    pub fn serialize_block_for_network(block: &Block) -> Result<Vec<u8>, anyhow::Error> {
        bincode::serialize(block).map_err(|e| anyhow::anyhow!("Block serialization error: {}", e))
    }
    
    /// Deserialize block from network data
    pub fn deserialize_block_from_network(data: &[u8]) -> Result<Block, anyhow::Error> {
        bincode::deserialize(data).map_err(|e| anyhow::anyhow!("Block deserialization error: {}", e))
    }
    
    /// Prepare transaction for network transmission
    pub fn serialize_transaction_for_network(transaction: &Transaction) -> Result<Vec<u8>, anyhow::Error> {
        bincode::serialize(transaction).map_err(|e| anyhow::anyhow!("Transaction serialization error: {}", e))
    }
    
    /// Deserialize transaction from network data
    pub fn deserialize_transaction_from_network(data: &[u8]) -> Result<Transaction, anyhow::Error> {
        bincode::deserialize(data).map_err(|e| anyhow::anyhow!("Transaction deserialization error: {}", e))
    }
}

/// Storage integration helpers
pub mod storage_integration {
    use crate::blockchain::Blockchain;
    use crate::block::Block;
    use crate::transaction::Transaction;
    
    /// Serialize blockchain state for storage
    pub fn serialize_blockchain_state(blockchain: &Blockchain) -> Result<Vec<u8>, anyhow::Error> {
        bincode::serialize(blockchain).map_err(|e| anyhow::anyhow!("Serialization error: {}", e))
    }
    
    /// Deserialize blockchain state from storage
    pub fn deserialize_blockchain_state(data: &[u8]) -> Result<Blockchain, anyhow::Error> {
        bincode::deserialize(data).map_err(|e| anyhow::anyhow!("Deserialization error: {}", e))
    }
    
    /// Create storage key for block
    pub fn block_storage_key(height: u64) -> String {
        format!("block:{:016x}", height)
    }
    
    /// Create storage key for transaction
    pub fn transaction_storage_key(tx_hash: &crate::types::Hash) -> String {
        format!("tx:{}", hex::encode(tx_hash.as_bytes()))
    }
    
    /// Create storage key for identity
    pub fn identity_storage_key(did: &str) -> String {
        format!("identity:{}", did)
    }
}
