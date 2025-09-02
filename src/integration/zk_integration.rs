//! ZK Integration Module  
//! Re-exports from lib-proofs for blockchain use

pub use lib_proofs::{
    ZkTransactionProof,
    transaction::verification::verify_transaction,
    types::{ZkProof, VerificationResult},
};

// Helper functions for backwards compatibility
pub fn verify_transaction_proof(proof: &ZkTransactionProof) -> Result<bool, String> {
    verify_transaction(proof).map_err(|e| e.to_string())
}

pub fn is_valid_proof_structure(proof: &ZkTransactionProof) -> bool {
    println!("🚨 DEBUG: Checking proof structure...");
    println!("🚨 DEBUG: amount_proof.is_empty() = {}", proof.amount_proof.is_empty());
    println!("🚨 DEBUG: balance_proof.is_empty() = {}", proof.balance_proof.is_empty());
    println!("🚨 DEBUG: nullifier_proof.is_empty() = {}", proof.nullifier_proof.is_empty());
    
    println!("🚨 DEBUG: amount_proof.proof_system = '{}'", proof.amount_proof.proof_system);
    println!("🚨 DEBUG: amount_proof.plonky2_proof.is_some() = {}", proof.amount_proof.plonky2_proof.is_some());
    
    // Check if the proof has the required fields
    let valid = !proof.amount_proof.is_empty() && 
               !proof.balance_proof.is_empty() &&
               !proof.nullifier_proof.is_empty();
    
    println!("🚨 DEBUG: Overall proof structure valid = {}", valid);
    valid
}
