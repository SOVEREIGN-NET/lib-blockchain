//! Transaction type definitions
//!
//! Defines the types of transactions supported by the ZHTP blockchain.
//! Note: Identity transaction processing is handled by integration with lib-identity package.

use serde::{Serialize, Deserialize};

/// Transaction types supported by ZHTP blockchain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TransactionType {
    /// Standard value transfer between accounts
    Transfer,
    /// Identity registration on blockchain (delegates to lib-identity)
    IdentityRegistration,
    /// Identity update/modification (delegates to lib-identity)  
    IdentityUpdate,
    /// Identity revocation (delegates to lib-identity)
    IdentityRevocation,
    /// Smart contract deployment (delegates to lib-contracts)
    ContractDeployment,
    /// Smart contract execution (delegates to lib-contracts)
    ContractExecution,
}

impl TransactionType {
    /// Check if this transaction type relates to identity management
    pub fn is_identity_transaction(&self) -> bool {
        matches!(self, 
            TransactionType::IdentityRegistration |
            TransactionType::IdentityUpdate |
            TransactionType::IdentityRevocation
        )
    }

    /// Check if this transaction type relates to smart contracts
    pub fn is_contract_transaction(&self) -> bool {
        matches!(self,
            TransactionType::ContractDeployment |
            TransactionType::ContractExecution
        )
    }

    /// Check if this is a standard transfer transaction
    pub fn is_transfer(&self) -> bool {
        matches!(self, TransactionType::Transfer)
    }

    /// Get a human-readable description of the transaction type
    pub fn description(&self) -> &'static str {
        match self {
            TransactionType::Transfer => "Standard value transfer",
            TransactionType::IdentityRegistration => "Identity registration",
            TransactionType::IdentityUpdate => "Identity update",
            TransactionType::IdentityRevocation => "Identity revocation",
            TransactionType::ContractDeployment => "Smart contract deployment",
            TransactionType::ContractExecution => "Smart contract execution",
        }
    }

    /// Get the transaction type as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionType::Transfer => "transfer",
            TransactionType::IdentityRegistration => "identity_registration",
            TransactionType::IdentityUpdate => "identity_update",
            TransactionType::IdentityRevocation => "identity_revocation",
            TransactionType::ContractDeployment => "contract_deployment",
            TransactionType::ContractExecution => "contract_execution",
        }
    }

    /// Parse transaction type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "transfer" => Some(TransactionType::Transfer),
            "identity_registration" => Some(TransactionType::IdentityRegistration),
            "identity_update" => Some(TransactionType::IdentityUpdate),
            "identity_revocation" => Some(TransactionType::IdentityRevocation),
            "contract_deployment" => Some(TransactionType::ContractDeployment),
            "contract_execution" => Some(TransactionType::ContractExecution),
            _ => None,
        }
    }
}
