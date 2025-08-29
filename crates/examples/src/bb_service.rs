use reqwest::{Client, Error as ReqwestError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Error types for bb-service operations
#[derive(Debug, thiserror::Error)]
pub enum BbServiceError {
    #[error("Request failed: {0}")]
    Request(#[from] ReqwestError),
    #[error("Service error: {0}")]
    Service(String),
    #[error("Invalid response format")]
    InvalidResponse,
}

/// Represents a compiled Noir circuit as arbitrary JSON
pub type CompiledCircuit = serde_json::Value;

/// Input map for circuit execution
pub type InputMap = HashMap<String, serde_json::Value>;

/// Proof data structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofData {
    pub proof: Vec<u8>,
    #[serde(rename = "publicInputs")]
    pub public_inputs: Vec<serde_json::Value>,
}

/// Request structure for proof generation
#[derive(Debug, Serialize)]
struct ProveRequest {
    circuit: CompiledCircuit,
    input: InputMap,
}

/// Request structure for proof verification  
#[derive(Debug, Serialize)]
struct VerifyRequest {
    circuit: CompiledCircuit,
    proof: ProofData,
}

/// Response structure for proof generation
#[derive(Debug, Deserialize)]
struct ProveResponse {
    message: String,
    proof: ProofData,
}

/// Response structure for proof verification
#[derive(Debug, Deserialize)]
struct VerifyResponse {
    message: String,
    #[serde(rename = "isValid")]
    is_valid: bool,
}

/// Error response structure
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

/// Client for interacting with the bb-service
pub struct BbServiceClient {
    client: Client,
    base_url: String,
}

impl BbServiceClient {
    /// Create a new bb-service client
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    /// Create a new bb-service client with default localhost URL
    pub fn new_localhost() -> Self {
        Self::new("http://localhost:3000".to_string())
    }

    /// Generate a proof using the bb-service
    pub async fn generate_proof(
        &self,
        circuit: CompiledCircuit,
        input: InputMap,
    ) -> Result<ProofData, BbServiceError> {
        let request = ProveRequest { circuit, input };
        
        let response = self
            .client
            .post(&format!("{}/prove", self.base_url))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            let prove_response: ProveResponse = response.json().await?;
            Ok(prove_response.proof)
        } else {
            let error_response: ErrorResponse = response
                .json()
                .await
                .map_err(|_| BbServiceError::InvalidResponse)?;
            Err(BbServiceError::Service(format!(
                "{}: {}",
                error_response.error,
                error_response.details.unwrap_or_default()
            )))
        }
    }

    /// Verify a proof using the bb-service
    pub async fn verify_proof(
        &self,
        circuit: CompiledCircuit,
        proof: ProofData,
    ) -> Result<bool, BbServiceError> {
        let request = VerifyRequest { circuit, proof };
        
        let response = self
            .client
            .post(&format!("{}/verify", self.base_url))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            let verify_response: VerifyResponse = response.json().await?;
            Ok(verify_response.is_valid)
        } else {
            let error_response: ErrorResponse = response
                .json()
                .await
                .map_err(|_| BbServiceError::InvalidResponse)?;
            Err(BbServiceError::Service(format!(
                "{}: {}",
                error_response.error,
                error_response.details.unwrap_or_default()
            )))
        }
    }

    /// Check if the bb-service is healthy/reachable
    pub async fn health_check(&self) -> Result<bool, BbServiceError> {
        let response = self
            .client
            .get(&format!("{}/health", self.base_url))
            .send()
            .await?;
        
        Ok(response.status().is_success())
    }
}
