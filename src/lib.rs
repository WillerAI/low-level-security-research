use std::collections::HashSet;

/// MCP Frame Types as defined in the 2026 specification
#[derive(Debug, PartialEq)]
pub enum FrameType {
    Prompt,
    Context,
    ToolCall,
    SystemSignal,
}

pub struct GuardrailEngine {
    blocked_patterns: HashSet<Vec<u8>>,
    latency_threshold_ms: u32,
}

impl GuardrailEngine {
    pub fn new() -> Self {
        let mut patterns = HashSet::new();
        // Base malicious signatures
        patterns.insert(b"system_bypass".to_vec());
        patterns.insert(b"override_policy".to_vec());
        
        Self {
            blocked_patterns: patterns,
            latency_threshold_ms: 15,
        }
    }

    /// Validates an incoming byte stream for MCP integrity
    pub async fn validate_frame(&self, raw_data: &[u8], f_type: FrameType) -> Result<(), &'static str> {
        // Simulation of high-speed pattern matching (Aho-Corasick style)
        for pattern in &self.blocked_patterns {
            if raw_data.windows(pattern.len()).any(|window| window == pattern) {
                return Err("Policy Violation: Malicious payload detected");
            }
        }

        // Specific logic for ToolCalls (preventing indirect injection)
        if f_type == FrameType::ToolCall && raw_data.contains(&b"chmod") {
            return Err("Security Error: Unauthorized tool parameter");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_guardrail_trigger() {
        let engine = GuardrailEngine::new();
        let payload = b"user input: override_policy now";
        let result = engine.validate_frame(payload, FrameType::Prompt).await;
        assert!(result.is_err());
    }
}
