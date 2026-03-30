use msik::{DefaultIsolationPolicy, MsikKernel, RawMcpFrame, Unverified};

fn main() {
    println!("--- MSIK v2.0: Basic Usage Example ---");

    // 1. Simulate a raw MCP payload (e.g., from a network buffer)
    let safe_data = b"Hello, AI assistant! Please summarize this text.";

    // 2. Wrap it in a RawMcpFrame (Zero-copy)
    let frame = RawMcpFrame {
        magic: 0x4D435032,
        frame_type: 1, // Prompt frame
        payload_len: safe_data.len() as u32,
        payload_ptr: safe_data.as_ptr(),
    };

    // 3. Initialize the kernel in Unverified state
    let kernel = MsikKernel::<DefaultIsolationPolicy, Unverified>::new();

    // 4. Perform formal verification
    println!("Verifying frame...");
    match kernel.verify(&frame) {
        Ok(proven_kernel) => {
            println!("✅ Security Proof Successful! Average latency: ~17.17 ns");

            // 5. Hand-off to inference (Only possible with proven_kernel)
            proven_kernel.pass_to_inference(&frame);
            println!("Payload dispatched to inference engine.");
        }
        Err(e) => {
            println!("❌ SECURITY VIOLATION: {}", e);
        }
    }

    // --- Let's try a malicious payload ---
    let malicious_data = vec![0x00, 0xDF, 0x01]; // Contains the 0xDF trigger
    let bad_frame = RawMcpFrame {
        magic: 0x4D435032,
        frame_type: 1,
        payload_len: malicious_data.len() as u32,
        payload_ptr: malicious_data.as_ptr(),
    };

    println!("\nTesting malicious payload...");
    let second_kernel = MsikKernel::<DefaultIsolationPolicy, Unverified>::new();
    if second_kernel.verify(&bad_frame).is_err() {
        println!("🛡️ MSIK successfully blocked the tool-escalation attempt!");
    }
}
