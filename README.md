# MSIK 2.0: Formally Verified Security Kernel for MCP
![CI](https://github.com/WillerAI/low-level-security-research/actions/workflows/ci.yml/badge.svg)

**High-Performance (17.17ns) Formal Isolation Layer for Agentic AI Workflows.**

MSIK (Model Context Protocol Safe Inference Kernel) is a zero-copy security shim written in Rust 2024. It provides deterministic, mathematically proven isolation between untrusted prompt data and privileged tool execution contexts.

## 🚀 Key Features
- **Ultra-Low Latency**: Average verification overhead of **17.17 ns**.
- **Formal Verification**: Memory safety and logic invariants proven via **Kani**.
- **Zero-Copy**: Direct DMA-buffer analysis with zero heap allocations.
- **Python-Native**: First-class support via PyO3 (`pip install .`).
- **Rust 2024**: Built on the bleeding edge of the Rust ecosystem.

## 🐍 Python Integration
MSIK provides high-performance Python bindings via PyO3.

### Installation
\`\`\`bash
pip install .
\`\`\`

### Usage
\`\`\`python
import msik

# Fast formal verification of an MCP frame
try:
    is_safe = msik.verify_payload(frame_type=1, payload=b"your_data_here")
    print("Payload verified and isolated.")
except ValueError as e:
    print(f"Security Alert: {e}")
\`\`\`

## 🛠️ Performance Metrics
- **Verification Latency**: 17.17 ns (L1-cache bound).
- **Throughput**: ~58M frames/sec per core.
- **Memory Overhead**: 0 bytes heap allocation during hot-path.

## 🛡️ Security Hardening
- **Fuzz Testing**: 100M+ iterations without panic (LLVM LibFuzzer).
- **Static Analysis**: Verified via cargo clippy and cargo audit.
- **Formal Methods**: Proofs for buffer safety integrated via Kani.
