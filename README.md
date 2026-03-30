# MSIK: MCP-Safe-Inference-Kernel 🛡️

High-performance, low-latency guardrail shim for **Model Context Protocol (MCP)** traffic. 
Designed to intercept and validate token streams before they reach the inference engine.

## Features
- **Zero-copy validation**: Direct byte-stream analysis.
- **Async-first**: Built on Tokio for high-throughput environments.
- **Prompt Injection Defense**: Multi-layered heuristic for malicious payload detection.

## Usage
`msik` acts as a transparent proxy between the MCP client and the LLM server, ensuring that every frame complies with your safety policies.
