use crate::{DefaultIsolationPolicy, MsikKernel, RawMcpFrame};
use std::time::Instant;

pub fn run_benchmark() {
    let payload = b"standard_inference_request_0123456789";
    let frame = RawMcpFrame {
        magic: 0x4D435032,
        frame_type: 1,
        payload_len: payload.len() as u32,
        payload_ptr: payload.as_ptr(),
    };

    let kernel = MsikKernel::<DefaultIsolationPolicy>::new();
    let iterations = 1_000_000;

    println!("--- MSIK Performance Benchmark ---");
    println!("Processing {} iterations...", iterations);

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = std::hint::black_box(kernel.verify(&frame));
    }
    let duration = start.elapsed();
    let avg_ns = duration.as_nanos() as f64 / iterations as f64;

    println!("Total execution time: {:?}", duration);
    println!("Average latency: {:.2} ns per frame", avg_ns);
    println!("----------------------------------");
}
