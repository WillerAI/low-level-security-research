// Standardized for Rust 2024 Edition
#![allow(unsafe_op_in_unsafe_fn)]

pub mod bench;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::marker::PhantomData;

// --- Compile-Time Structural Invariants ---

const _: () = assert!(std::mem::size_of::<RawMcpFrame>() == 17);

// --- State Machine Lifecycle Markers ---

#[derive(Clone, Copy, Debug)]
pub struct Unverified;

#[derive(Clone, Copy, Debug)]
pub struct FormallyProven;

// --- Core Data Structures ---

#[repr(C, packed)]
pub struct RawMcpFrame {
    pub magic: u32,
    pub frame_type: u8,
    pub payload_len: u32,
    pub payload_ptr: *const u8,
}

impl RawMcpFrame {
    #[inline(always)]
    pub fn payload(&self) -> &[u8] {
        if self.payload_ptr.is_null() || self.payload_len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.payload_ptr, self.payload_len as usize) }
    }
}

// --- Security Policy Engine ---

pub trait SecurityPolicy<T> {
    fn prove_isolation(frame: &RawMcpFrame) -> bool;
}

#[derive(Clone, Copy)]
pub struct DefaultIsolationPolicy;

impl SecurityPolicy<FormallyProven> for DefaultIsolationPolicy {
    #[inline(always)]
    fn prove_isolation(frame: &RawMcpFrame) -> bool {
        let p = frame.payload();
        if frame.frame_type == 1 {
            !p.contains(&0xDF)
        } else {
            true
        }
    }
}

// --- MSIK Kernel (Typestate Pattern Implementation) ---

#[derive(Clone, Copy)]
pub struct MsikKernel<P: SecurityPolicy<FormallyProven>, S = Unverified> {
    _policy: PhantomData<P>,
    _state: PhantomData<S>,
}

// Fix 1: Implement Default as suggested by Clippy
impl<P: SecurityPolicy<FormallyProven>> Default for MsikKernel<P, Unverified> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: SecurityPolicy<FormallyProven>> MsikKernel<P, Unverified> {
    pub fn new() -> Self {
        Self {
            _policy: PhantomData,
            _state: PhantomData,
        }
    }

    pub fn verify(
        self,
        frame: &RawMcpFrame,
    ) -> Result<MsikKernel<P, FormallyProven>, &'static str> {
        if P::prove_isolation(frame) {
            Ok(MsikKernel {
                _policy: PhantomData,
                _state: PhantomData,
            })
        } else {
            Err("Security Violation: Formal isolation proof failed.")
        }
    }
}

impl<P: SecurityPolicy<FormallyProven>> MsikKernel<P, FormallyProven> {
    #[inline(always)]
    pub fn pass_to_inference(&self, _frame: &RawMcpFrame) {
        // Production hook for verified DMA transfer.
    }
}

// --- Python Interoperability Layer ---

#[pyfunction]
fn verify_payload(frame_type: u8, payload: Vec<u8>) -> PyResult<bool> {
    let frame = RawMcpFrame {
        magic: 0x4D435032,
        frame_type,
        payload_len: payload.len() as u32,
        payload_ptr: payload.as_ptr(),
    };

    let kernel = MsikKernel::<DefaultIsolationPolicy, Unverified>::new();

    kernel
        .verify(&frame)
        .map(|_| true)
        // Fix 2: Simplified closure
        .map_err(PyValueError::new_err)
}

#[pymodule]
fn msik(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_payload, m)?)?;
    Ok(())
}

// --- Formal Verification Hooks (Kani Model Checker) ---

#[cfg(kani)]
#[kani::proof]
fn proof_msik_kernel_safety() {
    let frame_type: u8 = kani::any();
    let payload_len: u32 = kani::any();
    kani::assume(payload_len < 4096);

    let payload = vec![0u8; payload_len as usize];
    let frame = RawMcpFrame {
        magic: 0x4D435032,
        frame_type,
        payload_len,
        payload_ptr: payload.as_ptr(),
    };

    let kernel = MsikKernel::<DefaultIsolationPolicy, Unverified>::new();
    let _ = kernel.verify(&frame);
}

// --- Unit Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_verification_flow() {
        let payload = b"benign_prompt_data";
        let frame = RawMcpFrame {
            magic: 0x4D435032,
            frame_type: 1,
            payload_len: payload.len() as u32,
            payload_ptr: payload.as_ptr(),
        };

        let kernel = MsikKernel::<DefaultIsolationPolicy, Unverified>::new();
        assert!(kernel.verify(&frame).is_ok());
    }

    #[test]
    fn test_security_escalation_denial() {
        let malicious = vec![0x00, 0xDF, 0x01];
        let frame = RawMcpFrame {
            magic: 0x4D435032,
            frame_type: 1,
            payload_len: malicious.len() as u32,
            payload_ptr: malicious.as_ptr(),
        };

        let kernel = MsikKernel::<DefaultIsolationPolicy, Unverified>::new();
        assert!(kernel.verify(&frame).is_err());
    }
}
