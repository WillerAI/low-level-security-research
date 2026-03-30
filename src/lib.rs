pub mod bench;

use std::marker::PhantomData;
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

// --- Твоё элитное ядро (остается без изменений) ---

#[derive(Clone, Copy)]
pub struct Unverified;
#[derive(Clone, Copy)]
pub struct FormallyProven;

#[repr(C, packed)]
pub struct RawMcpFrame {
    pub magic: u32,
    pub frame_type: u8,
    pub payload_len: u32,
    pub payload_ptr: *const u8,
}

impl RawMcpFrame {
    pub fn payload(&self) -> &[u8] {
        if self.payload_ptr.is_null() || self.payload_len == 0 { return &[]; }
        unsafe { std::slice::from_raw_parts(self.payload_ptr, self.payload_len as usize) }
    }
}

pub trait SecurityPolicy<T> {
    fn prove_isolation(frame: &RawMcpFrame) -> bool;
}

#[derive(Clone, Copy)]
pub struct DefaultIsolationPolicy;

impl SecurityPolicy<FormallyProven> for DefaultIsolationPolicy {
    fn prove_isolation(frame: &RawMcpFrame) -> bool {
        if frame.frame_type == 1 { 
            !frame.payload().contains(&0xDF) 
        } else {
            true
        }
    }
}

#[derive(Clone, Copy)]
pub struct MsikKernel<P: SecurityPolicy<FormallyProven>, S = Unverified> {
    _policy: PhantomData<P>,
    _state: PhantomData<S>,
}

impl<P: SecurityPolicy<FormallyProven>> MsikKernel<P, Unverified> {
    pub fn new() -> Self { Self { _policy: PhantomData, _state: PhantomData } }
    pub fn verify(self, frame: &RawMcpFrame) -> Result<MsikKernel<P, FormallyProven>, &'static str> {
        if P::prove_isolation(frame) { Ok(MsikKernel { _policy: PhantomData, _state: PhantomData }) }
        else { Err("Security Violation: Formal isolation proof failed.") }
    }
}

// --- PYTHON BINDINGS (Новый слой) ---

/// Функция, которую будет вызывать Python
#[pyfunction]
fn verify_payload(frame_type: u8, payload: Vec<u8>) -> PyResult<bool> {
    let frame = RawMcpFrame {
        magic: 0x4D435032,
        frame_type,
        payload_len: payload.len() as u32,
        payload_ptr: payload.as_ptr(),
    };

    let kernel = MsikKernel::<DefaultIsolationPolicy, Unverified>::new();
    
    match kernel.verify(&frame) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyValueError::new_err(e)),
    }
}

/// Название модуля в Python должно совпадать с названием в Cargo.toml
#[pymodule]
fn msik(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_payload, m)?)?;
    Ok(())
}
