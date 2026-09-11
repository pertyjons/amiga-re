//! `hardware.register.list` — the custom-chip register map this build carries.
//!
//! This operation reads no source: it returns hardware knowledge, including register
//! names and offsets from the custom base. Keeping that mapping in the operation API
//! avoids duplicating register tables in callers.
//!
//! Both frames travel: the offset a listing shows and the absolute address a
//! real machine uses. Deriving one from the other separately in every consumer
//! is exactly the arithmetic this layer exists to do once.

use crate::diagnostics::Diagnostic;
use crate::protocol::Status;
use crate::request::OperationName;
use crate::response::{
    HardwareRegister, HardwareRegisterListResult, OperationOutcome, OperationResult,
};

pub(crate) fn run(diagnostics: Vec<Diagnostic>, digest: String) -> OperationOutcome {
    let result = HardwareRegisterListResult {
        custom_base: amiga_hw::CUSTOM_BASE,
        registers: amiga_hw::known_registers()
            .into_iter()
            .map(|(offset, name)| HardwareRegister {
                offset,
                address: amiga_hw::CUSTOM_BASE.saturating_add(u32::from(offset)),
                name,
            })
            .collect(),
    };
    OperationOutcome {
        operation: OperationName::HardwareRegisterList,
        status: Status::Success,
        diagnostics,
        normalized_request_sha256: Some(digest),
        result: Some(OperationResult::HardwareRegisterList(result)),
    }
}
