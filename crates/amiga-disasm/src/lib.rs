//! MC68000 reverse-engineering support: recursive control-flow analysis and
//! text listings, layered on the external `m68000` instruction decoder.
//!
//! [`analyze`] / [`analyze_entries`] follow control flow from entry points and
//! return a [`ControlFlowAnalysis`]; [`listing::render`] turns that into a
//! labelled assembly listing, and [`listing::linear`] does a plain sweep.

pub mod abi;
pub mod access;
pub mod callgraph;
pub mod constants;
pub mod control_flow;
pub mod data;
pub(crate) mod dataflow;
pub mod derived;
pub mod execute;
pub mod fd;
pub mod fixed_point;
pub mod function;
pub mod globals;
pub mod listing;
pub mod lvo;
pub mod pointer;
pub mod report;
pub mod resolution;
pub mod select;
pub mod slice;
pub mod summary;
pub mod xref;

pub use abi::{AbiArgument, ArgumentType, NamedConstant};
pub use access::{AccessForm, RegisterAccess, register_accesses};
pub use callgraph::{CallGraph, CallGraphEdge, CallGraphNode, callgraph, callgraph_from_edges};
pub use constants::{
    ConstantValue, RegisterKind, Unresolved, ValueOptions, constant_before, parse_register,
};
pub use control_flow::{
    CallEdge, ControlFlowAnalysis, DecodedInstruction, ExternalFlow, ExternalKind, FlowEdge,
    FlowKind, FlowOptions, Rebase, Relocation, Relocations, UnresolvedFlow, analyze,
    analyze_entries, analyze_entries_cancellable, analyze_entries_with,
};
pub use data::{
    DataPreview, DataRegion, DataScan, DisputedTarget, MAX_DATA_REGION, MAX_PREVIEW_TEXT,
    MAX_PREVIEW_VALUES, TargetConflict,
};
pub use derived::{DerivedAccess, DerivedTarget, derived_accesses};
pub use execute::{
    Access, AccessSource, Breakpoints, Bus, CpuContext, Device, DeviceAccess, DeviceBus, Execution,
    Fault, Host, HostAction, HostChain, HostMemory, InterruptDelivery, InterruptFrame,
    InterruptHandler, InterruptSchedule, Memory, MemoryAccessEvent, MemoryError, MemoryWrite,
    NoHost, Register, RegisterDelta, RegisterFile, RunOptions, ScheduledInterrupt, Step,
    StopReason, TouchedRegion, WatchAccess, Watchpoint, changed_regions, run, run_with_host,
    touched_regions,
};
pub use fixed_point::{
    ClampHint, ClampKind, FixedPointHint, FixedPointKind, FixedPointScale, clamp_hints,
    fixed_point_hints, fixed_point_scales,
};
pub use function::{
    FrameStyle, FunctionInput, FunctionOutput, FunctionRegister, FunctionReturn, FunctionSignature,
    RegisterLanes, StackSlot, StackSlotKind, function_signatures,
};
pub use globals::{AbsoluteAccess, AccessKind, GlobalAccess, absolute_accesses, global_accesses};
pub use listing::{Coverage, DisasmError, SweptInstruction, coverage, linear, render, sweep};
pub use lvo::{
    Library, LibraryCall, infer_libraries, infer_library_candidates, is_library_call_mode,
    library_call, lvo_name,
};
pub use pointer::{BlockAddress, PointerBase, PointerWrite, pointer_relative_writes};
pub use report::{
    CallArgument, CollectOptions, Confidence, ConflictCandidate, Evidence, Fact, FactKind,
    LvoEntry, MAX_XREF_SITES, MemoryAddressing, Producer, SCHEMA_VERSION, XrefVia, collect,
    index_by_subject, private_suffix, referenced_by,
};
pub use resolution::{Description, ResolutionStats};
pub use select::{Category, Exclusions, Filter, Filtered, Selection, categories};
pub use slice::{Location, Slice, SliceInput, SliceSeed, SliceStep, SliceStop, slice};
pub use summary::{Completeness, FunctionSummary, LibraryCallSummary, summarize};
pub use xref::{RefKind, Reference, references};
