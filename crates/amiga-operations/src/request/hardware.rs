//! Arguments for the `hardware.*` operations: the custom-chip register map,
//! Copper lists, and the register and Copper references a routine makes.
use super::*;

/// Where the Copper list a patch routine writes into actually lives.
///
/// Its own source, because a loader routinely copies a template out of one file
/// and patches the copy: the code and the list it edits need not be the same
/// bytes. An absent source means the same one the code came from, which is the
/// common case and the only one that could be assumed.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CopperTemplate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocator>,
    /// Byte offset of the template within that source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// The absolute address the list is at when the routine runs, for a routine
    /// that loads that address as a constant instead of receiving it in the
    /// pointer register. Without it such a load is an unrelated address and
    /// every store after it is dropped; with it, a constant landing in the list
    /// establishes the base at the instruction that loaded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u32>,
}

/// Arguments for `hardware.copper.references`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CopperReferencesArguments {
    pub source: SourceLocator,
    /// CODE hunk holding the patch routine. Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// The patch routine's entry, as hunk offsets. Required: the pointer
    /// register's value is read *at* the entry, so without one there is no
    /// origin to measure the writes from.
    pub entries: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    /// Address register holding the runtime copy's base.
    pub pointer_register: u8,
    #[serde(default)]
    pub template: CopperTemplate,
    /// Also apply every immediate write and report the resulting list.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub apply: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_writes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_instructions: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl CopperReferencesArguments {
    #[must_use]
    pub fn new(source: impl Into<String>, entries: Vec<u32>, pointer_register: u8) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            entries,
            origin: None,
            pointer_register,
            template: CopperTemplate::default(),
            apply: false,
            maximum_writes: None,
            maximum_instructions: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }

    #[must_use]
    pub fn with_template(mut self, source: Option<String>, offset: u32) -> Self {
        self.template = CopperTemplate {
            source: source.map(SourceLocator::file),
            offset: Some(offset),
            address: self.template.address,
        };
        self
    }

    /// State where the list lives when the routine runs, so a constant load of
    /// that address establishes the base.
    #[must_use]
    pub const fn with_template_address(mut self, address: u32) -> Self {
        self.template.address = Some(address);
        self
    }

    #[must_use]
    pub const fn applying(mut self) -> Self {
        self.apply = true;
        self
    }
}

/// Arguments for `hardware.register.references`.
///
/// No subsystem filter. Unlike the string scan's `contains`, filtering here
/// decides nothing about *which* accesses survive a cap that a caller cannot
/// redo: every access names its subsystem, and narrowing to one is a display
/// choice over a list that is already complete.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterReferencesArguments {
    pub source: SourceLocator,
    /// CODE hunk to analyze. Defaults to hunk 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunk: Option<u32>,
    /// Where the traversal starts, as hunk offsets. Defaults to offset 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<u32>,
    /// The address the hunk is mapped at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_accesses: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl RegisterReferencesArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            hunk: None,
            entries: Vec::new(),
            origin: None,
            maximum_accesses: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn in_hunk(mut self, hunk: u32) -> Self {
        self.hunk = Some(hunk);
        self
    }

    #[must_use]
    pub fn from_entries(mut self, entries: Vec<u32>) -> Self {
        self.entries = entries;
        self
    }

    #[must_use]
    pub const fn mapped_at(mut self, origin: u32) -> Self {
        self.origin = Some(origin);
        self
    }
}

/// Arguments for `hardware.copper.scan`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CopperScanArguments {
    pub source: SourceLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_lists: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl CopperScanArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            maximum_lists: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn with_maximum_lists(mut self, lists: usize) -> Self {
        self.maximum_lists = Some(lists);
        self
    }
}

/// Arguments for `hardware.copper.decode`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CopperDecodeArguments {
    pub source: SourceLocator,
    /// Byte offset the Copper stream starts at. Nothing in an image marks one,
    /// so this is a claim about the bytes rather than something read from them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_instructions: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_input_bytes: Option<u64>,
}

impl CopperDecodeArguments {
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: SourceLocator::file(source),
            offset: None,
            maximum_instructions: None,
            maximum_input_bytes: None,
        }
    }

    #[must_use]
    pub const fn at_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Arguments for `hardware.register.list`.
///
/// It takes none. The custom-chip register map is knowledge this build carries,
/// not a question about any file — and an operation with no arguments is
/// exactly right for a capability whose answer depends on nothing but the
/// build. The empty struct exists so the request document has the same shape as
/// every other.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareRegisterListArguments {}

impl HardwareRegisterListArguments {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}
