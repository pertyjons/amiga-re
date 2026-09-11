//! What a library vector's arguments *are*: which register carries each one,
//! and what its bits mean.
//!
//! An fd table says a vector takes `(byteSize)(d0)`; it does not say that `d1`
//! of `AllocMem` is a bitfield whose `$10002` means `MEMF_CHIP|MEMF_CLEAR`.
//! That last step is what turns a resolved constant from a number a reader has
//! to look up into the thing the code actually asked for.
//!
//! ## Curated, small, and sourced
//!
//! Argument registers and constant values were checked against the Exec/DOS
//! FD files and `exec/memory.h` / `dos/dos.h` in
//! [NDK 3.2 R4](https://aminet.net/package/dev/misc/NDK3.2). Exact source hashes
//! and comparison results are recorded in `docs/hardware-and-abi-references.md`.
//! Entries include V36 functions and are not an AmigaOS 1.x availability list.
//! The set is deliberately short: the vectors a program calls in its first
//! hundred instructions, where a wrong claim would
//! also be a *load-bearing* wrong claim. A vector missing from this table is
//! not a gap to be filled by guessing — a config-supplied fd table already
//! names arguments for anything, and only the type information below needs
//! this crate's confidence.
//!
//! ## Decoding is gated on the type, never on the value
//!
//! A constant is rendered symbolically only where this table says what the
//! argument is. `$10002` in an untyped register stays `0x10002`, because
//! reading it as memory flags would be inventing a type the code never
//! declared.

/// One named bit or value of an argument's type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedConstant {
    pub value: u32,
    pub name: &'static str,
}

/// What an argument register holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentType {
    /// Just a number: an address, a size, a count. Rendered as it was written.
    Raw,
    /// A bitfield, rendered as the `|`-joined names of the bits that are set,
    /// with any leftover bits shown as a number so nothing is silently
    /// dropped.
    Flags(&'static [NamedConstant]),
    /// A closed set of values, rendered as the matching name or the number
    /// when it matches none.
    Enumeration(&'static [NamedConstant]),
}

/// One argument of a curated vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiArgument {
    pub name: &'static str,
    /// The register in fd spelling: `d0`, `a1`, …
    pub register: &'static str,
    pub kind: ArgumentType,
}

/// `exec/memory.h` allocation flags.
const MEMF: &[NamedConstant] = &[
    NamedConstant {
        value: 1 << 0,
        name: "MEMF_PUBLIC",
    },
    NamedConstant {
        value: 1 << 1,
        name: "MEMF_CHIP",
    },
    NamedConstant {
        value: 1 << 2,
        name: "MEMF_FAST",
    },
    NamedConstant {
        value: 1 << 8,
        name: "MEMF_LOCAL",
    },
    NamedConstant {
        value: 1 << 9,
        name: "MEMF_24BITDMA",
    },
    NamedConstant {
        value: 1 << 10,
        name: "MEMF_KICK",
    },
    NamedConstant {
        value: 1 << 16,
        name: "MEMF_CLEAR",
    },
    NamedConstant {
        value: 1 << 17,
        name: "MEMF_LARGEST",
    },
    NamedConstant {
        value: 1 << 18,
        name: "MEMF_REVERSE",
    },
    NamedConstant {
        value: 1 << 19,
        name: "MEMF_TOTAL",
    },
    NamedConstant {
        value: 1 << 31,
        name: "MEMF_NO_EXPUNGE",
    },
];

/// `dos/dos.h` access modes for `Open`.
const DOS_MODE: &[NamedConstant] = &[
    NamedConstant {
        value: 1004,
        name: "MODE_READWRITE",
    },
    NamedConstant {
        value: 1005,
        name: "MODE_OLDFILE",
    },
    NamedConstant {
        value: 1006,
        name: "MODE_NEWFILE",
    },
];

/// `dos/dos.h` seek modes.
const DOS_SEEK: &[NamedConstant] = &[
    NamedConstant {
        value: -1_i32 as u32,
        name: "OFFSET_BEGINNING",
    },
    NamedConstant {
        value: 0,
        name: "OFFSET_CURRENT",
    },
    NamedConstant {
        value: 1,
        name: "OFFSET_END",
    },
];

const fn raw(name: &'static str, register: &'static str) -> AbiArgument {
    AbiArgument {
        name,
        register,
        kind: ArgumentType::Raw,
    }
}

const fn flags(
    name: &'static str,
    register: &'static str,
    constants: &'static [NamedConstant],
) -> AbiArgument {
    AbiArgument {
        name,
        register,
        kind: ArgumentType::Flags(constants),
    }
}

const fn enumeration(
    name: &'static str,
    register: &'static str,
    constants: &'static [NamedConstant],
) -> AbiArgument {
    AbiArgument {
        name,
        register,
        kind: ArgumentType::Enumeration(constants),
    }
}

const ALLOC: &[AbiArgument] = &[raw("byteSize", "d0"), flags("requirements", "d1", MEMF)];
const FREE_MEM: &[AbiArgument] = &[raw("memoryBlock", "a1"), raw("byteSize", "d0")];
const FREE_VEC: &[AbiArgument] = &[raw("memoryBlock", "a1")];
const OPEN_LIBRARY: &[AbiArgument] = &[raw("libName", "a1"), raw("version", "d0")];
const CLOSE_LIBRARY: &[AbiArgument] = &[raw("library", "a1")];
const OPEN_DEVICE: &[AbiArgument] = &[
    raw("devName", "a0"),
    raw("unitNumber", "d0"),
    raw("ioRequest", "a1"),
    raw("flags", "d1"),
];
const IO_REQUEST: &[AbiArgument] = &[raw("ioRequest", "a1")];
const DOS_OPEN: &[AbiArgument] = &[raw("name", "d1"), enumeration("accessMode", "d2", DOS_MODE)];
const DOS_CLOSE: &[AbiArgument] = &[raw("file", "d1")];
const DOS_READ_WRITE: &[AbiArgument] =
    &[raw("file", "d1"), raw("buffer", "d2"), raw("length", "d3")];
const DOS_SEEK_ARGS: &[AbiArgument] = &[
    raw("file", "d1"),
    raw("position", "d2"),
    enumeration("mode", "d3", DOS_SEEK),
];

/// The curated argument list for one vector, or empty when this table does not
/// describe it.
///
/// `library` is the identity's own name (`exec.library`, `dos.library`), so a
/// vector offset is never read against the wrong library — the same LVO means
/// different things under different bases, which is the mistake this signature
/// shape exists to prevent.
#[must_use]
pub fn arguments(library: &str, lvo: i16) -> &'static [AbiArgument] {
    match (library, lvo) {
        ("exec.library", -198 | -684) => ALLOC,
        ("exec.library", -210) => FREE_MEM,
        ("exec.library", -690) => FREE_VEC,
        ("exec.library", -552) => OPEN_LIBRARY,
        ("exec.library", -414) => CLOSE_LIBRARY,
        ("exec.library", -444) => OPEN_DEVICE,
        ("exec.library", -450 | -456 | -462 | -468 | -474) => IO_REQUEST,
        ("dos.library", -30) => DOS_OPEN,
        ("dos.library", -36) => DOS_CLOSE,
        ("dos.library", -42 | -48) => DOS_READ_WRITE,
        ("dos.library", -66) => DOS_SEEK_ARGS,
        _ => &[],
    }
}

/// The type this table gives `register` of one vector, defaulting to raw.
#[must_use]
pub fn argument_type(library: &str, lvo: i16, register: &str) -> ArgumentType {
    arguments(library, lvo)
        .iter()
        .find(|argument| argument.register.eq_ignore_ascii_case(register))
        .map_or(ArgumentType::Raw, |argument| argument.kind)
}

/// Render `value` as its type reads it.
///
/// Unmatched bits are always shown. A flags word whose known names covered
/// only part of it would otherwise read as fully understood, which is exactly
/// the case where a reader most needs to look at the number.
#[must_use]
pub fn render(kind: ArgumentType, value: u32) -> String {
    match kind {
        ArgumentType::Raw => render_number(value),
        ArgumentType::Enumeration(constants) => constants
            .iter()
            .find(|constant| constant.value == value)
            .map_or_else(|| render_number(value), |constant| constant.name.to_owned()),
        ArgumentType::Flags(constants) => {
            let mut names = Vec::new();
            let mut remaining = value;
            for constant in constants {
                if value & constant.value == constant.value && constant.value != 0 {
                    names.push(constant.name);
                    remaining &= !constant.value;
                }
            }
            if names.is_empty() {
                return render_number(value);
            }
            if remaining != 0 {
                return format!("{}|{}", names.join("|"), render_number(remaining));
            }
            names.join("|")
        }
    }
}

/// Small values read better as decimal; anything larger is an address, a mask,
/// or a flag word, and reads better as hex.
fn render_number(value: u32) -> String {
    if value < 0x1_0000 {
        value.to_string()
    } else {
        format!("{value:#x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_flags_render_as_the_names_the_code_asked_for() {
        let kind = argument_type("exec.library", -198, "d1");
        assert_eq!(render(kind, (1 << 1) | (1 << 16)), "MEMF_CHIP|MEMF_CLEAR");
        assert_eq!(render(kind, 1 << 1), "MEMF_CHIP");
    }

    #[test]
    fn unknown_bits_are_shown_rather_than_dropped() {
        // A flags word that is only partly understood must not read as fully
        // understood: the leftover is exactly what a reader needs to see.
        let kind = argument_type("exec.library", -198, "d1");
        assert_eq!(render(kind, (1 << 1) | (1 << 5)), "MEMF_CHIP|32");
        // And a word with no known bit at all stays a number.
        assert_eq!(render(kind, 1 << 5), "32");
    }

    #[test]
    fn an_untyped_argument_is_never_decoded_as_flags() {
        // The same bits in `byteSize` are a size, not memory flags. Decoding
        // them would invent a type the code never declared.
        let kind = argument_type("exec.library", -198, "d0");
        assert_eq!(kind, ArgumentType::Raw);
        assert_eq!(render(kind, (1 << 1) | (1 << 16)), "0x10002");
    }

    #[test]
    fn the_same_lvo_under_two_libraries_is_two_different_vectors() {
        // -30 is dos.library/Open and graphics.library/BltBitMap; only the
        // one this table describes gets arguments.
        assert_eq!(arguments("dos.library", -30).len(), 2);
        assert!(arguments("graphics.library", -30).is_empty());
    }

    #[test]
    fn an_enumeration_falls_back_to_its_number() {
        let kind = argument_type("dos.library", -30, "d2");
        assert_eq!(render(kind, 1005), "MODE_OLDFILE");
        assert_eq!(render(kind, 7), "7");
    }

    #[test]
    fn every_curated_register_parses_as_a_register() {
        for (library, lvo) in [
            ("exec.library", -198),
            ("exec.library", -444),
            ("dos.library", -42),
            ("dos.library", -66),
        ] {
            for argument in arguments(library, lvo) {
                assert!(
                    crate::constants::parse_register(argument.register).is_some(),
                    "{library} {lvo}: {:?} is not a register",
                    argument.register
                );
            }
        }
    }
}
