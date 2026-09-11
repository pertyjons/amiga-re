//! Recovering a project object that needs a parser or a decoder.
//!
//! `amiga-project` describes how every object is recovered but implements none
//! of it: the format crate depends on no parser and no codec, so that a project
//! can be *described* by a build that cannot open every container it names. What
//! a build can actually recover is a capability, and a capability belongs to the
//! operation layer.
//!
//! This is the toolkit implementation of [`amiga_project::Recover`]. Keeping parser and
//! codec dispatch here lets the CLI and downstream tools verify projects through the
//! same operation API, including ADF members, LHA members, and decompressed objects.
//!
//! Every refusal names what it refused. A codec or container this build does not
//! implement must produce a stated reason, never a silently shorter report,
//! because a verification that only checked what it could reach and then said
//! "all good" would be worse than no verification.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::sync::Arc;

use amiga_project::document::{Codec, Selector};

/// Recovery over the parsers and decoders this build carries.
///
/// A `range` selector never arrives here: `amiga-project` takes those itself
/// rather than asking a caller for a dependency to do arithmetic.
#[derive(Debug)]
pub struct ContainerRecovery {
    maximum_output_bytes: usize,
    limits: crate::OperationLimits,
    remaining_steps: Cell<usize>,
    cached: RefCell<Option<CachedRecipe>>,
}

#[derive(Debug)]
struct CachedRecipe {
    key: String,
    exports: BTreeMap<String, Vec<u8>>,
}

impl ContainerRecovery {
    /// Build a recoverer that refuses decompressed output above `bytes`.
    #[must_use]
    pub fn new(bytes: u64) -> Self {
        Self::from_limits(crate::OperationLimits::default().with_maximum_output_bytes(bytes))
    }

    /// Recovery with a shared instruction budget for all sandbox derivations.
    #[must_use]
    pub fn from_limits(limits: crate::OperationLimits) -> Self {
        Self {
            maximum_output_bytes: usize::try_from(limits.maximum_output_bytes())
                .unwrap_or(usize::MAX),
            limits,
            remaining_steps: Cell::new(limits.maximum_sandbox_steps()),
            cached: RefCell::new(None),
        }
    }

    fn sandbox(
        &self,
        container: &[u8],
        export: &str,
        inputs: &BTreeMap<&str, &[u8]>,
        maximum_output_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        if inputs.is_empty() || inputs.len() > 16 {
            return Err("sandbox recipes require 1..=16 verified inputs".to_owned());
        }
        let total = inputs
            .values()
            .try_fold(0_u64, |sum, bytes| sum.checked_add(bytes.len() as u64))
            .ok_or("sandbox input byte count overflows")?;
        if total > self.limits.maximum_input_bytes().min(64 * 1024 * 1024) {
            return Err("sandbox recipe inputs exceed the byte budget".to_owned());
        }
        let pins: BTreeMap<_, _> = inputs
            .iter()
            .map(|(name, bytes)| (*name, amiga_core::sha256(bytes)))
            .collect();
        let key = amiga_core::sha256(
            serde_json::json!({
                "recipe": amiga_core::sha256(container), "inputs": pins,
            })
            .to_string()
            .as_bytes(),
        );
        if let Some(cached) = self
            .cached
            .borrow()
            .as_ref()
            .filter(|cached| cached.key == key)
        {
            if cached
                .exports
                .values()
                .try_fold(0_usize, |sum, bytes| sum.checked_add(bytes.len()))
                .is_none_or(|sum| sum > maximum_output_bytes)
            {
                return Err("cached sandbox exports exceed the output byte budget".to_owned());
            }
            return cached
                .exports
                .get(export)
                .cloned()
                .ok_or_else(|| format!("sandbox recipe has no export {export:?}"));
        }
        let call = crate::sandbox_recipe::SandboxRecipe::parse(container, self.limits)?;
        if !call.memory_exports.iter().any(|item| item.name == export) {
            return Err(format!("sandbox recipe has no export {export:?}"));
        }
        let output_bytes = call
            .memory_exports
            .iter()
            .try_fold(0_u64, |sum, item| sum.checked_add(u64::from(item.length)))
            .ok_or("sandbox export byte count overflows")?;
        if output_bytes > maximum_output_bytes as u64 {
            return Err("sandbox exports exceed the output byte budget".to_owned());
        }
        if !call.run.source.members.is_empty() {
            return Err("sandbox executable must be a direct verified input; derive container members as project objects first".to_owned());
        }
        // RAM accounting is shared with all direct calls in sandbox::prepare.
        let remaining = self
            .remaining_steps
            .get()
            .checked_sub(call.run.maximum_steps)
            .ok_or("sandbox derivations exceed the shared instruction budget")?;
        self.remaining_steps.set(remaining);
        let sources = inputs
            .iter()
            .map(|(name, bytes)| {
                crate::SourceName::parse(name)
                    .map(|name| crate::ResolvedSource::new(name, Arc::from(*bytes)))
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let resolver = crate::InMemorySourceResolver::holding(sources);
        let context = crate::ExecutionContext::new(&resolver).with_limits(self.limits);
        let mut diagnostics = Vec::new();
        let mut sink = crate::NoEvents;
        let called = crate::operations::sandbox::call(
            &call,
            &context,
            &mut diagnostics,
            &mut crate::BoundedSink::new(&mut sink),
        )
        .map_err(|d| format!("{d:?}"))?;
        if !diagnostics.is_empty() {
            return Err(format!(
                "sandbox derivation produced diagnostics: {diagnostics:?}"
            ));
        }
        if !called.record.returned {
            return Err(format!(
                "sandbox recipe did not return: {:?}",
                called.record.stop
            ));
        }
        let exports: BTreeMap<_, _> = called.exports.into_iter().collect();
        let bytes = exports
            .get(export)
            .cloned()
            .ok_or_else(|| format!("sandbox recipe has no export {export:?}"))?;
        *self.cached.borrow_mut() = Some(CachedRecipe { key, exports });
        Ok(bytes)
    }
}

impl Default for ContainerRecovery {
    fn default() -> Self {
        Self::new(crate::limits::DEFAULT_MAXIMUM_OUTPUT_BYTES)
    }
}

impl ContainerRecovery {
    fn recover_container(
        &self,
        selector: &Selector,
        container: &[u8],
        maximum_output_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        match selector {
            Selector::Adf { path, .. } => {
                let image = amiga_adf::Image::open(container).map_err(|error| error.to_string())?;
                let entry = image
                    .entries()
                    .iter()
                    .find(|entry| volume_path(&entry.path) == *path)
                    .ok_or_else(|| format!("no entry {path:?} in the volume"))?;
                if u64::from(entry.size.get()) > maximum_output_bytes as u64 {
                    return Err("ADF member exceeds the output byte budget".to_owned());
                }
                image.read_file(entry).map_err(|error| error.to_string())
            }
            Selector::Lha { member, .. } => {
                let archive =
                    amiga_lha::Archive::parse(container).map_err(|error| error.to_string())?;
                let entry = archive
                    .entries()
                    .iter()
                    .find(|entry| entry.name() == *member)
                    .ok_or_else(|| format!("no member {member:?} in the archive"))?;
                if u64::from(entry.original_size()) > maximum_output_bytes as u64
                    || (entry.is_stored()
                        && u64::from(entry.compressed_size()) > maximum_output_bytes as u64)
                {
                    return Err("LHA member exceeds the output byte budget".to_owned());
                }
                archive
                    .read(
                        entry,
                        amiga_lha::OutputLimit::new(maximum_output_bytes as u64),
                    )
                    .map_err(|error| error.to_string())
            }
            Selector::Decompressed {
                codec,
                declared_size,
            } => {
                let (data, stream_declared) = decompress(codec, container, maximum_output_bytes)?;
                // A size the stream declares is a cross-check, not a hint. If
                // the record and the stream disagree, this is not the recipe
                // that produced these bytes, and saying so beats reporting a
                // digest mismatch whose cause nobody can see.
                match (declared_size, stream_declared) {
                    (Some(recorded), Some(found)) if u64::from(found) != *recorded => Err(format!(
                        "the record declares {recorded} output byte(s) but the stream \
                         declares {found}"
                    )),
                    (Some(recorded), None) => Err(format!(
                        "a {} stream carries no output size, so the recorded {recorded} \
                         cannot be checked",
                        codec.name()
                    )),
                    _ => Ok(data),
                }
            }
            // Handled inside the format crate; reaching here would mean it
            // changed its mind about what it delegates.
            Selector::Range { .. } => Err("a byte range needs no parser".to_owned()),
            Selector::Sandbox { .. } => {
                Err("sandbox recovery requires verified project inputs".to_owned())
            }
        }
    }

    pub(crate) fn verification_limits(&self) -> amiga_project::verify::VerificationLimits {
        self.limits.verification_limits()
    }
}

impl amiga_project::Recover for ContainerRecovery {
    fn recover(&self, selector: &Selector, container: &[u8]) -> Result<Vec<u8>, String> {
        self.recover_container(selector, container, self.maximum_output_bytes)
    }

    fn recover_with_inputs(
        &self,
        selector: &Selector,
        container: &[u8],
        inputs: &BTreeMap<&str, &[u8]>,
    ) -> Result<Vec<u8>, String> {
        self.recover_bounded(
            selector,
            container,
            inputs,
            self.maximum_output_bytes as u64,
        )
    }

    fn recover_bounded(
        &self,
        selector: &Selector,
        container: &[u8],
        inputs: &BTreeMap<&str, &[u8]>,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        let maximum = usize::try_from(maximum_bytes)
            .unwrap_or(usize::MAX)
            .min(self.maximum_output_bytes);
        if let Selector::Sandbox {
            export,
            inputs: names,
        } = selector
        {
            if !names.keys().map(String::as_str).eq(inputs.keys().copied()) {
                return Err("sandbox input bindings do not match the selector".to_owned());
            }
            self.sandbox(container, export, inputs, maximum)
        } else {
            self.recover_container(selector, container, maximum)
        }
    }
}

/// Run one recorded decompression recipe, returning the bytes and whatever
/// output size the stream itself declared.
///
/// Exhaustive over the codecs the project format names, which is what keeps the
/// vocabulary and the implementations from drifting: a codec added to the format
/// stops compiling here until it is either decoded or explicitly refused.
fn decompress(
    codec: &Codec,
    packed: &[u8],
    maximum_output_bytes: usize,
) -> Result<(Vec<u8>, Option<u32>), String> {
    match codec {
        Codec::Powerpacker { mode_bits } => {
            let data = amiga_compress::decode_embedded_powerpacker_bounded(
                packed,
                *mode_bits,
                maximum_output_bytes,
            )
            .map_err(|error| error.to_string())?;
            // The decoder allocates exactly the trailer's output size and
            // refuses a stream that does not fill it, so the produced length
            // *is* what this stream declared.
            let declared = u32::try_from(data.len()).ok();
            Ok((data, declared))
        }
        Codec::ByteRun1 {} => Ok((
            amiga_compress::decode_byte_run1_bounded(packed, maximum_output_bytes)
                .map_err(|error| error.to_string())?,
            None,
        )),
        Codec::RleXor {
            marker,
            xor,
            inline_marker,
            size_bytes,
            size_includes_field,
        } => {
            let decoded = amiga_compress::decode_rle_xor_bounded(
                packed,
                amiga_compress::RleXorParams {
                    marker: *marker,
                    xor: *xor,
                    inline_marker: *inline_marker,
                    size_bytes: *size_bytes,
                    size_includes_field: *size_includes_field,
                },
                maximum_output_bytes,
            )
            .map_err(|error| error.to_string())?;
            Ok((decoded.data, decoded.declared_size))
        }
    }
}

/// A walked ADF path as the project spells it: `/`-separated, host-independent.
fn volume_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use amiga_project::Recover as _;

    const POWERPACKER_MODES: [u8; 4] = [9, 10, 12, 13];

    #[test]
    fn stored_lha_payload_cannot_bypass_the_output_limit_with_a_false_size() {
        let payload = b"eight123";
        let name = b"file";
        let mut header = b"-lh0-".to_vec();
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        header.extend_from_slice(&1_u32.to_le_bytes()); // False original size.
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.extend_from_slice(&[0x20, 0, name.len() as u8]);
        header.extend_from_slice(name);
        header.extend_from_slice(&amiga_lha::crc16(payload).to_le_bytes());
        let checksum = header
            .iter()
            .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
        let mut archive = vec![header.len() as u8, checksum];
        archive.extend_from_slice(&header);
        archive.extend_from_slice(payload);
        archive.push(0);
        let selector = Selector::Lha {
            member: "file".to_owned(),
            method: None,
            crc16: None,
        };
        assert!(
            ContainerRecovery::new(4)
                .recover(&selector, &archive)
                .unwrap_err()
                .contains("output byte budget")
        );
    }

    #[test]
    fn a_recorded_recipe_decodes_the_bytes_it_names() {
        // Copy 3 literals, then replicate 'Z' four times.
        let packed = [0x02, b'A', b'B', b'C', 0xfd, b'Z'];
        let selector = Selector::Decompressed {
            codec: Codec::ByteRun1 {},
            declared_size: None,
        };
        assert_eq!(
            ContainerRecovery::default().recover(&selector, &packed),
            Ok(b"ABCZZZZ".to_vec())
        );
    }

    #[test]
    fn every_rle_xor_parameter_is_carried_rather_than_defaulted() {
        // The same stream under two markers decodes to two different things.
        // A recoverer that supplied its own default would silently produce one
        // of them for a project that recorded the other.
        let mut stream = 6_u32.to_be_bytes().to_vec();
        stream.extend_from_slice(&[b'A', b'B', 0x90, 2, b'C', b'D']);
        let packed: Vec<u8> = stream
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ (index as u8))
            .collect();
        let recipe = |marker: u8| Selector::Decompressed {
            codec: Codec::RleXor {
                marker,
                xor: true,
                inline_marker: false,
                size_bytes: 4,
                size_includes_field: false,
            },
            declared_size: None,
        };
        assert_eq!(
            ContainerRecovery::default().recover(&recipe(0x90), &packed),
            Ok(b"ABCCCD".to_vec())
        );
        assert_eq!(
            ContainerRecovery::default().recover(&recipe(0x91), &packed),
            Ok(vec![b'A', b'B', 0x90, 0x02, b'C', b'D'])
        );
    }

    #[test]
    fn a_declared_size_the_stream_contradicts_is_refused_by_name() {
        let mut stream = 6_u32.to_be_bytes().to_vec();
        stream.extend_from_slice(&[b'A', b'B', 0x90, 2, b'C', b'D']);
        let selector = Selector::Decompressed {
            codec: Codec::RleXor {
                marker: 0x90,
                xor: false,
                inline_marker: false,
                size_bytes: 4,
                size_includes_field: false,
            },
            declared_size: Some(7),
        };
        let Err(reason) = ContainerRecovery::default().recover(&selector, &stream) else {
            panic!("a contradicted declared size must be refused");
        };
        assert!(reason.contains("declares 7"), "{reason}");
        assert!(reason.contains("declares 6"), "{reason}");
    }

    #[test]
    fn a_truncated_stream_is_a_reason_rather_than_a_panic() {
        let selector = Selector::Decompressed {
            codec: Codec::ByteRun1 {},
            declared_size: None,
        };
        // A literal run promising three bytes with one left.
        assert!(
            ContainerRecovery::default()
                .recover(&selector, &[0x02, b'A'])
                .is_err()
        );
    }

    #[test]
    fn a_byte_range_is_not_this_layer_s_business() {
        let selector = Selector::Range {
            offset: 0,
            length: 1,
        };
        assert!(
            ContainerRecovery::default()
                .recover(&selector, b"x")
                .is_err()
        );
    }

    #[test]
    fn project_recovery_refuses_an_rle_run_before_it_exceeds_its_limit() {
        let selector = Selector::Decompressed {
            codec: Codec::RleXor {
                marker: 0x90,
                xor: false,
                inline_marker: false,
                size_bytes: 0,
                size_includes_field: false,
            },
            declared_size: None,
        };
        let error = ContainerRecovery::new(255)
            .recover(&selector, &[0x90, u8::MAX, b'A'])
            .expect_err("a 256-byte run must exceed the 255-byte limit");
        assert!(error.contains("255-byte limit"), "{error}");
    }

    #[test]
    fn project_recovery_refuses_powerpacker_before_allocating_past_its_limit() {
        let selector = Selector::Decompressed {
            codec: Codec::Powerpacker {
                mode_bits: POWERPACKER_MODES,
            },
            declared_size: None,
        };
        let error = ContainerRecovery::new(2)
            .recover(&selector, &powerpacker_stream(b"ABC"))
            .expect_err("three decoded bytes must exceed the two-byte limit");
        assert!(error.contains("size 3"), "{error}");
        assert!(error.contains("2-byte limit"), "{error}");
    }

    #[test]
    fn project_recovery_refuses_byte_run1_before_growing_past_its_limit() {
        let selector = Selector::Decompressed {
            codec: Codec::ByteRun1 {},
            declared_size: None,
        };
        let error = ContainerRecovery::new(6)
            .recover(&selector, &[0x02, b'A', b'B', b'C', 0xfd, b'Z'])
            .expect_err("seven decoded bytes must exceed the six-byte limit");
        assert!(error.contains("6-byte limit"), "{error}");
    }

    #[test]
    fn project_recovery_accepts_every_codec_at_the_exact_limit() {
        let cases = [
            (
                Selector::Decompressed {
                    codec: Codec::Powerpacker {
                        mode_bits: POWERPACKER_MODES,
                    },
                    declared_size: None,
                },
                powerpacker_stream(b"ABC"),
            ),
            (
                Selector::Decompressed {
                    codec: Codec::ByteRun1 {},
                    declared_size: None,
                },
                vec![0x02, b'A', b'B', b'C'],
            ),
            (
                Selector::Decompressed {
                    codec: Codec::RleXor {
                        marker: 0x90,
                        xor: false,
                        inline_marker: false,
                        size_bytes: 0,
                        size_includes_field: false,
                    },
                    declared_size: None,
                },
                b"ABC".to_vec(),
            ),
        ];
        for (selector, packed) in cases {
            assert_eq!(
                ContainerRecovery::new(3).recover(&selector, &packed),
                Ok(b"ABC".to_vec())
            );
        }
    }

    fn powerpacker_stream(payload: &[u8; 3]) -> Vec<u8> {
        let fields = [
            (0, 1),
            (2, 2),
            (u32::from(payload[2]), 8),
            (u32::from(payload[1]), 8),
            (u32::from(payload[0]), 8),
        ];
        let mut bits = Vec::new();
        for (value, count) in fields {
            for shift in (0..count).rev() {
                bits.push((value >> shift) & 1);
            }
        }
        bits.resize(bits.len().next_multiple_of(32), 0);
        let word = bits
            .iter()
            .enumerate()
            .fold(0_u32, |word, (index, bit)| word | (bit << index));
        let mut packed = word.to_be_bytes().to_vec();
        packed.extend_from_slice(&(3_u32 << 8).to_be_bytes());
        packed
    }
}
