//! Names for a disassembly, from the project that reviewed them.
//!
//! There were two naming stores and they were not connected. Labels came from
//! `amiga-re.toml`'s `[[symbols]]` table; the reviewed names a project records
//! appeared nowhere in the output a person reads. A downstream project that
//! adopted the project format and removed its now-duplicated table lost every
//! label — silently, because an unlabelled disassembly looks exactly like one
//! whose symbols were never configured.
//!
//! Two rules make this safe to apply automatically:
//!
//! **The image is identified by its digest, never by its path.** A project's
//! names are used only when some image's object digest equals the digest of the
//! bytes being disassembled. Matching on a file name would put one module's
//! names on another's offsets, which is the failure the whole address model
//! exists to prevent.
//!
//! **A stale annotation names nothing.** `amiga_project::Index` excludes them
//! from every lookup; they are listed here so a reader is told the name exists
//! and was withheld, rather than being left to wonder where it went.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use amiga_core::sha256;

/// The reviewed names one project gives one image.
///
/// Flattened at construction into owned strings: the alternative is to keep the
/// loaded project and an index borrowing from it side by side, and every caller
/// would then carry two lifetimes to render one label.
#[derive(Clone)]
pub(crate) struct ProjectNames {
    /// The project root the names came from, for the header a listing prints.
    root: PathBuf,
    /// The image whose object digest matched the analyzed bytes.
    image: String,
    /// (hunk, hunk-relative offset) -> the reviewed name.
    by_offset: BTreeMap<(u32, u64), String>,
    /// (base register, displacement) -> the reviewed name of that small-data
    /// slot. `disasm globals` finds the slots; this is what names them.
    globals: BTreeMap<(String, i32), String>,
    /// (hunk, entry offset) -> the reviewed calling contract.
    ///
    /// Read here rather than at each use, because this is the one place that
    /// reads the project format: a second reader would be a second vocabulary
    /// for the same document.
    signatures: BTreeMap<(u32, u64), Signature>,
}

/// Where a reviewed contract keeps one value.
///
/// The document's own two shapes, flattened. A register keeps the lowercase
/// spelling the document uses, because that is what a `--reg` argument is
/// matched against; rendering it uppercase is the listing's business.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SignatureLocation {
    Register(String),
    /// A byte offset from the stack pointer as the callee sees it on entry.
    Stack(u64),
}

/// One parameter or result of a reviewed contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SignatureValue {
    pub(crate) name: String,
    pub(crate) location: SignatureLocation,
}

/// One function's reviewed calling contract.
///
/// Both the rendered line a listing prints and the structured values a caller
/// preparing a call checks against, from one read of one annotation — so a
/// template cannot ask for an argument the listing does not show.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Signature {
    pub(crate) rendered: String,
    pub(crate) parameters: Vec<SignatureValue>,
}

impl SignatureLocation {
    /// How a listing spells this: `D1`, `+4(SP)`.
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Register(register) => register.to_uppercase(),
            Self::Stack(offset) => format!("+{offset}(SP)"),
        }
    }

    /// Which `--arg` position a stack slot is, when it is a longword argument.
    ///
    /// Arguments sit above the return marker, so `SP+4` is the first and each
    /// one after it is four bytes higher. An offset that is not `4 + 4n` names
    /// no whole argument — a word at `SP+6` is the low half of the first one —
    /// and `None` says so rather than rounding to a neighbour.
    pub(crate) fn stack_argument_index(&self) -> Option<usize> {
        let Self::Stack(offset) = self else {
            return None;
        };
        let above_marker = offset.checked_sub(4)?;
        if !above_marker.is_multiple_of(4) {
            return None;
        }
        usize::try_from(above_marker / 4).ok()
    }
}

/// The document's location, flattened.
fn abi_location(location: &amiga_project::document::AbiLocation) -> SignatureLocation {
    match location {
        amiga_project::document::AbiLocation::Register { register } => {
            SignatureLocation::Register(register.clone())
        }
        amiga_project::document::AbiLocation::Stack { offset } => SignatureLocation::Stack(*offset),
    }
}

fn signature_values(values: &[amiga_project::document::Parameter]) -> Vec<SignatureValue> {
    values
        .iter()
        .map(|value| SignatureValue {
            name: value.name.clone(),
            location: abi_location(&value.location),
        })
        .collect()
}

/// A callable signature, or `None` for a type that is not one.
///
/// The rendered line carries parameters and results only. `clobbers`/`preserves`
/// are the contract a *caller* checks before keeping a value across the call, and
/// they belong in a report rather than on an instruction: a call line long enough
/// to carry fifteen register names is one nobody reads.
fn read_signature(
    name: &str,
    definition: &amiga_project::document::TypeDefinition,
) -> Option<Signature> {
    let amiga_project::document::TypeDefinition::Function {
        parameters,
        results,
        ..
    } = definition
    else {
        return None;
    };
    let parameters = signature_values(parameters);
    let results = signature_values(results);
    let render = |values: &[SignatureValue]| -> String {
        values
            .iter()
            .map(|value| format!("{}={}", value.name, value.location.label()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut rendered = format!("{name}({})", render(&parameters));
    if !results.is_empty() {
        rendered.push_str(" -> ");
        rendered.push_str(&render(&results));
    }
    Some(Signature {
        rendered,
        parameters,
    })
}

impl ProjectNames {
    /// The names the project gives the image these bytes are, if any.
    ///
    /// `None` covers three different situations, and only the last is silent:
    /// no project was found, a project was found and could not be loaded (a
    /// warning), and a project was found that describes no image with this
    /// digest (a note, because that is exactly when a user expects labels and
    /// would otherwise get none without explanation).
    pub(crate) fn for_bytes(override_path: Option<&Path>, bytes: &[u8]) -> Option<Self> {
        let root = match override_path {
            Some(path) => path.to_path_buf(),
            None => {
                let cwd = std::env::current_dir().ok()?;
                amiga_project::discover(&cwd)?
            }
        };
        let loaded = match amiga_project::load(&root) {
            Ok(loaded) => loaded,
            Err(error) => {
                eprintln!(
                    "warning: {} could not be loaded, so its names are not used: {error}",
                    root.display()
                );
                return None;
            }
        };
        let project = &loaded.project;

        let digest = sha256(bytes);
        let object_digest: BTreeMap<&str, &str> = project
            .sources
            .objects
            .iter()
            .map(|object| (object.id.as_str(), object.sha256.as_str()))
            .collect();
        let image = project
            .programs
            .iter()
            .flat_map(|program| &program.images)
            .find(|image| {
                object_digest
                    .get(image.object_id.as_str())
                    .is_some_and(|recorded| recorded.eq_ignore_ascii_case(&digest))
            });
        let Some(image) = image else {
            eprintln!(
                "note: {} describes no image whose object digest is {digest}, \
                 so names come from amiga-re.toml only",
                root.display()
            );
            return None;
        };
        let image_id = image.id.clone();

        let index = amiga_project::Index::build(project);
        // Said once, here, rather than by each command: a stale annotation is
        // withheld from every lookup, and a reader who is not told will look
        // for the name in the listing and conclude it was never recorded.
        if !index.stale().is_empty() {
            let ids: Vec<&str> = index.stale().iter().map(|id| id.as_str()).collect();
            eprintln!(
                "note: {} stale annotation(s) are excluded until rebased: {}",
                ids.len(),
                ids.join(", ")
            );
        }
        let mut names = Self {
            root,
            image: image_id.clone(),
            by_offset: BTreeMap::new(),
            globals: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        // The type index, for the `type_id` a function annotation may carry.
        let types = amiga_project::TypeSizes::of(project);
        for document in &project.annotations {
            for annotation in &document.annotations {
                if annotation.is_stale() {
                    continue;
                }
                // The signature is keyed by the same offset as the name, and read
                // from the same annotation, so a listing cannot show one without
                // the other having been reviewed together.
                let signature = match annotation {
                    amiga_project::document::Annotation::Function {
                        name,
                        type_id: Some(type_id),
                        ..
                    } => types
                        .definition(type_id)
                        .and_then(|definition| read_signature(name, definition)),
                    _ => None,
                };
                let name = match annotation {
                    amiga_project::document::Annotation::Function { name, .. }
                    | amiga_project::document::Annotation::Symbol { name, .. }
                    | amiga_project::document::Annotation::Variable { name, .. } => name,
                    _ => continue,
                };
                match annotation.target() {
                    Some(amiga_project::document::Target::Hunk {
                        image_id: owner,
                        hunk,
                        offset,
                        ..
                    }) if *owner == image_id => {
                        names.by_offset.insert((*hunk, *offset), name.clone());
                        if let Some(signature) = signature {
                            names.signatures.insert((*hunk, *offset), signature);
                        }
                    }
                    // A runtime target is converted through its own named load
                    // map, never through the `--base` this run happens to use:
                    // the same executable loaded high and loaded low are both
                    // true, and the document says which one it meant.
                    Some(amiga_project::document::Target::Runtime {
                        image_id: owner,
                        load_map_id,
                        address,
                        ..
                    }) if *owner == image_id => {
                        if let Some((hunk, offset)) =
                            index.to_hunk_offset(&image_id, load_map_id, address)
                        {
                            names.by_offset.insert((hunk, offset), name.clone());
                            if let Some(signature) = signature {
                                names.signatures.insert((hunk, offset), signature);
                            }
                        }
                    }
                    Some(amiga_project::document::Target::BaseRegister {
                        image_id: owner,
                        base_register,
                        displacement,
                        ..
                    }) if *owner == image_id => {
                        names
                            .globals
                            .insert((base_register.clone(), *displacement), name.clone());
                    }
                    _ => {}
                }
            }
        }
        Some(names)
    }

    /// The reviewed name at one hunk offset of this image.
    pub(crate) fn at(&self, hunk: u32, offset: u64) -> Option<&str> {
        self.by_offset.get(&(hunk, offset)).map(String::as_str)
    }

    /// The reviewed calling contract of the function entered at one hunk offset.
    pub(crate) fn signature(&self, hunk: u32, offset: u64) -> Option<&Signature> {
        self.signatures.get(&(hunk, offset))
    }

    /// The reviewed name of one small-data slot, e.g. `("a5", -8)`.
    pub(crate) fn global(&self, base_register: &str, displacement: i32) -> Option<&str> {
        self.globals
            .get(&(base_register.to_owned(), displacement))
            .map(String::as_str)
    }

    /// A line for a listing header, so the reader can see which document the
    /// names came from and check it.
    pub(crate) fn provenance(&self) -> String {
        format!("{} image {}", self.root.display(), self.image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amiga_project::document::{AbiLocation, Parameter, TypeDefinition};

    fn parameter(name: &str, location: AbiLocation) -> Parameter {
        Parameter {
            name: name.to_owned(),
            type_id: "type:u16".to_owned(),
            location,
            notes: None,
        }
    }

    fn register(name: &str) -> AbiLocation {
        AbiLocation::Register {
            register: name.to_owned(),
        }
    }

    fn signature(parameters: Vec<Parameter>, results: Vec<Parameter>) -> TypeDefinition {
        TypeDefinition::Function {
            id: "type:sig".to_owned(),
            name: "Sig".to_owned(),
            parameters,
            results,
            clobbers: Some(vec!["d0".to_owned()]),
            preserves: None,
            notes: None,
        }
    }

    /// Registers uppercase to match the disassembly's own spelling, and a stack
    /// offset written from the callee's entry, which is what the format states.
    #[test]
    fn a_signature_renders_its_locations_the_way_the_listing_spells_them() {
        let signature = read_signature(
            "load_level",
            &signature(
                vec![
                    parameter("level", register("d1")),
                    parameter("destination", register("a2")),
                    parameter("flags", AbiLocation::Stack { offset: 4 }),
                ],
                vec![
                    parameter("status", register("d0")),
                    parameter("header", register("a0")),
                ],
            ),
        );
        assert_eq!(
            signature
                .as_ref()
                .map(|signature| signature.rendered.as_str()),
            Some(
                "load_level(level=D1, destination=A2, flags=+4(SP)) \
                 -> status=D0, header=A0"
            )
        );
    }

    /// A routine that returns nothing renders no arrow, rather than an arrow
    /// with nothing after it.
    #[test]
    fn a_signature_with_no_results_renders_no_arrow() {
        let signature = read_signature(
            "clear",
            &signature(vec![parameter("mask", register("d0"))], Vec::new()),
        );
        assert_eq!(
            signature
                .as_ref()
                .map(|signature| signature.rendered.as_str()),
            Some("clear(mask=D0)")
        );
    }

    /// A routine that takes nothing still renders its parentheses: `init()` is a
    /// reviewed claim that it takes nothing, and `init` would read as a name
    /// nobody worked the contract out for.
    #[test]
    fn a_signature_with_no_parameters_still_renders_parentheses() {
        let signature = read_signature("init", &signature(Vec::new(), Vec::new()));
        assert_eq!(
            signature
                .as_ref()
                .map(|signature| signature.rendered.as_str()),
            Some("init()")
        );
    }

    /// A `type_id` naming something that is not callable renders nothing, so a
    /// listing shows the plain name rather than a value type dressed as a call.
    #[test]
    fn a_value_type_is_not_a_signature() {
        let integer = TypeDefinition::Integer {
            id: "type:u16".to_owned(),
            name: "u16".to_owned(),
            size: 2,
            signed: false,
            byte_order: "big".to_owned(),
            notes: None,
        };
        assert!(read_signature("thing", &integer).is_none());
    }
}
