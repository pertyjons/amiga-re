//! Resolving a location to the knowledge attached to it.
//!
//! The question this answers is "what does the project say about hunk 0 offset
//! 4 of *this* image", and the emphasis is on *this*. Two modules of one
//! program routinely share numeric offsets — the fixture's do, deliberately —
//! so a resolver keyed on a number alone would confidently return the wrong
//! name. Every lookup therefore starts from an image.
//!
//! Runtime addresses go through a named load map. There is no ambient "the"
//! address space: an executable loaded high and the same executable loaded low
//! are both true, and which one a caller means is part of the question.
//!
//! Stale annotations are **excluded from resolution** and reported separately.
//! That is the whole point of detecting staleness: the knowledge survives in
//! the document and stays visible in a listing of problems, but it never
//! silently names bytes it was not written about.

use std::collections::BTreeMap;

use crate::document::{Annotation, Id, Project, Target};

/// What the project says about one hunk offset.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Resolved<'a> {
    /// The function whose entry is exactly here, if any.
    pub function: Option<&'a str>,
    /// Symbols naming this offset, in declaration order.
    pub symbols: Vec<&'a str>,
    /// Comments attached here or to an entity that is here.
    pub comments: Vec<Comment<'a>>,
    /// Region classifications covering this offset.
    pub regions: Vec<&'a str>,
    /// Bookmarks landing here.
    pub bookmarks: Vec<&'a str>,
    /// Globals stored here, in declaration order.
    ///
    /// Only the located shape: a small-data global is asked for by slot through
    /// [`Index::global`], because "what is `A5+8`" is a different question from
    /// "what is at hunk 0 offset 8" and the answer to one is not the answer to
    /// the other.
    pub variables: Vec<LocatedVariable<'a>>,
}

impl Resolved<'_> {
    /// Whether the project says anything at all about this offset.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.function.is_none()
            && self.symbols.is_empty()
            && self.comments.is_empty()
            && self.regions.is_empty()
            && self.bookmarks.is_empty()
            && self.variables.is_empty()
    }
}

/// One named global stored at a byte address, as a caller renders it.
///
/// The sibling of [`Global`], which names a small-data slot. Both are variables
/// every function shares; they differ in how the program reaches them, and a
/// caller rendering a listing wants whichever one the address it is at has.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocatedVariable<'a> {
    pub name: &'a str,
    /// The type the project gives it, when it gives one.
    pub type_id: Option<&'a str>,
    /// How many bytes of storage it occupies. Where `type_id` is present this
    /// is the size of that type, which
    /// [`validate`](crate::validate()) refuses to let disagree.
    pub width: u64,
}

/// One comment and where it goes relative to the location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Comment<'a> {
    pub placement: &'a str,
    pub text: &'a str,
}

/// A local variable, resolved within the function that scopes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Local<'a> {
    pub name: &'a str,
    /// `d0`, `a6`, or a stack slot rendered as `(displacement,base)`.
    pub storage: LocalStorage<'a>,
    /// The hunk offsets the variable is live across, when the project records
    /// them. A register with no lifetime is named for the whole function, which
    /// is weaker knowledge and is presented as such.
    pub lifetime: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalStorage<'a> {
    Register(&'a str),
    Stack { base: &'a str, displacement: i32 },
}

/// An index over one project's reviewed knowledge, keyed by where it applies.
///
/// Built once and queried many times: a listing asks per instruction, and
/// rebuilding the index per query would make annotating a large hunk quadratic.
#[derive(Debug, Default)]
pub struct Index<'a> {
    /// (image, hunk, offset) -> the annotations exactly there.
    at: BTreeMap<(&'a str, u32, u64), Vec<&'a Annotation>>,
    /// Annotations targeting an entity, keyed by that entity.
    on_entity: BTreeMap<&'a str, Vec<&'a Annotation>>,
    /// Variables, keyed by the function that scopes them.
    locals: BTreeMap<&'a str, Vec<&'a Annotation>>,
    /// (image, base register, displacement) -> the annotations naming that
    /// small-data slot. Any kind may name one; a `variable` is simply the kind
    /// that says "this is a global".
    globals: BTreeMap<(&'a str, &'a str, i32), Vec<&'a Annotation>>,
    /// image -> load map -> hunk -> runtime base, for address conversion.
    load_maps: BTreeMap<(&'a str, &'a str), BTreeMap<u32, u32>>,
    /// Annotations excluded because their object digest no longer matches.
    stale: Vec<&'a Id>,
}

impl<'a> Index<'a> {
    /// Index every annotation the project carries.
    ///
    /// Stale annotations are recorded in [`Self::stale`] and indexed nowhere,
    /// so no lookup can return one.
    #[must_use]
    pub fn build(project: &'a Project) -> Self {
        let mut index = Self::default();

        for program in &project.programs {
            for image in &program.images {
                for map in &image.load_maps {
                    let bases = map
                        .segments
                        .iter()
                        .filter_map(|segment| {
                            Some((segment.hunk, parse_hex_address(&segment.runtime_base)?))
                        })
                        .collect();
                    index
                        .load_maps
                        .insert((image.id.as_str(), map.id.as_str()), bases);
                }
            }
        }

        for document in &project.annotations {
            for annotation in &document.annotations {
                if annotation.is_stale() {
                    index.stale.push(annotation.id());
                    continue;
                }
                match annotation {
                    // A local is found through its function; a global has no
                    // function and is found through its target, like every
                    // other annotation.
                    Annotation::Variable {
                        scope: Some(scope), ..
                    } => {
                        index
                            .locals
                            .entry(scope.function_id.as_str())
                            .or_default()
                            .push(annotation);
                    }
                    _ => match annotation.target() {
                        Some(Target::Hunk {
                            image_id,
                            hunk,
                            offset,
                            ..
                        }) => {
                            index
                                .at
                                .entry((image_id.as_str(), *hunk, *offset))
                                .or_default()
                                .push(annotation);
                        }
                        // Keyed by the slot rather than by a file offset,
                        // because that is the question a listing asks: what is
                        // `A5+n` in this image?
                        Some(Target::BaseRegister {
                            image_id,
                            base_register,
                            displacement,
                            ..
                        }) => {
                            index
                                .globals
                                .entry((image_id.as_str(), base_register.as_str(), *displacement))
                                .or_default()
                                .push(annotation);
                        }
                        Some(Target::Entity { entity_id }) => {
                            index
                                .on_entity
                                .entry(entity_id.as_str())
                                .or_default()
                                .push(annotation);
                        }
                        // A runtime target is indexed at the hunk offset it
                        // converts to, so one lookup answers for both spellings.
                        Some(Target::Runtime {
                            image_id,
                            load_map_id,
                            address,
                            ..
                        }) => {
                            if let Some((hunk, offset)) = index.to_hunk_offset(
                                image_id.as_str(),
                                load_map_id.as_str(),
                                address,
                            ) {
                                index
                                    .at
                                    .entry((image_id.as_str(), hunk, offset))
                                    .or_default()
                                    .push(annotation);
                            }
                        }
                        _ => {}
                    },
                }
            }
        }
        index
    }

    /// The annotations whose object digest no longer matches, and which are
    /// therefore excluded from every lookup.
    #[must_use]
    pub fn stale(&self) -> &[&'a Id] {
        &self.stale
    }

    /// Convert a runtime address to `(hunk, offset)` under one named load map.
    ///
    /// `None` when the map does not cover the address. A missing conversion
    /// stays missing: guessing the nearest hunk would produce an offset that
    /// looks right and names the wrong bytes.
    #[must_use]
    pub fn to_hunk_offset(&self, image: &str, load_map: &str, address: &str) -> Option<(u32, u64)> {
        let value = parse_hex_address(address)?;
        let bases = self.load_maps.get(&(image, load_map))?;
        // The segment with the greatest base at or below the address. Without
        // hunk sizes here, the project's own ranges bound it; this only decides
        // *which* hunk an address belongs to.
        bases
            .iter()
            .filter(|(_, base)| **base <= value)
            .max_by_key(|(_, base)| **base)
            .map(|(hunk, base)| (*hunk, u64::from(value - base)))
    }

    /// What the project says about one hunk offset of one image.
    #[must_use]
    pub fn at(&self, image: &str, hunk: u32, offset: u64) -> Resolved<'a> {
        let mut resolved = Resolved::default();
        let Some(annotations) = self.at.get(&(image, hunk, offset)) else {
            return resolved;
        };
        for annotation in annotations {
            match annotation {
                Annotation::Function { name, id, .. } => {
                    resolved.function = Some(name.as_str());
                    // A comment attached to the function entity belongs here
                    // too: that indirection exists so renaming or rebasing the
                    // function carries the comment with it.
                    if let Some(attached) = self.on_entity.get(id.as_str()) {
                        for annotation in attached {
                            if let Annotation::Comment {
                                placement, text, ..
                            } = annotation
                            {
                                resolved.comments.push(Comment {
                                    placement: placement.as_str(),
                                    text: text.as_str(),
                                });
                            }
                        }
                    }
                }
                Annotation::Symbol { name, .. } => resolved.symbols.push(name.as_str()),
                Annotation::Bookmark { name, .. } => resolved.bookmarks.push(name.as_str()),
                Annotation::Comment {
                    placement, text, ..
                } => resolved.comments.push(Comment {
                    placement: placement.as_str(),
                    text: text.as_str(),
                }),
                Annotation::Region { classification, .. } => {
                    resolved.regions.push(classification.as_str());
                }
                // Only a global reaches here: `build` routes a scoped local to
                // `locals` and a small-data slot to `globals`, so a variable in
                // this index is one stored at a byte address.
                Annotation::Variable {
                    name,
                    target,
                    type_id,
                    ..
                } => {
                    if let Some(width) = target.as_deref().and_then(Target::byte_length) {
                        resolved.variables.push(LocatedVariable {
                            name: name.as_str(),
                            type_id: type_id.as_deref(),
                            width,
                        });
                    }
                }
            }
        }
        resolved
    }

    /// The locals scoped to one function.
    ///
    /// Scoped rather than global: a register means something different three
    /// instructions later, and naming `d0` for a whole program would be wrong
    /// more often than right.
    #[must_use]
    pub fn locals(&self, function_id: &str) -> Vec<Local<'a>> {
        self.locals
            .get(function_id)
            .into_iter()
            .flatten()
            .filter_map(|annotation| {
                let Annotation::Variable {
                    name,
                    storage: Some(storage),
                    lifetime,
                    ..
                } = annotation
                else {
                    return None;
                };
                Some(Local {
                    name: name.as_str(),
                    storage: match storage {
                        crate::document::Storage::Register { register } => {
                            LocalStorage::Register(register.as_str())
                        }
                        crate::document::Storage::Stack {
                            base_register,
                            displacement,
                        } => LocalStorage::Stack {
                            base: base_register.as_str(),
                            displacement: *displacement,
                        },
                    },
                    lifetime: lifetime.as_ref().and_then(|lifetime| {
                        match (&lifetime.start, &lifetime.end) {
                            (
                                Target::Hunk { offset: start, .. },
                                Target::Hunk { offset: end, .. },
                            ) => Some((*start, *end)),
                            _ => None,
                        }
                    }),
                })
            })
            .collect()
    }
}

impl<'a> Index<'a> {
    /// The name the project gives one small-data slot of one image.
    ///
    /// Keyed by the register as well as the displacement: `A4+8` and `A5+8` are
    /// different globals, and a lookup that ignored the register would name one
    /// of them for the other.
    #[must_use]
    pub fn global(
        &self,
        image: &str,
        base_register: &str,
        displacement: i32,
    ) -> Option<Global<'a>> {
        self.globals
            .get(&(image, base_register, displacement))
            .and_then(|annotations| annotations.iter().find_map(|annotation| global(annotation)))
    }

    /// Every named slot of one image, in `(register, displacement)` order.
    #[must_use]
    pub fn globals(&self, image: &str) -> Vec<Global<'a>> {
        self.globals
            .iter()
            .filter(|((named, _, _), _)| *named == image)
            .filter_map(|(_, annotations)| annotations.iter().find_map(|a| global(a)))
            .collect()
    }
}

/// One named small-data global, as a caller renders it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Global<'a> {
    pub name: &'a str,
    /// The address register the displacement is taken from, e.g. `a5`.
    pub base: &'a str,
    pub displacement: i32,
    /// The access width in bytes.
    pub width: u8,
}

/// The global one annotation names, when it names one.
fn global<'a>(annotation: &'a Annotation) -> Option<Global<'a>> {
    let (Annotation::Variable { name, .. } | Annotation::Symbol { name, .. }) = annotation else {
        return None;
    };
    let Some(Target::BaseRegister {
        base_register,
        displacement,
        width,
        ..
    }) = annotation.target()
    else {
        return None;
    };
    Some(Global {
        name: name.as_str(),
        base: base_register.as_str(),
        displacement: *displacement,
        width: *width,
    })
}

/// Parse a fixed-form `0x` address. The format bounds it to eight hex digits,
/// so this cannot overflow; a malformed one resolves to nothing rather than to
/// a plausible number.
fn parse_hex_address(address: &str) -> Option<u32> {
    u32::from_str_radix(address.strip_prefix("0x")?, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_must_be_fixed_form_to_parse() {
        assert_eq!(parse_hex_address("0x0000e63e"), Some(0x0000_e63e));
        for bad in ["e63e", "0xzzzz", "", "0x1_0000_0000"] {
            assert_eq!(parse_hex_address(bad), None, "{bad:?} was parsed");
        }
    }

    #[test]
    fn an_empty_resolution_is_recognizable() {
        assert!(Resolved::default().is_empty());
        assert!(
            !Resolved {
                function: Some("x"),
                ..Resolved::default()
            }
            .is_empty()
        );
    }
}
