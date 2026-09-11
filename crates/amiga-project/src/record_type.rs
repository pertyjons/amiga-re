//! Turning a record layout into type definitions, and back.
//!
//! A table resource names its record layout through `type_id`, which points at
//! a [`TypeDefinition::Struct`]. A decoder reads a layout string —
//! `u16,u16,ptr,char[16]` — through [`amiga_core::record::parse_layout`]. This
//! module is the one place those two spellings are converted into each other,
//! so a table stored as a project type decodes to the same rows as the layout
//! it was written from.
//!
//! Two decisions decide the shape of everything here.
//!
//! **The primitives are shared and their identities are canonical.** Two tables
//! that both begin with a `u16` field point at the same `type:u16`, rather than
//! each carrying a private copy. A project that defines `type:u16` twice with
//! different meanings is a project whose types cannot be reasoned about, and the
//! ids below are what make the collision impossible.
//!
//! **A type's `name` is the layout token it came from.** `u16`, `ptr`,
//! `char[16]`. It is what a person reading the document expects to see, and it
//! is what [`layout_of`] disambiguates on where the structure alone is
//! ambiguous — `bytes[4]` and `pad[4]` are both four bytes and mean different
//! things. Reading is structural first and consults the name only for that
//! distinction, so renaming a struct or a field never changes how it decodes.

use amiga_core::record::{FieldType, record_size};
use thiserror::Error;

use crate::document::{Field, Id, TypeDefinition};

/// Byte order every integer this module writes is read in.
///
/// Written out rather than inferred. Amiga data is big-endian, and a format
/// that took the host's order would decode differently on different machines.
const BYTE_ORDER: &str = "big";

/// Address space a bare `ptr` is recorded in.
///
/// `object` because that is the frame a table decoded out of a recovered object
/// is addressed in, and the only one `project.resource.export` resolves. A
/// pointer known to be in another frame is a type a person writes deliberately;
/// this module never guesses one.
const POINTER_SPACE: &str = "object";

/// The pointee of a `ptr` whose target type nobody has established yet.
///
/// The schema requires a pointer to name a pointee, and the layout vocabulary's
/// `ptr` says only "a 32-bit value that is an address". Rather than assert a
/// target it does not know, this points at a type whose whole content is that
/// it is unknown.
const OPAQUE_ID: &str = "type:opaque";

/// Every type definition describing one record layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordType {
    /// The struct a table resource's `type_id` should name.
    pub struct_id: Id,
    /// The struct and every type its fields point at, in write order:
    /// primitives first, so a reader meets a definition before its first use.
    pub definitions: Vec<TypeDefinition>,
}

/// Why a stored type could not be read back as a record layout.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RecordTypeError {
    #[error("{id} is a {kind}, and a table's record layout must be a struct")]
    NotAStruct { id: Id, kind: &'static str },
    #[error("{id} has no fields, so it describes no record")]
    NoFields { id: Id },
    #[error("{id} references {reference}, which this project does not define")]
    Dangling { id: Id, reference: Id },
    #[error("field {field} of {id} is a {reference}, which no record layout can express")]
    Unrepresentable {
        id: Id,
        field: String,
        reference: Id,
    },
    #[error(
        "{id} declares size {declared} but its fields occupy {actual}; the stored type and the \
         bytes it would read disagree"
    )]
    SizeMismatch { id: Id, declared: u64, actual: u64 },
    #[error(
        "field {field} of {id} sits at offset {offset} where the fields before it end at {expected}"
    )]
    OffsetMismatch {
        id: Id,
        field: String,
        offset: u64,
        expected: u64,
    },
}

/// The canonical id and name of the type describing one layout field.
///
/// Deterministic: the same field type always produces the same id, which is what
/// lets two tables share a primitive instead of each defining its own.
#[must_use]
pub fn field_type_identity(field: FieldType) -> (Id, String) {
    let name = match field {
        FieldType::U8 => "u8".to_owned(),
        FieldType::U16 => "u16".to_owned(),
        FieldType::U32 => "u32".to_owned(),
        FieldType::I8 => "i8".to_owned(),
        FieldType::I16 => "i16".to_owned(),
        FieldType::I32 => "i32".to_owned(),
        FieldType::Ptr => "ptr".to_owned(),
        FieldType::Char(length) => format!("char[{length}]"),
        FieldType::Bytes(length) => format!("bytes[{length}]"),
        FieldType::Pad(length) => format!("pad[{length}]"),
    };
    // The id may not carry `[` or `]`, so an array's length joins its name with
    // a dot. The `name` above keeps the layout spelling a person reads.
    let id = match field {
        FieldType::Char(length) => format!("type:char.{length}"),
        FieldType::Bytes(length) => format!("type:bytes.{length}"),
        FieldType::Pad(length) => format!("type:pad.{length}"),
        _ => format!("type:{name}"),
    };
    (id, name)
}

/// The definition of the type describing one layout field, plus any type it
/// points at.
fn definitions_for_field(field: FieldType) -> Vec<TypeDefinition> {
    let (id, name) = field_type_identity(field);
    let integer = |id: Id, name: String, size: u8, signed: bool| TypeDefinition::Integer {
        id,
        name,
        size,
        signed,
        byte_order: BYTE_ORDER.to_owned(),
        notes: None,
    };
    match field {
        FieldType::U8 => vec![integer(id, name, 1, false)],
        FieldType::U16 => vec![integer(id, name, 2, false)],
        FieldType::U32 => vec![integer(id, name, 4, false)],
        FieldType::I8 => vec![integer(id, name, 1, true)],
        FieldType::I16 => vec![integer(id, name, 2, true)],
        FieldType::I32 => vec![integer(id, name, 4, true)],
        FieldType::Ptr => vec![
            TypeDefinition::Integer {
                id: OPAQUE_ID.to_owned(),
                name: "opaque".to_owned(),
                size: 1,
                signed: false,
                byte_order: BYTE_ORDER.to_owned(),
                notes: Some(
                    "What a pointer points at when nobody has established what it points at. \
                     A pointer must name a pointee; this one names the fact that it is unknown."
                        .to_owned(),
                ),
            },
            TypeDefinition::Pointer {
                id,
                name,
                pointee_id: OPAQUE_ID.to_owned(),
                address_space: POINTER_SPACE.to_owned(),
                notes: None,
            },
        ],
        // A `char[N]` is an array of the signed byte the layout vocabulary
        // calls `char`, decoded as NUL-terminated Latin-1.
        FieldType::Char(count) => {
            let (element_id, element_name) = field_type_identity(FieldType::I8);
            vec![
                integer(element_id.clone(), element_name, 1, true),
                TypeDefinition::Array {
                    id,
                    name,
                    element_id,
                    count: u32::try_from(count).unwrap_or(u32::MAX),
                    notes: None,
                },
            ]
        }
        FieldType::Bytes(count) | FieldType::Pad(count) => {
            let (element_id, element_name) = field_type_identity(FieldType::U8);
            vec![
                integer(element_id.clone(), element_name, 1, false),
                TypeDefinition::Array {
                    id,
                    name,
                    element_id,
                    count: u32::try_from(count).unwrap_or(u32::MAX),
                    notes: None,
                },
            ]
        }
    }
}

/// Every definition needed to record `layout` as a struct called `name`.
///
/// Field names are positional (`field0`, `field1`, …) because a layout string
/// carries none. A person renaming them afterwards is the point of storing the
/// type at all, and [`layout_of`] reads structure rather than field names, so a
/// rename never changes what the table decodes to.
///
/// `struct_id` must be a `type:` id; callers derive it from the resource the
/// table belongs to so that two tables cannot collide on one struct.
#[must_use]
pub fn definitions_for_layout(struct_id: &str, name: &str, layout: &[FieldType]) -> RecordType {
    let mut definitions: Vec<TypeDefinition> = Vec::new();
    let mut fields = Vec::with_capacity(layout.len());
    let mut offset: u64 = 0;
    for (index, field) in layout.iter().copied().enumerate() {
        let (field_type_id, _) = field_type_identity(field);
        for definition in definitions_for_field(field) {
            // Deduplicated by identity: every `u16` in every table in the
            // project is the same `type:u16`, defined once.
            if !definitions
                .iter()
                .any(|existing| existing.id() == definition.id())
            {
                definitions.push(definition);
            }
        }
        fields.push(Field {
            name: format!("field{index}"),
            offset,
            type_id: field_type_id,
            notes: None,
        });
        offset = offset.saturating_add(field.size() as u64);
    }
    definitions.push(TypeDefinition::Struct {
        id: struct_id.to_owned(),
        name: name.to_owned(),
        size: record_size(layout) as u64,
        fields,
        notes: None,
    });
    RecordType {
        struct_id: struct_id.to_owned(),
        definitions,
    }
}

/// Read a stored struct back as the record layout that decodes it.
///
/// `resolve` answers "what is this type id", over whatever the project defines.
///
/// # Errors
/// Returns [`RecordTypeError`] when `definition` is not a struct, references a
/// type the project does not define, uses a type no layout can express, or
/// declares offsets or a size that disagree with its own fields — the last
/// because a struct with a gap or an overlap would decode different bytes than
/// the one that wrote it.
pub fn layout_of<'a>(
    definition: &TypeDefinition,
    resolve: &dyn Fn(&str) -> Option<&'a TypeDefinition>,
) -> Result<Vec<FieldType>, RecordTypeError> {
    let TypeDefinition::Struct {
        id,
        size,
        fields,
        name: _,
        notes: _,
    } = definition
    else {
        return Err(RecordTypeError::NotAStruct {
            id: definition.id().clone(),
            kind: definition.kind(),
        });
    };
    if fields.is_empty() {
        return Err(RecordTypeError::NoFields { id: id.clone() });
    }

    let mut layout = Vec::with_capacity(fields.len());
    let mut offset: u64 = 0;
    for field in fields {
        let Some(referenced) = resolve(&field.type_id) else {
            return Err(RecordTypeError::Dangling {
                id: id.clone(),
                reference: field.type_id.clone(),
            });
        };
        // A layout is a contiguous run of fields, and that is not a limitation
        // of this reader: `read_record` advances a cursor field by field, so a
        // struct with a gap or an overlap describes a different byte sequence
        // than the one this decoder would read. Refused rather than silently
        // read as if the offsets said something else.
        if field.offset != offset {
            return Err(RecordTypeError::OffsetMismatch {
                id: id.clone(),
                field: field.name.clone(),
                offset: field.offset,
                expected: offset,
            });
        }
        let Some(decoded) = field_type_of(referenced, resolve) else {
            return Err(RecordTypeError::Unrepresentable {
                id: id.clone(),
                field: field.name.clone(),
                reference: field.type_id.clone(),
            });
        };
        offset = offset.saturating_add(decoded.size() as u64);
        layout.push(decoded);
    }
    if *size != offset {
        return Err(RecordTypeError::SizeMismatch {
            id: id.clone(),
            declared: *size,
            actual: offset,
        });
    }
    Ok(layout)
}

/// One stored type as a layout field, or `None` if no layout can express it.
///
/// Structural, with one exception: `bytes[4]` and `pad[4]` are both an array of
/// four unsigned bytes and mean different things — read, and skipped — so the
/// array's name is what separates them. A padding array that has been renamed
/// therefore reads back as `bytes`, which produces a value where the original
/// produced none; that is why this module writes the layout token as the name.
fn field_type_of<'a>(
    definition: &TypeDefinition,
    resolve: &dyn Fn(&str) -> Option<&'a TypeDefinition>,
) -> Option<FieldType> {
    match definition {
        TypeDefinition::Integer {
            size,
            signed,
            byte_order,
            ..
        } => {
            if byte_order != BYTE_ORDER {
                return None;
            }
            match (size, signed) {
                (1, false) => Some(FieldType::U8),
                (2, false) => Some(FieldType::U16),
                (4, false) => Some(FieldType::U32),
                (1, true) => Some(FieldType::I8),
                (2, true) => Some(FieldType::I16),
                (4, true) => Some(FieldType::I32),
                _ => None,
            }
        }
        TypeDefinition::Pointer { .. } => Some(FieldType::Ptr),
        TypeDefinition::Array {
            name,
            element_id,
            count,
            ..
        } => {
            let element = resolve(element_id)?;
            // Whatever it is called, an array only decodes as one of these
            // three if its element is a single byte.
            if field_type_of(element, resolve)?.size() != 1 {
                return None;
            }
            let count = usize::try_from(*count).ok()?;
            if name.starts_with("char[") {
                Some(FieldType::Char(count))
            } else if name.starts_with("pad[") {
                Some(FieldType::Pad(count))
            } else {
                Some(FieldType::Bytes(count))
            }
        }
        // An alias is transparent: it renames a type without changing what the
        // bytes are.
        TypeDefinition::Alias { aliased_id, .. } => field_type_of(resolve(aliased_id)?, resolve),
        // An enum's stored value is its base type's, so it reads as that.
        TypeDefinition::Enum { base_id, .. } => field_type_of(resolve(base_id)?, resolve),
        // Neither decodes as a field: a struct is a layout of fields rather
        // than one of them, and a signature describes a call rather than any
        // bytes a record holds.
        TypeDefinition::Struct { .. } | TypeDefinition::Function { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amiga_core::record::parse_layout;

    fn round_trip(spec: &str) -> Vec<FieldType> {
        let layout = parse_layout(spec).expect("a layout");
        let record = definitions_for_layout("type:record.test", "test_record", &layout);
        let by_id = |id: &str| {
            record
                .definitions
                .iter()
                .find(|definition| definition.id() == id)
        };
        let structure = by_id(&record.struct_id).expect("the struct");
        layout_of(structure, &by_id).expect("a layout back")
    }

    /// The property the whole module exists for: a table written from a layout
    /// string decodes to the same rows when read back from the stored type.
    #[test]
    fn every_layout_token_survives_the_round_trip() {
        for spec in [
            "u8,u16,u32",
            "i8,i16,i32",
            "ptr",
            "char[16]",
            "bytes[4]",
            "pad[2]",
            "u16,u16,ptr,char[16]",
            "u8,pad[3],bytes[8],i32,ptr",
        ] {
            let expected = parse_layout(spec).expect("a layout");
            assert_eq!(round_trip(spec), expected, "{spec}");
        }
    }

    /// `bytes[N]` and `pad[N]` occupy the same bytes and mean different things.
    #[test]
    fn padding_and_raw_bytes_of_the_same_width_stay_distinct() {
        assert_eq!(round_trip("pad[4]"), vec![FieldType::Pad(4)]);
        assert_eq!(round_trip("bytes[4]"), vec![FieldType::Bytes(4)]);
        let (pad_id, _) = field_type_identity(FieldType::Pad(4));
        let (bytes_id, _) = field_type_identity(FieldType::Bytes(4));
        assert_ne!(pad_id, bytes_id);
    }

    /// Two tables sharing a field type share its definition rather than each
    /// carrying a copy that could drift.
    #[test]
    fn a_repeated_field_type_is_defined_once() {
        let layout = parse_layout("u16,u16,u16").expect("a layout");
        let record = definitions_for_layout("type:record.three", "three", &layout);
        let integers = record
            .definitions
            .iter()
            .filter(|definition| definition.id() == "type:u16")
            .count();
        assert_eq!(integers, 1);
        let TypeDefinition::Struct { fields, size, .. } = record
            .definitions
            .last()
            .expect("the struct is written last")
        else {
            panic!("the last definition is the struct");
        };
        assert_eq!(*size, 6);
        assert_eq!(
            fields.iter().map(|field| field.offset).collect::<Vec<_>>(),
            vec![0, 2, 4]
        );
    }

    #[test]
    fn a_struct_whose_fields_do_not_reach_its_declared_size_is_refused() {
        let layout = parse_layout("u16").expect("a layout");
        let mut record = definitions_for_layout("type:record.short", "short", &layout);
        let Some(TypeDefinition::Struct { size, .. }) = record.definitions.last_mut() else {
            panic!("the last definition is the struct");
        };
        *size = 8;
        let by_id = |id: &str| {
            record
                .definitions
                .iter()
                .find(|definition| definition.id() == id)
        };
        let structure = by_id("type:record.short").expect("the struct");
        assert!(matches!(
            layout_of(structure, &by_id),
            Err(RecordTypeError::SizeMismatch {
                declared: 8,
                actual: 2,
                ..
            })
        ));
    }

    #[test]
    fn a_field_pointing_at_nothing_is_refused_rather_than_skipped() {
        let layout = parse_layout("u16").expect("a layout");
        let record = definitions_for_layout("type:record.dangling", "dangling", &layout);
        let structure = record.definitions.last().expect("the struct");
        let nothing = |_: &str| None;
        assert!(matches!(
            layout_of(structure, &nothing),
            Err(RecordTypeError::Dangling { .. })
        ));
    }

    #[test]
    fn a_struct_of_structs_is_refused_because_no_layout_expresses_it() {
        let inner = definitions_for_layout("type:record.inner", "inner", &[FieldType::U16]);
        let outer = TypeDefinition::Struct {
            id: "type:record.outer".to_owned(),
            name: "outer".to_owned(),
            size: 2,
            fields: vec![Field {
                name: "nested".to_owned(),
                offset: 0,
                type_id: "type:record.inner".to_owned(),
                notes: None,
            }],
            notes: None,
        };
        let by_id = |id: &str| {
            inner
                .definitions
                .iter()
                .find(|definition| definition.id() == id)
        };
        assert!(matches!(
            layout_of(&outer, &by_id),
            Err(RecordTypeError::Unrepresentable { .. })
        ));
    }

    #[test]
    fn a_gap_between_fields_is_refused_rather_than_decoded_as_if_contiguous() {
        let structure = TypeDefinition::Struct {
            id: "type:record.gap".to_owned(),
            name: "gap".to_owned(),
            size: 6,
            fields: vec![
                Field {
                    name: "first".to_owned(),
                    offset: 0,
                    type_id: "type:u16".to_owned(),
                    notes: None,
                },
                Field {
                    name: "second".to_owned(),
                    offset: 4,
                    type_id: "type:u16".to_owned(),
                    notes: None,
                },
            ],
            notes: None,
        };
        let u16_type = TypeDefinition::Integer {
            id: "type:u16".to_owned(),
            name: "u16".to_owned(),
            size: 2,
            signed: false,
            byte_order: BYTE_ORDER.to_owned(),
            notes: None,
        };
        let by_id = |id: &str| (id == "type:u16").then_some(&u16_type);
        assert!(matches!(
            layout_of(&structure, &by_id),
            Err(RecordTypeError::OffsetMismatch {
                offset: 4,
                expected: 2,
                ..
            })
        ));
    }

    /// An alias renames a type without changing the bytes, so it decodes as
    /// whatever it aliases.
    #[test]
    fn an_alias_reads_as_the_type_it_renames() {
        let aliased = TypeDefinition::Integer {
            id: "type:u16".to_owned(),
            name: "u16".to_owned(),
            size: 2,
            signed: false,
            byte_order: BYTE_ORDER.to_owned(),
            notes: None,
        };
        let alias = TypeDefinition::Alias {
            id: "type:tile-index".to_owned(),
            name: "tile_index".to_owned(),
            aliased_id: "type:u16".to_owned(),
            notes: None,
        };
        let resolve = |id: &str| match id {
            "type:u16" => Some(&aliased),
            "type:tile-index" => Some(&alias),
            _ => None,
        };
        let structure = TypeDefinition::Struct {
            id: "type:record.alias".to_owned(),
            name: "alias".to_owned(),
            size: 2,
            fields: vec![Field {
                name: "index".to_owned(),
                offset: 0,
                type_id: "type:tile-index".to_owned(),
                notes: None,
            }],
            notes: None,
        };
        assert_eq!(
            layout_of(&structure, &resolve).expect("a layout"),
            vec![FieldType::U16]
        );
    }
}
