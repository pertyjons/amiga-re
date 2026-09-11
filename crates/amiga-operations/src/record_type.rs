//! A record layout as the type definitions a `project.edit` would write.
//!
//! `amiga_project::record_type` decides what a layout string becomes as project
//! types, and `analysis.table.decode` reads them back. A frontend needs the
//! same mapping to *write* them, and it reaches the project through this crate
//! rather than through `amiga-project` directly — so the conversion is offered
//! here in the shape [`crate::request::ProjectEdit::DefineType`] accepts,
//! instead of every adapter reassembling it.
//!
//! Nothing is decided here: the definitions come from `amiga-project`, and this
//! is the serialization boundary.

use crate::request::ProjectEdit;

/// One type definition, with the id a caller checks against what the project
/// already defines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordTypeDefinition {
    pub id: String,
    /// The definition as `project.edit` takes it.
    pub value: serde_json::Map<String, serde_json::Value>,
}

impl RecordTypeDefinition {
    /// This definition as the edit that would write it.
    #[must_use]
    pub fn define(&self) -> ProjectEdit {
        ProjectEdit::DefineType {
            definition: self.value.clone(),
        }
    }
}

/// Every type definition one record layout needs, and the struct that ties them
/// together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordTypePlan {
    /// What a table resource's `type_id` should name.
    pub struct_id: String,
    /// The struct and every type its fields point at, primitives first.
    ///
    /// Type identities are canonical and shared — every `u16` field in every
    /// table in a project points at one `type:u16` — so a caller writes only
    /// the ones the project does not already define, and finds out which from
    /// `project.describe`'s `types`.
    pub definitions: Vec<RecordTypeDefinition>,
}

/// Turn a parsed record layout into the definitions that record it.
///
/// # Errors
/// Never fails on the layout itself: every layout token has a type. The
/// `Option` covers only a definition that will not serialize into a JSON
/// object, which the format's own types cannot produce.
#[must_use]
pub fn definitions_for_layout(
    struct_id: &str,
    name: &str,
    layout: &[amiga_core::record::FieldType],
) -> RecordTypePlan {
    let record = amiga_project::record_type::definitions_for_layout(struct_id, name, layout);
    RecordTypePlan {
        struct_id: record.struct_id,
        definitions: record
            .definitions
            .iter()
            .filter_map(|definition| {
                let serde_json::Value::Object(value) = serde_json::to_value(definition).ok()?
                else {
                    return None;
                };
                Some(RecordTypeDefinition {
                    id: definition.id().clone(),
                    value,
                })
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping survives the trip through JSON, which is the only thing this
    /// module adds over the one in `amiga-project`.
    #[test]
    fn every_definition_serializes_into_an_object_with_its_own_id() {
        let layout = amiga_core::record::parse_layout("u16,u16,ptr,char[16]").expect("a layout");
        let plan = definitions_for_layout("type:record.enemies", "enemy_record", &layout);
        assert_eq!(plan.struct_id, "type:record.enemies");
        assert!(
            plan.definitions
                .iter()
                .all(|definition| definition.value["id"] == definition.id.as_str())
        );
        assert!(
            plan.definitions
                .iter()
                .any(|definition| definition.id == "type:record.enemies")
        );
        // The struct is last, so a caller writing them in order defines every
        // type before the struct that points at it.
        assert_eq!(
            plan.definitions
                .last()
                .map(|definition| definition.id.as_str()),
            Some("type:record.enemies")
        );
    }

    /// Each definition round-trips back into the format's own type vocabulary,
    /// which is what `project.edit` does with it.
    #[test]
    fn every_definition_deserializes_back_into_the_formats_type() {
        let layout =
            amiga_core::record::parse_layout("u8,pad[3],bytes[8],i32,ptr").expect("a layout");
        for definition in definitions_for_layout("type:record.mixed", "mixed", &layout).definitions
        {
            let parsed: Result<amiga_project::document::TypeDefinition, _> =
                serde_json::from_value(serde_json::Value::Object(definition.value.clone()));
            assert!(parsed.is_ok(), "{}: {parsed:?}", definition.id);
        }
    }
}
