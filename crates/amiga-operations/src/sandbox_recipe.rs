//! Immutable, versioned sandbox recipes used by project derivations.
//!
//! The request uses the existing operation vocabulary. Its normalized digest
//! binds every resolved default; replay refuses a build or limit change that
//! would reinterpret it. Project selectors supply checksum-verified inputs.

use serde::{Deserialize, Serialize};

use crate::{NormalizedOperation, OperationLimits, OperationRequestDocument, RequestEnvelope};

const RECIPE_VERSION: u32 = 1;
const EXECUTION_VERSION: u32 = 1;
const MAXIMUM_RECIPE_BYTES: usize = 1024 * 1024;

/// A complete call and the normalization it was reviewed against.
///
/// Construct with [`Self::new`], serialize with serde, then register those bytes
/// as a pinned project source. Unknown fields and noncanonical encodings are
/// refused on replay. Execution version 1 uses the current bounded MC68000/OCS
/// model; incompatible execution changes require a new version.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRecipe {
    recipe_version: u32,
    execution_version: u32,
    request: RequestEnvelope,
    normalized_request_sha256: String,
}

/// A recipe cannot be frozen or replayed under the stated execution contract.
#[derive(Debug, thiserror::Error)]
#[error("invalid sandbox recipe: {0}")]
pub struct RecipeError(String);

impl SandboxRecipe {
    /// Freeze JSON without silently discarding unknown execution fields.
    ///
    /// Omitted defaults are accepted; explicitly supplied fields must survive
    /// the request type's serialization. Input is bounded to 1 MiB.
    ///
    /// # Errors
    /// Refuses malformed JSON, unknown or noncanonical fields, and any request
    /// that [`Self::new`] cannot freeze.
    pub fn from_request_json(bytes: &[u8], limits: OperationLimits) -> Result<Self, RecipeError> {
        if bytes.len() > MAXIMUM_RECIPE_BYTES {
            return Err(RecipeError("request exceeds 1 MiB".to_owned()));
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| RecipeError(error.to_string()))?;
        let request: RequestEnvelope = serde_json::from_value(value.clone())
            .map_err(|error| RecipeError(error.to_string()))?;
        let encoded =
            serde_json::to_value(&request).map_err(|error| RecipeError(error.to_string()))?;
        if !retains_fields(&value, &encoded) {
            return Err(RecipeError(
                "unknown or noncanonical request fields would be discarded".to_owned(),
            ));
        }
        Self::new(request, limits)
    }

    /// Freeze a read-only `env.sandbox.call` under these normalization limits.
    ///
    /// The hunk, load origin, entry offset, stack, and instruction budget must
    /// be explicit. No source is opened or routine executed here.
    ///
    /// # Errors
    /// Refuses other operations, implicit layout, or lossy normalization.
    pub fn new(request: RequestEnvelope, limits: OperationLimits) -> Result<Self, RecipeError> {
        let normalized = checked_normalize(&request, limits).map_err(RecipeError)?;
        let recipe = Self {
            recipe_version: RECIPE_VERSION,
            execution_version: EXECUTION_VERSION,
            request,
            normalized_request_sha256: normalized.request.digest(),
        };
        let bytes = serde_json::to_vec(&recipe).map_err(|error| RecipeError(error.to_string()))?;
        if bytes.len() > MAXIMUM_RECIPE_BYTES {
            return Err(RecipeError("recipe exceeds 1 MiB".to_owned()));
        }
        Ok(recipe)
    }

    pub(crate) fn parse(
        bytes: &[u8],
        limits: OperationLimits,
    ) -> Result<crate::NormalizedSandboxCall, String> {
        if bytes.len() > MAXIMUM_RECIPE_BYTES {
            return Err("sandbox recipe exceeds 1 MiB".to_owned());
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let recipe: Self = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        if recipe.recipe_version != RECIPE_VERSION || recipe.execution_version != EXECUTION_VERSION
        {
            return Err("unsupported sandbox recipe or execution version".to_owned());
        }
        // Flattened request structs cannot reliably reject unknown fields at
        // every nesting level. Require exactly the serializer's document shape
        // so no unsupported execution input is silently discarded.
        if serde_json::to_value(&recipe).map_err(|e| e.to_string())? != value {
            return Err("sandbox recipe contains unknown fields or a noncanonical request; regenerate it with SandboxRecipe::new".to_owned());
        }
        let normalized = checked_normalize(&recipe.request, limits)?;
        if normalized.request.digest() != recipe.normalized_request_sha256 {
            return Err("sandbox recipe normalization digest changed; refusing to reinterpret execution inputs".to_owned());
        }
        match normalized.request.operation() {
            NormalizedOperation::EnvSandboxCall(call) => Ok(call.clone()),
            _ => Err("sandbox recipe is not env.sandbox.call".to_owned()),
        }
    }
}

fn retains_fields(input: &serde_json::Value, encoded: &serde_json::Value) -> bool {
    match (input, encoded) {
        (serde_json::Value::Object(input), serde_json::Value::Object(encoded)) => {
            input.iter().all(|(key, value)| {
                encoded
                    .get(key)
                    .is_some_and(|other| retains_fields(value, other))
            })
        }
        (serde_json::Value::Array(input), serde_json::Value::Array(encoded)) => {
            input.len() == encoded.len()
                && input
                    .iter()
                    .zip(encoded)
                    .all(|(value, other)| retains_fields(value, other))
        }
        _ => input == encoded,
    }
}

fn checked_normalize(
    request: &RequestEnvelope,
    limits: OperationLimits,
) -> Result<crate::Normalized, String> {
    let OperationRequestDocument::EnvSandboxCall(call) = &request.request else {
        return Err("only env.sandbox.call can derive a project object".to_owned());
    };
    if call.run.hunk.is_none()
        || call.run.load_origin.is_none()
        || call.run.entry_offset.is_none()
        || call.run.stack.is_none()
        || call.run.maximum_steps.is_none()
    {
        return Err("a sandbox recipe requires explicit hunk, load_origin, entry_offset, stack, and maximum_steps".to_owned());
    }
    let normalized = crate::normalize(request, limits).map_err(|d| format!("{d:?}"))?;
    if !normalized.diagnostics.is_empty() {
        return Err(format!(
            "recipe normalization must be lossless: {:?}",
            normalized.diagnostics
        ));
    }
    Ok(normalized)
}
