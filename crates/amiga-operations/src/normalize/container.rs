//! The normalized `container.*` requests, and what filling their defaults decides.
use super::*;

/// Fully resolved `container.lha.list` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedLhaList {
    pub source: NormalizedSource,
    pub maximum_members: usize,
    pub maximum_input_bytes: u64,
}

/// Which container an extraction reads.
///
/// One handler serves both, because everything after "recover the members"
/// — the write plan, the digest, the policy, the commit — is identical. Two
/// handlers would be two chances to get the reviewed-write protocol subtly
/// different.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerKind {
    Adf,
    Lha,
}

impl ContainerKind {
    /// The operation name this kind is served under.
    #[must_use]
    pub const fn operation(self) -> OperationName {
        match self {
            Self::Adf => OperationName::ContainerAdfExtract,
            Self::Lha => OperationName::ContainerLhaExtract,
        }
    }
}

/// Fully resolved container-extraction arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedContainerExtract {
    pub kind: ContainerKind,
    pub source: NormalizedSource,
    pub destination: DestinationName,
    pub policy: OutputPolicy,
    pub maximum_input_bytes: u64,
}

/// Fully resolved `container.adf.list` arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedAdfList {
    pub source: NormalizedSource,
    pub maximum_input_bytes: u64,
    pub maximum_entries: usize,
}

/// The canonical form of one `container.adf.list`.
pub(super) fn adf_list_document(list: &NormalizedAdfList) -> Value {
    json!({
        "source": list.source.canonical(),
        "maximum_input_bytes": list.maximum_input_bytes,
        "maximum_entries": list.maximum_entries,
    })
}

/// The canonical form of one `container.lha.list`.
pub(super) fn lha_list_document(list: &NormalizedLhaList) -> Value {
    json!({
        "source": list.source.canonical(),
        "maximum_members": list.maximum_members,
        "maximum_input_bytes": list.maximum_input_bytes,
    })
}

/// The canonical form of one container extraction.
///
/// The kind is not a field of its own because it is already the operation name
/// the document is filed under, and stating it twice is how the two come to
/// disagree.
///
/// Named for its container the way [`normalize_container_extract`] beside it is,
/// because `project.extract` has a document builder too: every module here does
/// `use super::*`, so two `extract_document`s would reach each other through the
/// glob and be told apart only by which item shadowed which.
pub(super) fn container_extract_document(extract: &NormalizedContainerExtract) -> Value {
    json!({
        "source": extract.source.canonical(),
        "destination": extract.destination.as_str(),
        "policy": extract.policy,
        "maximum_input_bytes": extract.maximum_input_bytes,
    })
}

/// Resolve container-extraction arguments, shared by both container kinds.
pub(super) fn normalize_container_extract(
    kind: ContainerKind,
    arguments: &crate::request::ContainerExtractArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    {
        {
            let source = normalize_source(&arguments.source)?;
            let destination = DestinationName::parse(&arguments.destination).map_err(|error| {
                vec![
                    Diagnostic::error(DiagnosticCode::RequestSourceNameInvalid, error.to_string())
                        .at("$.request.arguments.destination"),
                ]
            })?;
            let input_bytes = normalize_input_bytes(
                arguments.maximum_input_bytes,
                limits.maximum_input_bytes(),
                diagnostics,
            )?;

            Ok(NormalizedOperation::ContainerExtract(
                NormalizedContainerExtract {
                    kind,
                    source,
                    destination,
                    policy: arguments.policy.unwrap_or_default(),
                    maximum_input_bytes: input_bytes,
                },
            ))
        }
    }
}

/// Fill in what an `container.adf.list` request left unsaid.
pub(super) fn adf_list(
    arguments: &crate::request::AdfListArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    let source = normalize_source(&arguments.source)?;
    let input_bytes = normalize_input_bytes(
        arguments.maximum_input_bytes,
        limits.maximum_input_bytes(),
        diagnostics,
    )?;
    let entries = normalize_count(
        arguments.maximum_entries,
        limits.maximum_entries(),
        "maximum_entries",
        "entries",
        diagnostics,
    )?;

    Ok(NormalizedOperation::ContainerAdfList(NormalizedAdfList {
        source,
        maximum_input_bytes: input_bytes,
        maximum_entries: entries,
    }))
}

/// Fill in what an `container.lha.list` request left unsaid.
pub(super) fn lha_list(
    arguments: &crate::request::LhaListArguments,
    limits: OperationLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<NormalizedOperation, Vec<Diagnostic>> {
    Ok(NormalizedOperation::ContainerLhaList(NormalizedLhaList {
        source: normalize_source(&arguments.source)?,
        maximum_members: normalize_count(
            arguments.maximum_members,
            limits.maximum_entries(),
            "maximum_members",
            "members",
            diagnostics,
        )?,
        maximum_input_bytes: normalize_input_bytes(
            arguments.maximum_input_bytes,
            limits.maximum_input_bytes(),
            diagnostics,
        )?,
    }))
}
