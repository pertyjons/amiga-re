//! Output budgets apply during recovery, including reviewed commits.
use std::path::PathBuf;

use amiga_operations::{
    ContainerExtractArguments, DiagnosticCode, ExecutionContext, ExecutionMode,
    FilesystemDestinationResolver, FilesystemSourceResolver, OperationLimits,
    OperationRequestDocument, ProjectExtractArguments, ProjectInitArguments, ProjectLocator,
    RequestEnvelope, Router, Status,
};

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("amiga-lha-budget-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn archive(method: &[u8; 5]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for name in *b"ab" {
        let payload = if method == b"-lh0-" {
            b"data".as_slice()
        } else {
            &[]
        };
        let mut header = method.to_vec();
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        header.extend_from_slice(&4_u32.to_le_bytes());
        header.extend_from_slice(&[0; 4]);
        header.extend_from_slice(&[0x20, 0, 1, name]);
        header.extend_from_slice(&amiga_lha::crc16(b"data").to_le_bytes());
        bytes.push(header.len() as u8);
        bytes.push(
            header
                .iter()
                .fold(0_u8, |sum, byte| sum.wrapping_add(*byte)),
        );
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(payload);
    }
    bytes.push(0);
    bytes
}

fn request(document: OperationRequestDocument, mode: ExecutionMode) -> RequestEnvelope {
    let mut request = RequestEnvelope::read(document);
    request.execution.mode = mode;
    request
}

fn assert_limit(outcome: &amiga_operations::OperationOutcome) {
    assert_eq!(outcome.status, Status::Error, "{:?}", outcome.diagnostics);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::LimitExceeded),
        "{:?}",
        outcome.diagnostics
    );
    assert!(outcome.result.is_none());
}

#[test]
fn container_budget_failure_writes_nothing_even_with_a_reviewed_plan() {
    let workspace = Workspace::new();
    let root = &workspace.0;
    std::fs::write(root.join("input.lha"), archive(b"-lh0-")).unwrap();
    let sources = FilesystemSourceResolver::new(root.clone());
    let destinations = FilesystemDestinationResolver::new(root.clone());
    let context = ExecutionContext::new(&sources)
        .with_destinations(&destinations)
        .with_limits(OperationLimits::default().with_maximum_total_recovered_bytes(8));
    let document = OperationRequestDocument::ContainerLhaExtract(ContainerExtractArguments::new(
        "input.lha",
        "output",
    ));
    let prepared = Router::execute(&request(document.clone(), ExecutionMode::Prepare), &context);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let digest = prepared
        .container_extract()
        .unwrap()
        .plan
        .plan_sha256
        .clone();
    let limited =
        context.with_limits(OperationLimits::default().with_maximum_total_recovered_bytes(7));
    for mode in [
        ExecutionMode::Prepare,
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest,
        },
    ] {
        assert_limit(&Router::execute(&request(document.clone(), mode), &limited));
        assert!(!root.join("output").exists());
    }
    // The declared expansion is refused before this truncated stream is decoded.
    std::fs::write(root.join("input.lha"), archive(b"-lh5-")).unwrap();
    let limited =
        limited.with_limits(OperationLimits::default().with_maximum_total_recovered_bytes(3));
    assert_limit(&Router::execute(
        &request(document, ExecutionMode::Prepare),
        &limited,
    ));
    assert!(!root.join("output").exists());
}

#[test]
fn project_budget_is_shared_across_archives_and_preserves_documents_on_failure() {
    let workspace = Workspace::new();
    let root = &workspace.0;
    for name in ["one.lha", "two.lha"] {
        std::fs::write(root.join(name), archive(b"-lh0-")).unwrap();
    }
    let sources = FilesystemSourceResolver::new(root.clone());
    let destinations = FilesystemDestinationResolver::new(root.clone());
    let context = ExecutionContext::new(&sources).with_destinations(&destinations);
    let init = OperationRequestDocument::ProjectInit(ProjectInitArguments::new(
        "Budget",
        "project",
        vec!["one.lha".to_owned(), "two.lha".to_owned()],
    ));
    let prepared = Router::execute(&request(init.clone(), ExecutionMode::Prepare), &context);
    let digest = prepared.project_init().unwrap().plan.plan_sha256.clone();
    assert_eq!(
        Router::execute(
            &request(
                init,
                ExecutionMode::CommitReviewed {
                    approved_plan_sha256: digest
                }
            ),
            &context
        )
        .status,
        Status::Success
    );
    let loaded = amiga_project::load(&root.join("project")).unwrap();
    let sources_path = root
        .join("project")
        .join(&loaded.project.root.documents.sources);
    let before = std::fs::read(&sources_path).unwrap();
    let mut extract = request(
        OperationRequestDocument::ProjectExtract(ProjectExtractArguments::default()),
        ExecutionMode::Prepare,
    );
    extract.project = Some(ProjectLocator::Path {
        path: "project".to_owned(),
    });
    let context =
        context.with_limits(OperationLimits::default().with_maximum_total_recovered_bytes(16));
    let prepared = Router::execute(&extract, &context);
    assert_eq!(
        prepared.status,
        Status::Prepared,
        "{:?}",
        prepared.diagnostics
    );
    let digest = prepared.project_extract().unwrap().plan.plan_sha256.clone();
    assert_eq!(prepared.project_extract().unwrap().objects.len(), 4);
    let context =
        context.with_limits(OperationLimits::default().with_maximum_total_recovered_bytes(15));
    for mode in [
        ExecutionMode::Prepare,
        ExecutionMode::CommitReviewed {
            approved_plan_sha256: digest,
        },
    ] {
        extract.execution.mode = mode;
        assert_limit(&Router::execute(&extract, &context));
        assert_eq!(std::fs::read(&sources_path).unwrap(), before);
        let output = root.join("project/extracted");
        assert!(!output.exists() || std::fs::read_dir(output).unwrap().next().is_none());
    }
}
