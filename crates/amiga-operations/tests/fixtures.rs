//! The test data this crate's suite reads is present in this checkout.
//!
//! Every fixture beside this suite is synthetic and holds no third-party bytes,
//! which is what `fixtures/README.md` documents and what makes committing them
//! correct. A blanket `*.adf` ignore rule used to exclude `volume.adf` anyway,
//! so a fresh clone or a new git worktree ran the suite against a file that was
//! not there and failed with mismatched listings rather than a missing input.
//!
//! This names the gap in one place. A failure here means the checkout is
//! incomplete, not that the operations changed.

use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn every_fixture_the_suite_reads_is_present() {
    for name in [
        "sample.bin",
        "volume.adf",
        "source.survey.request.json",
        "source.survey.response.json",
        "container.adf.list.request.json",
        "container.adf.list.response.json",
    ] {
        let path = fixture(name);
        assert!(
            path.is_file(),
            "{} is missing. It is committed test data, not private media, so \
             this checkout is incomplete rather than merely unprepared.",
            path.display()
        );
    }
}
