//! Externally supplied library-vector names (`[[fd]]` tables).
//!
//! Lives beside the commands rather than inside `report`, because naming a
//! library vector is not a reporting concern: `disasm report`, the sandbox
//! commands, and `boot trace` all answer "what is vector -30 of exec?", and
//! they must answer it the same way. A project that supplies an fd table and
//! sees the vector named in one command but not another has been told the
//! toolkit disagrees with itself.

use super::*;

/// Every `[[fd]]`-supplied vector description, keyed by library and by the
/// negative vector offset the call site encodes.
pub(crate) type FdNames = std::collections::BTreeMap<
    amiga_disasm::Library,
    std::collections::BTreeMap<i16, amiga_disasm::LvoEntry>,
>;

/// Load the fd tables the config in effect references.
///
/// The only entry point commands that do not otherwise parse a config should
/// use; it resolves the config exactly as every other command does, so an
/// `--config` override reaches the fd tables too.
pub(crate) fn config_fd_names(config_override: Option<&Path>) -> Result<FdNames> {
    let Some((path, config)) = optional_config(config_override)? else {
        return Ok(FdNames::new());
    };
    load_fd_names(Some(&config), path.parent())
}

/// Load the LVO names of every `[[fd]]` table `config` references, keyed by
/// library and negative vector offset. Table paths are resolved relative to
/// `config_dir`, the directory holding the config that named them.
///
/// Diagnostics are strict: an unknown library, a duplicate table, an unreadable
/// file, or a malformed fd is an error, not a silent skip. A project that
/// mistyped a path must not quietly get unnamed vectors.
pub(crate) fn load_fd_names(
    config: Option<&amiga_core::Config>,
    config_dir: Option<&Path>,
) -> Result<FdNames> {
    let mut names = FdNames::new();
    let Some(config) = config else {
        return Ok(names);
    };
    for table in &config.fd {
        let library = amiga_disasm::Library::from_name(&table.library).with_context(|| {
            format!(
                "[[fd]] library {:?} is neither a known library (exec, dos, graphics, \
                 intuition) nor a plausible `name.library`/`name.device` open-name",
                table.library
            )
        })?;
        if names.contains_key(&library) {
            bail!("duplicate [[fd]] table for {}", library.as_str());
        }
        let path = match config_dir {
            Some(directory) => directory.join(&table.path),
            None => table.path.clone(),
        };
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read fd table {}", path.display()))?;
        let parsed = amiga_disasm::fd::parse(&text)
            .with_context(|| format!("failed to parse fd table {}", path.display()))?;
        let mut vectors = std::collections::BTreeMap::new();
        for entry in parsed.entries {
            let arguments = pair_fd_arguments(&entry);
            vectors.insert(
                entry.lvo_offset(),
                amiga_disasm::LvoEntry {
                    name: entry.name,
                    arguments,
                    public: entry.public,
                },
            );
        }
        names.insert(library, vectors);
    }
    Ok(names)
}

/// The rendered name of one library vector: an fd-supplied name when the
/// project described the vector, otherwise the curated built-in name.
///
/// The same preference order `amiga_disasm::collect` applies to
/// `FactKind::LibraryCall`, so a vector never has one name in a report and
/// another in a stop reason.
///
/// A vector an fd table places in a `##private` region is suffixed, because a
/// private vector is not API: the curated tables deliberately leave those
/// unnamed, and an fd-supplied private name must not read like public API.
pub(crate) fn lvo_display_name(
    names: &FdNames,
    library: &amiga_disasm::Library,
    offset: i16,
) -> Option<String> {
    if let Some(entry) = names.get(library).and_then(|table| table.get(&offset)) {
        return Some(format!(
            "{}{}",
            entry.name,
            amiga_disasm::private_suffix(entry.public)
        ));
    }
    amiga_disasm::lvo_name(library, offset).map(str::to_owned)
}

/// Pair an fd entry's parameter names with its registers. NDK tables use `/`
/// both to join the registers of one multi-register argument
/// (`IEEEDPAdd(y,z)(d0/d1,d2/d3)`) and as a plain separator
/// (`Draw(rp,x,y)(a1,d0/d1)`), so pair by whichever reading matches the
/// parameter count; when neither does, keep the registers unnamed rather
/// than guessing.
fn pair_fd_arguments(entry: &amiga_disasm::fd::FdEntry) -> Vec<amiga_disasm::CallArgument> {
    let flattened: Vec<&str> = entry
        .registers
        .iter()
        .flat_map(|group| group.split('/'))
        .map(str::trim)
        .filter(|register| !register.is_empty())
        .collect();
    if entry.params.len() == entry.registers.len() {
        entry
            .registers
            .iter()
            .zip(&entry.params)
            .map(|(register, name)| {
                amiga_disasm::CallArgument::new(Some(name.clone()), register.clone())
            })
            .collect()
    } else if entry.params.len() == flattened.len() {
        flattened
            .iter()
            .zip(&entry.params)
            .map(|(register, name)| {
                amiga_disasm::CallArgument::new(Some(name.clone()), (*register).to_owned())
            })
            .collect()
    } else {
        entry
            .registers
            .iter()
            .map(|register| amiga_disasm::CallArgument::new(None, register.clone()))
            .collect()
    }
}
