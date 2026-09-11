//! The composed semantic fact report (`disasm report`).
//!
//! Composes the game-agnostic facts collected by `amiga-disasm` with the
//! knowledge only the CLI holds — HUNK relocations, config symbols, and
//! custom-chip register names — and renders the result as grep-friendly text
//! or as the JSON interchange format other tools consume. Both renderers read
//! the same fact list; neither shows a fact the other cannot.

use amiga_disasm::report::{Confidence, Evidence, Fact, FactKind, MemoryAddressing, Producer};

use super::*;

/// The identifier stored in every JSON report next to
/// [`amiga_disasm::SCHEMA_VERSION`].
const REPORT_SCHEMA: &str = "amiga-re.semantic-report";

/// Compose the full fact list for a prepared analysis: collected facts plus
/// relocation facts for the analyzed hunk and config-symbol facts that map
/// into it.
/// The fact list for an analysis, from `analysis.code.facts`.
///
/// What stays here is the *config's* symbols. They are this frontend's table,
/// not a fact about the bytes, and the operation would have to be handed them
/// to know about them — which is the wrong direction: `[[symbols]]` is a name a
/// person put in a file beside their checkout.
///
/// The operation owns composed analyses, relocation resolution, and reverse links. The
/// CLI renders those shared facts without recomputing them.
pub(crate) fn compose_facts(
    prepared: &Prepared,
    library: Option<amiga_disasm::Library>,
    base_register: u8,
) -> Result<Vec<Fact>> {
    let name = amiga_operations::SourceName::parse("analysis-input")?;
    let mut arguments = amiga_operations::CodeFactsArguments::new(name.as_str())
        .from_entries(prepared.entries.clone())
        .through_register(base_register)
        .with_library_vectors(library_vectors(prepared)?);
    arguments = match prepared.region() {
        amiga_operations::CodeRegion::Hunk => arguments.in_hunk(prepared.hunk()),
        amiga_operations::CodeRegion::Raw => arguments.in_raw(
            prepared
                .expected_sha256()
                .context("a raw prepared image has no digest pin")?,
        ),
        amiga_operations::CodeRegion::BootBlock => {
            unreachable!("the disassembly prologue does not prepare boot blocks")
        }
    };
    if let Some(base) = prepared.base {
        arguments = arguments.mapped_at(base.origin);
    }
    if let Some(library) = library {
        arguments = arguments.with_default_library(library.as_str());
    }

    let sources = amiga_operations::InMemorySourceResolver::new(
        amiga_operations::ResolvedSource::new(name, prepared.bytes.clone().into()),
    );
    let context = amiga_operations::ExecutionContext::new(&sources);
    let outcome = amiga_operations::Router::execute(
        &amiga_operations::RequestEnvelope::read(
            amiga_operations::OperationRequestDocument::AnalysisCodeFacts(arguments),
        ),
        &context,
    );
    crate::commands::fail_on_errors(&outcome)
        .with_context(|| format!("failed to compose facts for {}", prepared.source_label()))?;
    let composed = outcome
        .analysis_code_facts()
        .context("the fact composition returned no result")?;
    let mut facts = composed.facts.clone();

    if let Some(config) = &prepared.config {
        for symbol in &config.symbols {
            // Symbols are absolute addresses; only those mapping into the
            // analyzed hunk become facts of this report.
            let offset = match prepared.base {
                Some(base) => base.abs_to_offset(symbol.addr),
                None => Some(symbol.addr),
            };
            let Some(offset) = offset.filter(|offset| (*offset as usize) < prepared.code().len())
            else {
                continue;
            };
            facts.push(Fact {
                subject: offset,
                kind: FactKind::Symbol {
                    addr: symbol.addr,
                    name: symbol.name.clone(),
                },
                confidence: Confidence::User,
                producer: Producer::Config,
                evidence: vec![Evidence::Config { addr: symbol.addr }],
            });
        }
    }

    facts.sort();
    facts.dedup();
    Ok(facts)
}

/// The fd tables this frontend read, as request data.
///
/// The tables are its configuration; the *names they give a vector* are facts
/// the model must keep. Passing them rather than a path is what lets two
/// adapters given the same table produce the same facts.
fn library_vectors(prepared: &Prepared) -> Result<Vec<amiga_operations::LibraryVector>> {
    let tables = load_fd_names(prepared.config.as_ref(), prepared.config_dir.as_deref())?;
    let mut vectors = Vec::new();
    for (library, entries) in tables {
        for (lvo, entry) in entries {
            vectors.push(amiga_operations::LibraryVector {
                library: library.as_str().to_owned(),
                lvo,
                name: entry.name,
                arguments: entry
                    .arguments
                    .into_iter()
                    .map(|argument| amiga_operations::VectorArgument {
                        register: argument.register,
                        name: argument.name,
                    })
                    .collect(),
                public: entry.public,
            });
        }
    }
    Ok(vectors)
}

/// Where a HUNK relocation points once its stored addend has been read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RelocationTarget {
    pub(crate) hunk: u32,
    pub(crate) offset: u32,
}

/// Baseline statistics over a composed fact list (roadmap Stage 0).
#[derive(Serialize)]
pub(crate) struct ReportStats {
    total_bytes: usize,
    decoded_bytes: usize,
    instructions: usize,
    functions: usize,
    calls: usize,
    /// Calls and jumps a relocation proves leave the analyzed hunk. They are
    /// resolved, so they are not `unresolved_flow`; they land in another hunk,
    /// so they are not `calls` of this one either.
    external_flow: usize,
    unresolved_flow: usize,
    references_resolved: usize,
    references_unresolved: usize,
    /// Resolved references a relocation proves the destination of, as opposed
    /// to ones resolved by reading the operand as an address of this hunk.
    /// A subset of `references_resolved`.
    references_relocated: usize,
    hardware_accesses_named: usize,
    hardware_accesses_unknown: usize,
    /// Library-call naming and argument resolution, folded from the same facts
    /// by `amiga-disasm` rather than counted a second time here — one fold, so
    /// the header can never disagree with the facts under it.
    resolution: amiga_disasm::ResolutionStats,
}

/// How a reference site's target was resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceClass {
    /// A HUNK relocation names the destination hunk.
    Relocated,
    /// The operand reads as an address inside the analyzed hunk.
    InImage,
    /// Neither: a hardware register, another image, or an unmapped address.
    Unresolved,
}

impl ReportStats {
    pub(crate) fn compute(prepared: &Prepared, facts: &[Fact]) -> Self {
        let coverage = amiga_disasm::coverage(&prepared.analysis, prepared.code().len());
        let mut stats = Self {
            total_bytes: coverage.total_bytes,
            decoded_bytes: coverage.decoded_bytes,
            instructions: coverage.instructions,
            functions: coverage.functions,
            calls: coverage.calls,
            external_flow: 0,
            unresolved_flow: 0,
            references_resolved: 0,
            references_unresolved: 0,
            references_relocated: 0,
            hardware_accesses_named: 0,
            hardware_accesses_unknown: 0,
            resolution: amiga_disasm::ResolutionStats::from_facts(facts),
        };
        let resolver = Resolver::for_prepared(prepared);
        for fact in facts {
            match &fact.kind {
                FactKind::UnresolvedFlow => stats.unresolved_flow += 1,
                FactKind::ExternalFlow { .. } => stats.external_flow += 1,
                FactKind::Reference {
                    target,
                    addressing,
                    operand,
                } => {
                    match resolver.classify_reference(fact.subject, *target, *addressing, *operand)
                    {
                        ReferenceClass::Relocated => {
                            stats.references_resolved += 1;
                            stats.references_relocated += 1;
                        }
                        ReferenceClass::InImage => stats.references_resolved += 1,
                        ReferenceClass::Unresolved => stats.references_unresolved += 1,
                    }
                }
                FactKind::HardwareAccess { offset, .. } => {
                    if amiga_hw::register_name(*offset).is_some() {
                        stats.hardware_accesses_named += 1;
                    } else {
                        stats.hardware_accesses_unknown += 1;
                    }
                }
                _ => {}
            }
        }
        stats
    }
}

/// Resolves offsets, addresses, and names against the config, mapped origin,
/// and address spaces a listing was prepared with. Renderers for code that is
/// not a hunk of a loaded executable (boot code) use [`Resolver::unmapped`],
/// which resolves nothing and prints addresses in the one frame it has.
pub(crate) struct Resolver<'a> {
    config: Option<&'a amiga_core::Config>,
    /// The reviewed names of the project describing these bytes, consulted
    /// before the config table. A name a person reviewed and recorded in the
    /// format the toolkit calls authoritative must not be the one the listing
    /// omits.
    names: Option<&'a crate::commands::ProjectNames>,
    /// The analyzed hunk, which the project's offsets are relative to.
    hunk: Option<u32>,
    base: Option<amiga_core::config::Base>,
    /// The analyzed hunk's address spaces; `None` for code with no hunk.
    map: Option<amiga_core::AddressMap>,
    /// The decoded code and the relocations that prove where its operands
    /// really point. Both are needed and neither is an index of its own: the
    /// answer comes from `amiga_disasm::Relocations`, which the traversal and
    /// the fact list already use, so a renderer cannot disagree with them.
    relocations: Option<(
        &'a amiga_disasm::ControlFlowAnalysis,
        &'a amiga_disasm::Relocations,
    )>,
}

impl<'a> Resolver<'a> {
    /// A resolver with no config, no mapped origin, no hunk frames, and no
    /// relocations.
    pub(crate) fn unmapped() -> Self {
        Self {
            config: None,
            names: None,
            hunk: None,
            base: None,
            map: None,
            relocations: None,
        }
    }

    /// A resolver over names alone: the config table, the open project, and
    /// the mapped origin the two are read through.
    ///
    /// No analysis and no relocations, because a name needs neither. Exists so
    /// a command that routes through `amiga-operations` can still render the
    /// reviewed names without building a second control-flow analysis to hang
    /// them on.
    pub(crate) const fn for_names(
        config: Option<&'a amiga_core::Config>,
        names: Option<&'a crate::commands::ProjectNames>,
        hunk: u32,
        base: Option<amiga_core::config::Base>,
    ) -> Self {
        Self {
            config,
            names,
            hunk: Some(hunk),
            base,
            map: None,
            relocations: None,
        }
    }

    pub(crate) fn for_prepared(prepared: &'a Prepared) -> Self {
        Self {
            config: prepared.config.as_ref(),
            names: prepared.names.as_ref(),
            hunk: Some(prepared.hunk()),
            base: prepared.base,
            map: Some(prepared.address_map()),
            relocations: Some((&prepared.analysis, prepared.flow_relocations())),
        }
    }

    /// The project's reviewed name for a location in the analyzed hunk.
    ///
    /// Offsets are the project's frame, so an absolute address is converted
    /// through the mapped origin first; without one there is nothing to convert
    /// through, and guessing would name the wrong bytes.
    fn project_symbol(&self, offset: Option<u32>, absolute: Option<u32>) -> Option<&'a str> {
        let names = self.names?;
        let hunk = self.hunk?;
        let offset = match offset {
            Some(offset) => offset,
            None => self.base?.abs_to_offset(absolute?)?,
        };
        names.at(hunk, u64::from(offset))
    }

    /// Where an absolute operand of `site` naming `target` really points, when
    /// a relocation patches it. A relocated operand's destination is the
    /// relocation's target hunk; its stored addend alone proves nothing.
    fn relocated_reference(
        &self,
        site: u32,
        target: u32,
        addressing: amiga_disasm::RefKind,
        operand: Option<u32>,
    ) -> Option<RelocationTarget> {
        if addressing != amiga_disasm::RefKind::Absolute {
            return None;
        }
        let (analysis, relocations) = self.relocations?;
        let end = analysis.instructions.get(&site)?.end;
        let relocation = relocations.resolve_operand(site, end, operand, target)?;
        Some(RelocationTarget {
            hunk: relocation.target_hunk,
            offset: relocation.target_offset,
        })
    }

    /// The hunk offset a reference target resolves to, if any: PC-relative
    /// targets already are offsets; absolute targets go through the mapped
    /// origin when one is set.
    ///
    /// **Absolute short has no offset reading without a base.** The long form
    /// falls back to the raw value because the offset and absolute frames
    /// coincide for code analyzed at zero, and because a `HUNK_RELOC32` record
    /// may genuinely make the operand a hunk offset. Neither holds for sixteen
    /// bits: no relocation record patches them, and the addresses the form
    /// reaches are low memory, where a fabricated offset lands inside the code.
    fn reference_offset(&self, target: u32, addressing: amiga_disasm::RefKind) -> Option<u32> {
        match addressing {
            amiga_disasm::RefKind::PcRelative => Some(target),
            amiga_disasm::RefKind::Absolute => match self.base {
                Some(base) => base.abs_to_offset(target),
                None => Some(target),
            },
            amiga_disasm::RefKind::AbsoluteShort => self.base?.abs_to_offset(target),
        }
    }

    /// How a reference site's target is resolved, which is what the report's
    /// reference counts are counting.
    fn classify_reference(
        &self,
        site: u32,
        target: u32,
        addressing: amiga_disasm::RefKind,
        operand: Option<u32>,
    ) -> ReferenceClass {
        if self
            .relocated_reference(site, target, addressing, operand)
            .is_some()
        {
            // The relocation names the target hunk, so the reference is
            // resolved whatever its stored addend happens to be.
            ReferenceClass::Relocated
        } else if self.target_location(target, addressing).is_some() {
            ReferenceClass::InImage
        } else {
            ReferenceClass::Unresolved
        }
    }

    /// Every address space of a hunk offset inside the analyzed hunk.
    pub(crate) fn locate(&self, offset: u32) -> Option<amiga_core::Location> {
        let map = self.map?;
        let offset = amiga_core::HunkOffset::new(offset);
        map.contains(offset).then(|| map.locate(offset))
    }

    /// The stable anchor of an entity of `kind` at a hunk offset. `None` for
    /// code with no hunk frame, which has no report entities to link to.
    fn anchor(&self, kind: amiga_core::EntityKind, offset: u32) -> Option<amiga_core::Anchor> {
        Some(self.map?.anchor(kind, amiga_core::HunkOffset::new(offset)))
    }

    /// The hunk offset of a reference target that lands inside the analyzed
    /// hunk; `None` for a target outside it (a hardware register, an address
    /// in another hunk, an unmapped absolute operand).
    pub(crate) fn reference_offset_in_image(
        &self,
        target: u32,
        addressing: amiga_disasm::RefKind,
    ) -> Option<u32> {
        let offset = self.reference_offset(target, addressing)?;
        self.locate(offset).map(|_| offset)
    }

    /// Where an operand of `site` really points inside the analyzed hunk,
    /// reading a relocated operand through the record that patches it.
    ///
    /// This is the resolution every consumer of a [`FactKind::Reference`] must
    /// use: the stored addend of a cross-hunk operand is a small number that
    /// lands *somewhere* in this hunk by accident, and taking it at face value
    /// invents a cross-reference the report itself does not have.
    pub(crate) fn reference_target_in_image(
        &self,
        site: u32,
        target: u32,
        addressing: amiga_disasm::RefKind,
        operand: Option<u32>,
    ) -> Option<u32> {
        match self.relocated_reference(site, target, addressing, operand) {
            // Only a relocation into the analyzed hunk resolves here.
            Some(relocation) => (Some(relocation.hunk) == self.analyzed_hunk())
                .then_some(relocation.offset)
                .filter(|offset| self.locate(*offset).is_some()),
            None => self.reference_offset_in_image(target, addressing),
        }
    }

    /// Every address space of a reference target that lands inside the
    /// analyzed hunk.
    fn target_location(
        &self,
        target: u32,
        addressing: amiga_disasm::RefKind,
    ) -> Option<amiga_core::Location> {
        self.locate(self.reference_offset(target, addressing)?)
    }

    /// A reference target with the address space of every frame that resolves
    /// spelled out, e.g. `hunk0+0x44 (abs 0xe682, file 0x64)` for a target
    /// inside the analyzed hunk and `abs 0xdff096` for one outside it.
    ///
    /// A relocated operand is shown at the destination its relocation proves,
    /// never at the addend the file stores, which for a cross-hunk reference
    /// is a small number with no meaning in this hunk.
    fn reference_location_text(
        &self,
        site: u32,
        target: u32,
        addressing: amiga_disasm::RefKind,
        operand: Option<u32>,
    ) -> String {
        if let Some(relocated) = self.relocated_reference(site, target, addressing, operand) {
            return self.relocation_target_text(relocated.hunk, relocated.offset);
        }
        if let Some(location) = self.target_location(target, addressing) {
            return location.to_string();
        }
        match (addressing, self.map) {
            (amiga_disasm::RefKind::Absolute | amiga_disasm::RefKind::AbsoluteShort, _) => {
                amiga_core::Address::Runtime(amiga_core::RuntimeAddress::new(target)).to_string()
            }
            (amiga_disasm::RefKind::PcRelative, Some(map)) => {
                amiga_core::Address::Hunk(map.hunk(), amiga_core::HunkOffset::new(target))
                    .to_string()
            }
            // Code with no hunk frame: the header declares the one frame the
            // listing uses.
            (amiga_disasm::RefKind::PcRelative, None) => format!("{target:#x}"),
        }
    }

    /// The hunk-relative form alone, for the compact annotations of a listing.
    fn reference_short_text(
        &self,
        site: u32,
        target: u32,
        addressing: amiga_disasm::RefKind,
        operand: Option<u32>,
    ) -> String {
        if self
            .relocated_reference(site, target, addressing, operand)
            .is_some()
        {
            return self.reference_location_text(site, target, addressing, operand);
        }
        match self.target_location(target, addressing) {
            Some(location) => location.short().to_string(),
            None => self.reference_location_text(site, target, addressing, operand),
        }
    }

    /// A mapped address with every frame that resolves, e.g.
    /// `hunk0+0x4 (abs 0x10004, file 0x24)` for an address inside the analyzed
    /// hunk and `abs 0x10004` for one outside it.
    fn runtime_location_text(&self, address: u32) -> String {
        match self.locate_runtime(address) {
            Some(location) => location.to_string(),
            None => {
                amiga_core::Address::Runtime(amiga_core::RuntimeAddress::new(address)).to_string()
            }
        }
    }

    /// A hunk offset of the analyzed hunk with every frame that resolves; an
    /// offset outside the hunk keeps the hunk frame it was given.
    fn offset_location_text(&self, offset: u32) -> String {
        match (self.locate(offset), self.map) {
            (Some(location), _) => location.to_string(),
            (None, Some(map)) => {
                amiga_core::Address::Hunk(map.hunk(), amiga_core::HunkOffset::new(offset))
                    .to_string()
            }
            (None, None) => format!("{offset:#x}"),
        }
    }

    /// A hunk offset with its symbol and every address space that resolves,
    /// e.g. `helper @ hunk0+0x42 (abs 0x10042, file 0x62)`.
    pub(crate) fn describe_offset(&self, offset: u32) -> String {
        self.named_location(
            self.target_symbol(Some(offset), None),
            self.offset_location_text(offset),
        )
    }

    /// A mapped address with its symbol and every address space that resolves.
    pub(crate) fn describe_runtime(&self, address: u32) -> String {
        self.named_location(
            self.target_symbol(None, Some(address)),
            self.runtime_location_text(address),
        )
    }

    /// `symbol @ location`, or the location alone when nothing names it.
    fn named_location(&self, symbol: Option<&str>, location: String) -> String {
        match symbol {
            Some(name) => format!("{name} @ {location}"),
            None => location,
        }
    }

    /// The hunk this report resolves address spaces for, if any.
    pub(crate) fn analyzed_hunk(&self) -> Option<u32> {
        self.map.map(|map| map.hunk().get())
    }

    /// Every address space of a mapped address that lands inside the analyzed
    /// hunk.
    fn locate_runtime(&self, address: u32) -> Option<amiga_core::Location> {
        self.map?
            .locate_runtime(amiga_core::RuntimeAddress::new(address))
    }

    /// A relocation target: every frame that resolves when it points into the
    /// analyzed hunk, the target hunk's own frame when it points elsewhere,
    /// since this report maps only one hunk.
    pub(crate) fn relocation_target_text(&self, target_hunk: u32, target_offset: u32) -> String {
        if self.analyzed_hunk() == Some(target_hunk) {
            return self.named_location(
                self.target_symbol(Some(target_offset), None),
                self.offset_location_text(target_offset),
            );
        }
        amiga_core::Address::Hunk(
            amiga_core::HunkId::new(target_hunk),
            amiga_core::HunkOffset::new(target_offset),
        )
        .to_string()
    }

    /// The config symbol for a target, resolving offsets through the mapped
    /// origin into the absolute frame config symbols use.
    fn target_symbol(&self, offset: Option<u32>, absolute: Option<u32>) -> Option<&'a str> {
        if let Some(name) = self.project_symbol(offset, absolute) {
            return Some(name);
        }
        let config = self.config?;
        let absolute = absolute.or_else(|| {
            let offset = offset?;
            match self.base {
                Some(base) => base.offset_to_abs(offset),
                None => Some(offset),
            }
        })?;
        config.symbol_name(absolute)
    }

    /// The config symbol for a reference target, looked up in the frame the
    /// target is expressed in. A relocated operand uses the relocation's
    /// target hunk and offset rather than its stored addend; ordinary absolute
    /// targets resolve directly and PC-relative targets go through the mapped
    /// origin.
    fn reference_symbol(
        &self,
        site: u32,
        target: u32,
        addressing: amiga_disasm::RefKind,
        operand: Option<u32>,
    ) -> Option<&'a str> {
        if self
            .relocated_reference(site, target, addressing, operand)
            .is_some()
        {
            return self
                .reference_target_in_image(site, target, addressing, operand)
                .and_then(|offset| self.target_symbol(Some(offset), None));
        }
        match addressing {
            amiga_disasm::RefKind::Absolute | amiga_disasm::RefKind::AbsoluteShort => {
                self.target_symbol(None, Some(target))
            }
            amiga_disasm::RefKind::PcRelative => self.target_symbol(Some(target), None),
        }
    }

    /// The function name shown for a hunk offset: the config symbol, else the
    /// `sub_` stub, both in the absolute frame when a base is set. An offset
    /// the mapped origin cannot express stays a stub in the offset frame
    /// rather than resolving symbols against the wrong table.
    pub(crate) fn function_name(&self, offset: u32) -> String {
        let address = match self.base {
            Some(base) => base.offset_to_abs(offset),
            None => Some(offset),
        };
        if let Some(name) = self.project_symbol(Some(offset), None) {
            return name.to_owned();
        }
        match address {
            Some(address) => self
                .config
                .and_then(|config| config.symbol_name(address))
                .map_or_else(|| stub_symbol_name(address), str::to_owned),
            None => stub_symbol_name(offset),
        }
    }

    /// The reviewed calling contract of the function entered at `offset`.
    ///
    /// Only a *project* answers this. A config's `[[symbols]]` table names an
    /// address and says nothing about what a routine is handed, so there is no
    /// second source to fall back to — and inventing a convention here is what
    /// the format's explicit ABI locations exist to prevent.
    pub(crate) fn function_signature(&self, offset: u32) -> Option<&'a str> {
        Some(
            self.names?
                .signature(self.hunk?, u64::from(offset))?
                .rendered
                .as_str(),
        )
    }

    /// The reviewed label for a hunk offset, or `None` where nobody named it.
    ///
    /// The one lookup both listings label from. `annotate` used to own it and
    /// `flow` labelled from offsets alone, so the same project named one
    /// listing and not the other and a reader comparing them saw names appear
    /// and disappear with no rule to infer. Unlike [`Self::function_name`] this
    /// invents nothing: a `sub_` stub is a rendering choice a listing makes for
    /// its own discovered entries, not a name somebody reviewed.
    pub(crate) fn label_at(&self, offset: u32) -> Option<String> {
        self.target_symbol(Some(offset), None)
            .map(|name| sanitize(name.to_owned()))
    }
}

/// Replace control characters in config- or fd-supplied text so a hostile
/// name cannot break the one-fact-per-line output shape. Allocates only when
/// something needs replacing.
fn sanitize(text: String) -> String {
    if text.contains(|character: char| character.is_control()) {
        text.replace(|character: char| character.is_control(), "?")
    } else {
        text
    }
}

/// `(libName=a1, version=d0)` for an fd-described vector, empty otherwise.
fn argument_signature(arguments: &[amiga_disasm::CallArgument]) -> String {
    if arguments.is_empty() {
        return String::new();
    }
    let rendered = arguments
        .iter()
        .map(|argument| {
            // The register always shows, with the value appended when one was
            // established: `byteSize=d0=32000` says both what the ABI expects
            // and what this site passes, and an unresolved argument still
            // names its register rather than disappearing. The register keeps
            // the spelling its table used, so an fd-described signature reads
            // back exactly as the fd file wrote it.
            let slot = match &argument.name {
                Some(name) => format!("{name}={}", argument.register),
                None => argument.register.clone(),
            };
            // An argument with no value says which stop cost it — `=?join`
            // sends the reader to the two paths, where a bare `d1` only says
            // to give up. `?` alone marks the case where nothing was asked.
            match (&argument.value, &argument.symbolic, argument.unresolved) {
                (Some(value), None, None) => format!("{slot}={}", value.rendered),
                (None, Some(symbolic), None) => format!("{slot}=~{}", symbolic.rendered),
                (None, None, Some(reason)) => format!("{slot}=?{reason}"),
                _ => slot,
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("({rendered})")
}

/// `Q8`, or `Q?` when the shift amount came from a register.
fn q_format(fractional_bits: Option<u8>) -> String {
    fractional_bits.map_or_else(|| "Q?".to_owned(), |bits| format!("Q{bits}"))
}

/// The bracketed operand note of a reference: how the operand names its
/// target, and whether a relocation proves where it points.
fn reference_operand_text(
    resolver: &Resolver<'_>,
    site: u32,
    target: u32,
    addressing: amiga_disasm::RefKind,
    operand: Option<u32>,
) -> String {
    if resolver
        .relocated_reference(site, target, addressing, operand)
        .is_some()
    {
        return format!("[{} operand, reloc32]", ref_kind_str(addressing));
    }
    format!("[{} operand]", ref_kind_str(addressing))
}

/// A data preview, rendered on one line. The escaping that keeps the bytes
/// safe already happened in `amiga-disasm::data`; this only frames it.
fn preview_text(preview: &amiga_disasm::DataPreview) -> String {
    let more = |truncated: bool| if truncated { " ..." } else { "" };
    match preview {
        amiga_disasm::DataPreview::Text { text, truncated } => {
            format!("\"{text}\"{}", more(*truncated))
        }
        amiga_disasm::DataPreview::Pointers { offsets, truncated } => format!(
            "[{}]{}",
            offsets
                .iter()
                .map(|offset| format!("{offset:#x}"))
                .collect::<Vec<_>>()
                .join(", "),
            more(*truncated)
        ),
        amiga_disasm::DataPreview::Bytes { bytes, truncated } => {
            format!("{}{}", hex::encode(bytes), more(*truncated))
        }
    }
}

/// Why a referenced offset's code/data reading is disputed.
fn conflict_text(conflict: amiga_disasm::TargetConflict) -> &'static str {
    match conflict {
        amiga_disasm::TargetConflict::IntoInstruction => {
            "referenced inside a decoded instruction, not at its start"
        }
        amiga_disasm::TargetConflict::CodeReadsAsText => {
            "decoded as code but the same bytes read as text"
        }
    }
}

/// A bounded list of instruction sites, e.g. `L00000000,L00000008`. A capped
/// list names what it left out, so it never reads as the whole set.
fn site_list(sites: &[u32], total: usize) -> String {
    let listed = sites
        .iter()
        .map(|site| format!("L{site:08X}"))
        .collect::<Vec<_>>()
        .join(",");
    match total.saturating_sub(sites.len()) {
        0 => listed,
        omitted => format!("{listed} (+{omitted} more of {total})"),
    }
}

/// How the sites of a reverse cross-reference reach their target.
fn xref_via_str(via: amiga_disasm::XrefVia) -> &'static str {
    match via {
        amiga_disasm::XrefVia::Call => "called from",
        amiga_disasm::XrefVia::Operand => "addressed from",
        amiga_disasm::XrefVia::Relocation => "relocated from",
    }
}

fn clamp_side(clamp: amiga_disasm::ClampKind) -> &'static str {
    match clamp {
        amiga_disasm::ClampKind::Lower => "lower",
        amiga_disasm::ClampKind::Upper => "upper",
    }
}

/// The shared `<direction> <slot>` core of a memory-access text, e.g.
/// `write A5+0x8` or `read screen_buffer @ hunk0+0x4 (abs 0x10004, file 0x24)`.
/// A base-relative slot names its register because its address space is that
/// register's value, which static analysis does not know.
fn memory_access_text(
    resolver: &Resolver<'_>,
    target: &MemoryAddressing,
    access: amiga_disasm::AccessKind,
) -> String {
    match target {
        MemoryAddressing::BaseRelative {
            register,
            displacement,
        } => format!(
            "{} A{register}{}",
            access_kind_str(access),
            signed_hex(*displacement)
        ),
        MemoryAddressing::Absolute { address } => format!(
            "{} {}",
            access_kind_str(access),
            resolver.named_location(
                resolver.target_symbol(None, Some(*address)),
                resolver.runtime_location_text(*address)
            )
        ),
    }
}

/// How a report was narrowed, as the command line spells it.
///
/// Parsed here rather than in the library because the *spelling* is a frontend
/// concern; what the narrowing means is `amiga_disasm::select`'s.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReportView {
    /// `--function <offset>`.
    pub(crate) function: Option<u32>,
    /// `--range <start>..<end>`.
    pub(crate) range: Option<String>,
    /// `--only <category>`, repeatable.
    pub(crate) only: Vec<String>,
    /// `--min-confidence <name>`.
    pub(crate) minimum_confidence: Option<String>,
    /// `--subsystem <name>`, repeatable: keep only hardware accesses to these
    /// custom-chip subsystems.
    pub(crate) subsystems: Vec<String>,
    /// `--order address|name`.
    pub(crate) order: Option<String>,
}

impl ReportView {
    /// Resolve the flags into the library's own filter.
    fn resolve(&self) -> Result<amiga_disasm::Filter> {
        let selection = match (self.function, self.range.as_deref()) {
            (Some(_), Some(_)) => bail!("--function and --range select different things; pass one"),
            (Some(entry), None) => amiga_disasm::Selection::Function { entry },
            (None, Some(text)) => {
                let (start, end) = text
                    .split_once("..")
                    .context("--range is START..END, e.g. 0x100..0x200")?;
                let start = amiga_core::parse_u32(start).map_err(|error| anyhow::anyhow!(error))?;
                let end = amiga_core::parse_u32(end).map_err(|error| anyhow::anyhow!(error))?;
                if end <= start {
                    bail!("--range END must be greater than START");
                }
                amiga_disasm::Selection::Range { start, end }
            }
            (None, None) => amiga_disasm::Selection::Whole,
        };
        let mut categories = std::collections::BTreeSet::new();
        for name in &self.only {
            let category = amiga_disasm::Category::parse(name).with_context(|| {
                format!(
                    "unknown --only {name:?} (use {})",
                    amiga_disasm::Category::ALL
                        .iter()
                        .map(|category| category.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            categories.insert(category);
        }
        let minimum_confidence = match self.minimum_confidence.as_deref() {
            Some(name) => Some(parse_confidence(name)?),
            None => None,
        };
        Ok(amiga_disasm::Filter {
            selection,
            categories,
            minimum_confidence,
        })
    }

    /// The custom-chip subsystems `--subsystem` named, validated against the
    /// register map so a typo is refused rather than silently matching nothing.
    fn subsystems(&self) -> Result<std::collections::BTreeSet<String>> {
        let known: std::collections::BTreeSet<&'static str> = amiga_hw::known_registers()
            .iter()
            .map(|(offset, _)| amiga_hw::subsystem(*offset))
            .collect();
        let mut selected = std::collections::BTreeSet::new();
        for name in &self.subsystems {
            if !known.contains(name.as_str()) {
                bail!(
                    "unknown --subsystem {name:?} (use {})",
                    known.iter().copied().collect::<Vec<_>>().join(", ")
                );
            }
            selected.insert(name.clone());
        }
        Ok(selected)
    }

    /// How to order the function index.
    fn order(&self) -> Result<FunctionOrder> {
        match self.order.as_deref() {
            None | Some("address") => Ok(FunctionOrder::Address),
            Some("name") => Ok(FunctionOrder::Name),
            Some(other) => bail!("unknown --order {other:?} (use address or name)"),
        }
    }
}

/// How the function index is ordered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FunctionOrder {
    /// By entry offset, which is also the order the analysis found them in.
    Address,
    /// By the name a reader knows them by, which is what a large index is
    /// searched by once the addresses stop meaning anything.
    Name,
}

/// Parse a confidence name into the floor it names.
fn parse_confidence(name: &str) -> Result<Confidence> {
    const LEVELS: [Confidence; 5] = [
        Confidence::Certain,
        Confidence::Inferred,
        Confidence::Probable,
        Confidence::Observed,
        Confidence::User,
    ];
    LEVELS
        .into_iter()
        .find(|level| level.label() == name)
        .with_context(|| {
            format!(
                "unknown confidence {name:?} (use {})",
                LEVELS
                    .iter()
                    .map(|level| level.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

#[expect(
    clippy::too_many_arguments,
    reason = "one report has a target, an ABI, a narrowing, a format, and an optional graph"
)]
pub(crate) fn disasm_report(
    config_override: Option<&Path>,
    target: &DisasmTargetArgs,
    library_name: Option<&str>,
    base_register: u8,
    format: &str,
    view: &ReportView,
    dot: Option<&Path>,
    force: bool,
) -> Result<()> {
    let mut out = Document::new();
    let prepared = prepare_code_analysis(config_override, target)?;
    let library = parse_library(library_name)?;
    let facts = compose_facts(&prepared, library, base_register)?;
    let filter = view.resolve()?;
    // Summaries fold the facts the report *carries*, not the facts it started
    // with: a header stating something the fact list below does not show would
    // break the one rule this report has.
    let mut filtered = amiga_disasm::select::apply(&prepared.analysis, &facts, &filter);
    // A subsystem is a narrowing of the hardware category, so it is counted the
    // same way: what it removed is excluded by category, not quietly missing.
    let subsystems = view.subsystems()?;
    if !subsystems.is_empty() {
        let before = filtered.facts.len();
        filtered.facts.retain(|fact| match &fact.kind {
            FactKind::HardwareAccess { offset, .. } => {
                subsystems.contains(amiga_hw::subsystem(*offset))
            }
            // Only hardware facts claim a subsystem; nothing else is filtered
            // by one, because nothing else has one to be judged by.
            _ => true,
        });
        filtered.exclusions.by_category += before - filtered.facts.len();
    }
    // The summaries know whether the list they fold is everything, because one
    // of their fields — `leaf` — is true precisely because facts are absent.
    let completeness = if filter.is_empty() {
        amiga_disasm::Completeness::Complete
    } else {
        amiga_disasm::Completeness::Partial
    };
    let mut summaries = amiga_disasm::summarize(&prepared.analysis, &filtered.facts, completeness);
    // The index describes the report, not the hunk it came from: a narrowed
    // report listing functions whose facts it dropped would be the very
    // contradiction the narrowing exists to avoid.
    summaries.retain(|summary| {
        filter
            .selection
            .admits_function(&prepared.analysis, summary.entry)
    });
    if view.order()? == FunctionOrder::Name {
        // Ties keep entry order, so the index stays deterministic when two
        // functions share a stub name.
        summaries.sort_by_cached_key(|summary| {
            (
                sanitize(resolver_name(&prepared, summary.entry)),
                summary.entry,
            )
        });
    }
    let stats = ReportStats::compute(&prepared, &filtered.facts);
    let provenance = Provenance::collect(&prepared, library_name, base_register, &filter);

    // Every argument is checked before anything is written: a rejected
    // invocation must leave nothing behind, and a failed write must not leave a
    // report claiming a graph that does not exist.
    if !matches!(format, "text" | "json") {
        bail!("unknown --format {format:?} (use text or json)");
    }
    if let Some(path) = dot {
        write_dot(&prepared, &summaries, path, force)?;
    }
    match format {
        "text" => print_document(&render_text(
            &prepared,
            target,
            &filtered,
            &summaries,
            &stats,
            &provenance,
            dot,
        )?)?,
        "json" => row!(
            out,
            "{}",
            render_json(
                &prepared,
                target,
                &filtered,
                &summaries,
                &stats,
                &provenance,
                dot
            )?
        ),
        other => bail!("unknown --format {other:?} (use text or json)"),
    }
    out.print()
}

/// The name one function is known by, for ordering the index before the
/// renderers build their own resolver.
fn resolver_name(prepared: &Prepared, entry: u32) -> String {
    Resolver::for_prepared(prepared).function_name(entry)
}

/// What produced this report, recorded so it can be reproduced.
///
/// Not decoration: a semantic report is an argument about bytes, and an
/// argument whose inputs are unknown cannot be checked. Everything that changes
/// the output is here — the bytes, the selection, the ABI knowledge, the
/// narrowing, and the tool that did it.
struct Provenance {
    source_sha256: String,
    tool: &'static str,
    version: &'static str,
    /// The config's file name, never its host path: a report is shared, and an
    /// absolute path says more about the machine than about the analysis.
    config_file: Option<String>,
    config_sha256: Option<String>,
    library: Option<String>,
    base_register: u8,
    selection: String,
    categories: Vec<&'static str>,
    minimum_confidence: Option<&'static str>,
}

impl Provenance {
    fn collect(
        prepared: &Prepared,
        library_name: Option<&str>,
        base_register: u8,
        filter: &amiga_disasm::Filter,
    ) -> Self {
        // The config is pinned by content, not by path: two machines with the
        // same config produce the same report, and a changed config is visible
        // even when its path did not move.
        let config_file = prepared
            .config_path
            .as_ref()
            .and_then(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned());
        let config_sha256 = prepared
            .config_path
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .map(|bytes| sha256(&bytes));
        Self {
            source_sha256: sha256(&prepared.bytes),
            tool: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            config_file,
            config_sha256,
            library: library_name.map(str::to_owned),
            base_register,
            selection: filter.selection.describe(),
            categories: filter
                .categories
                .iter()
                .map(|category| category.as_str())
                .collect(),
            minimum_confidence: filter.minimum_confidence.map(Confidence::label),
        }
    }
}

/// Write the call graph as DOT, using the same anchors the report uses.
///
/// One node per summarized function, so a graph produced beside a narrowed
/// report describes the same functions the report does rather than the whole
/// hunk it came from.
fn write_dot(
    prepared: &Prepared,
    summaries: &[amiga_disasm::FunctionSummary],
    path: &Path,
    force: bool,
) -> Result<()> {
    let resolver = Resolver::for_prepared(prepared);
    let anchors = Anchors::new(&resolver, &prepared.analysis);
    let mut dot = String::new();
    writeln!(dot, "digraph callgraph {{")?;
    writeln!(dot, "  node [shape=box];")?;
    for summary in summaries {
        let anchor = anchors.function_anchor(summary.entry);
        writeln!(
            dot,
            "  {:?} [label={:?}];",
            anchor,
            format!(
                "{}\n{} instruction(s){}",
                sanitize(resolver.function_name(summary.entry)),
                summary.instruction_count,
                if summary.leaf == Some(true) {
                    ", leaf"
                } else {
                    ""
                }
            )
        )?;
    }
    let entries: std::collections::BTreeSet<u32> =
        summaries.iter().map(|summary| summary.entry).collect();
    for summary in summaries {
        for callee in &summary.callees {
            // Only edges whose both ends are in the report: an edge to a
            // function the reader cannot look up is a dangling claim.
            if entries.contains(callee) {
                writeln!(
                    dot,
                    "  {:?} -> {:?};",
                    anchors.function_anchor(summary.entry),
                    anchors.function_anchor(*callee)
                )?;
            }
        }
    }
    writeln!(dot, "}}")?;
    prepare_output_file(path, force)?;
    fs::write(path, dot.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Parse a `--library` name into the initial-A6 library.
pub(crate) fn parse_library(name: Option<&str>) -> Result<Option<amiga_disasm::Library>> {
    match name {
        Some(name) => Ok(Some(amiga_disasm::Library::from_name(name).with_context(
            || {
                format!(
                    "{name:?} is neither a known library (exec, dos, graphics, intuition) \
                     nor a plausible `name.library`/`name.device` open-name"
                )
            },
        )?)),
        None => Ok(None),
    }
}

// --- anchored entities -------------------------------------------------------

/// One anchored entity of a report: something a cross-reference can point at.
struct Entity {
    anchor: amiga_core::Anchor,
    location: amiga_core::Location,
    /// The name a reader knows it by, when anything names it.
    name: Option<String>,
}

/// Assigns the stable anchors of one report.
///
/// A fact belongs to the entity that lives at its subject: the function at an
/// entry, the configured symbol, the decoded instruction at a code offset, or
/// the data at an offset control flow never reached (a relocated pointer, a
/// string). Anchors are derived from the offset and the kind alone, so they
/// stay identical across runs of the same input.
struct Anchors<'a> {
    resolver: &'a Resolver<'a>,
    analysis: &'a amiga_disasm::ControlFlowAnalysis,
}

impl<'a> Anchors<'a> {
    fn new(resolver: &'a Resolver<'a>, analysis: &'a amiga_disasm::ControlFlowAnalysis) -> Self {
        Self { resolver, analysis }
    }

    /// The entity kind that lives at a hunk offset: a decoded instruction, or
    /// else data this analysis never reached as code.
    fn site_kind(&self, offset: u32) -> amiga_core::EntityKind {
        if self.analysis.instructions.contains_key(&offset) {
            amiga_core::EntityKind::Instruction
        } else {
            amiga_core::EntityKind::DataRegion
        }
    }

    /// The anchor of the entity a reference points at: the function at an
    /// entry, the instruction at a decoded offset, the data elsewhere. Forward
    /// and reverse cross-references both resolve through this, so both name
    /// the same entity.
    fn target_anchor(&self, offset: u32) -> Option<amiga_core::Anchor> {
        let kind = if self.analysis.functions.contains(&offset) {
            amiga_core::EntityKind::Function
        } else {
            self.site_kind(offset)
        };
        self.resolver.anchor(kind, offset)
    }

    /// The anchor of the entity a fact is about.
    fn fact_anchor(&self, fact: &Fact) -> Option<amiga_core::Anchor> {
        let (kind, offset) = match &fact.kind {
            FactKind::Function { entry }
            | FactKind::FunctionSignature {
                signature: amiga_disasm::FunctionSignature { entry, .. },
            } => (amiga_core::EntityKind::Function, *entry),
            FactKind::Symbol { .. } => (amiga_core::EntityKind::Symbol, fact.subject),
            // A reverse cross-reference and a code/data dispute are both about
            // their target, so they anchor to the entity a forward reference
            // points at.
            FactKind::ReferencedBy { .. } | FactKind::TargetConflict { .. } => {
                return self.target_anchor(fact.subject);
            }
            FactKind::DataRegion { .. } => (amiga_core::EntityKind::DataRegion, fact.subject),
            _ => (self.site_kind(fact.subject), fact.subject),
        };
        self.resolver.anchor(kind, offset)
    }

    /// The anchor a function entry is known by.
    ///
    /// One rule, used by the index, the headers, and the DOT graph, so a reader
    /// following an anchor from any of them lands on the same entity.
    fn function_anchor(&self, entry: u32) -> String {
        self.resolver
            .anchor(amiga_core::EntityKind::Function, entry)
            .map_or_else(|| format!("F{entry:08X}"), |anchor| anchor.to_string())
    }

    /// Every anchored entity a reference in this report can point at, ordered
    /// by offset and kind. Function entries and configured symbols are named
    /// entities of their own; instructions are anchored by the documented rule
    /// rather than enumerated, since every decoded instruction has one.
    fn entities(&self, facts: &[Fact]) -> Vec<Entity> {
        let mut entities = std::collections::BTreeMap::new();
        for fact in facts {
            let (kind, offset, name) = match &fact.kind {
                FactKind::Function { entry } => (
                    amiga_core::EntityKind::Function,
                    *entry,
                    Some(self.resolver.function_name(*entry)),
                ),
                FactKind::Symbol { name, .. } => (
                    amiga_core::EntityKind::Symbol,
                    fact.subject,
                    Some(name.clone()),
                ),
                // A classified region is named by what it looks like, since
                // nothing else names it until a config symbol does.
                FactKind::DataRegion { preview, .. } => (
                    amiga_core::EntityKind::DataRegion,
                    fact.subject,
                    Some(preview.class().to_owned()),
                ),
                _ => continue,
            };
            let (Some(anchor), Some(location)) = (
                self.resolver.anchor(kind, offset),
                self.resolver.locate(offset),
            ) else {
                continue;
            };
            entities.entry((offset, kind)).or_insert_with(|| Entity {
                anchor,
                location,
                name: name.map(sanitize),
            });
        }
        entities.into_values().collect()
    }
}

/// The entity table: one line per anchored, named entity, before the facts
/// that talk about them.
fn render_entities(text: &mut String, entities: &[Entity]) -> Result<()> {
    if entities.is_empty() {
        return Ok(());
    }
    writeln!(text, "; Entities: anchor  kind  location  name")?;
    writeln!(text)?;
    for entity in entities {
        writeln!(
            text,
            "@{:<18} {:<9} {}{}",
            entity.anchor.to_string(),
            entity.anchor.kind().tag(),
            entity.location,
            entity
                .name
                .as_ref()
                .map(|name| format!("  {name}"))
                .unwrap_or_default()
        )?;
    }
    writeln!(text)?;
    Ok(())
}

// --- text renderer ---------------------------------------------------------

/// ` at file 0x20..0x7c` for a hunk with a known file anchor, empty when the
/// anchor is unknown or the end of the range would overflow the file frame.
fn file_range_text(map: &amiga_core::AddressMap) -> String {
    let Some(start) = map.file_start() else {
        return String::new();
    };
    match start.get().checked_add(u64::from(map.size())) {
        Some(end) => format!(" at file {:#x}..{end:#x}", start.get()),
        None => format!(" at file {:#x}", start.get()),
    }
}

fn render_text(
    prepared: &Prepared,
    _target: &DisasmTargetArgs,
    filtered: &amiga_disasm::Filtered,
    summaries: &[amiga_disasm::FunctionSummary],
    stats: &ReportStats,
    provenance: &Provenance,
    dot: Option<&Path>,
) -> Result<String> {
    let facts = &filtered.facts;
    let mut text = String::new();
    writeln!(text, "; Semantic fact report by amiga-re")?;
    writeln!(
        text,
        "; Schema: {REPORT_SCHEMA} v{}",
        amiga_disasm::SCHEMA_VERSION
    )?;
    writeln!(text, "; Source SHA-256: {}", provenance.source_sha256)?;
    let map = prepared.address_map();
    let entries = prepared
        .entries
        .iter()
        .map(|offset| format!("{offset:#x}"))
        .collect::<Vec<_>>()
        .join(", ");
    match prepared.region() {
        amiga_operations::CodeRegion::Hunk => writeln!(
            text,
            "; Hunk: {} (CODE, {:#x} bytes){}; entry offsets: {entries}",
            prepared.hunk(),
            prepared.code().len(),
            file_range_text(&map),
        )?,
        amiga_operations::CodeRegion::Raw => writeln!(
            text,
            "; Raw image: {:#x} bytes; entry offsets: {entries}",
            prepared.code().len(),
        )?,
        amiga_operations::CodeRegion::BootBlock => {
            unreachable!("disasm report does not prepare boot blocks")
        }
    }
    match (prepared.region(), map.origin()) {
        (amiga_operations::CodeRegion::Hunk, Some(origin)) => writeln!(
            text,
            "; Base: origin {:#x} (hunk{}+0x0 is mapped at abs {:#x})",
            origin.get(),
            map.hunk().get(),
            origin.get()
        )?,
        (amiga_operations::CodeRegion::Raw, Some(origin)) => writeln!(
            text,
            "; Base: origin {:#x} (raw offset 0 is mapped at abs {:#x})",
            origin.get(),
            origin.get()
        )?,
        (_, None) => writeln!(
            text,
            "; Base: none (no mapped origin, so no runtime address space)"
        )?,
        (amiga_operations::CodeRegion::BootBlock, _) => {
            unreachable!("disasm report does not prepare boot blocks")
        }
    }
    match prepared.region() {
        amiga_operations::CodeRegion::Hunk => {
            writeln!(
                text,
                "; Address spaces: hunk{}+0x.. hunk-relative, abs 0x.. runtime, file 0x.. whole-file",
                map.hunk().get()
            )?;
            writeln!(
                text,
                "; L######## subjects and evidence sites are offsets into hunk {}",
                map.hunk().get()
            )?;
        }
        amiga_operations::CodeRegion::Raw => {
            writeln!(
                text,
                "; Address spaces: raw+0x.. image-relative, abs 0x.. runtime, file 0x.. source"
            )?;
            writeln!(
                text,
                "; L######## subjects and evidence sites are raw-image offsets"
            )?;
        }
        amiga_operations::CodeRegion::BootBlock => {
            unreachable!("disasm report does not prepare boot blocks")
        }
    }
    writeln!(
        text,
        "; Anchors: h<hunk>-<kind>-<offset as 8 hex digits>; every subject has one \
         (insn for a decoded instruction, data otherwise)"
    )?;
    // Coverage is the whole selected region's; everything below it is counted from the facts
    // this report kept. Two different scopes on adjacent lines, each said out
    // loud, because a narrowed report otherwise reads as a shrunken hunk.
    let coverage_scope = match prepared.region() {
        amiga_operations::CodeRegion::Hunk => "hunk",
        amiga_operations::CodeRegion::Raw => "raw image",
        amiga_operations::CodeRegion::BootBlock => {
            unreachable!("disasm report does not prepare boot blocks")
        }
    };
    writeln!(
        text,
        "; Coverage (whole {coverage_scope}): {}/{} bytes, {} instructions, {} functions, {} calls",
        stats.decoded_bytes, stats.total_bytes, stats.instructions, stats.functions, stats.calls
    )?;
    writeln!(
        text,
        "; References (this report): {} resolved ({} by relocation), {} unresolved",
        stats.references_resolved, stats.references_relocated, stats.references_unresolved,
    )?;
    let resolution = &stats.resolution;
    writeln!(
        text,
        "; Library calls (this report): {} sites — {} named, {} unnamed vector, \
         {} unknown base; {} described, {} undescribed",
        resolution.sites,
        resolution.named,
        resolution.unnamed_vector,
        resolution.unknown_library,
        resolution.described,
        resolution.undescribed
    )?;
    // The measurement the Stage 4 stop decision asks for. The histogram is the
    // point rather than the rate: it says whether more ABI entries would buy
    // anything, or whether the walk would refuse the values anyway.
    writeln!(
        text,
        "; Call arguments (this report): {}/{} resolved ({:.1}%); {} symbolic; {} refused by the walk",
        resolution.resolved,
        resolution.arguments,
        resolution.resolved_percent(),
        resolution.symbolic,
        resolution.refused_by_walk()
    )?;
    // Gated on the reasons rather than on the unresolved count: an argument
    // carrying neither a value nor a reason would otherwise print an empty
    // list, which reads as "no reasons" instead of "nothing to say".
    if !resolution.reasons.is_empty() {
        // Declaration order, not count order, so the line diffs cleanly between
        // runs of the same program; the leader is named separately instead.
        let histogram = amiga_disasm::Unresolved::all()
            .iter()
            .filter_map(|reason| {
                resolution
                    .reasons
                    .get(reason)
                    .map(|count| format!("{reason} {count}"))
            })
            .collect::<Vec<_>>()
            .join(", ");
        // With one reason the histogram already says which it is.
        let leader = match resolution.dominant_reason() {
            Some((reason, _)) if resolution.reasons.len() > 1 => {
                format!(" (most often {reason})")
            }
            _ => String::new(),
        };
        writeln!(text, "; Unresolved because: {histogram}{leader}")?;
    }
    writeln!(
        text,
        "; Hardware accesses (this report): {} named, {} unknown; \
         external flow: {}; unresolved flow: {}",
        stats.hardware_accesses_named,
        stats.hardware_accesses_unknown,
        stats.external_flow,
        stats.unresolved_flow
    )?;
    // What produced this report, so it can be reproduced or disbelieved.
    writeln!(text, "; Tool: {} {}", provenance.tool, provenance.version)?;
    match (&provenance.config_file, &provenance.config_sha256) {
        (Some(name), Some(digest)) => {
            writeln!(text, "; Config: {name} (SHA-256 {digest})")?;
        }
        _ => writeln!(text, "; Config: none")?,
    }
    writeln!(
        text,
        "; Options: library {}, small-data base A{}",
        provenance.library.as_deref().unwrap_or("inferred"),
        provenance.base_register
    )?;
    // A narrowed report says so, in the header, before anything it kept.
    writeln!(
        text,
        "; Selection: {}{}{}",
        provenance.selection,
        if provenance.categories.is_empty() {
            String::new()
        } else {
            format!("; categories {}", provenance.categories.join(","))
        },
        provenance
            .minimum_confidence
            .map(|level| format!("; confidence at least {level}"))
            .unwrap_or_default()
    )?;
    if filtered.exclusions.any() {
        writeln!(
            text,
            "; Excluded: {} fact(s) — {} outside the selection, {} by category, \
             {} below the confidence floor",
            filtered.exclusions.total(),
            filtered.exclusions.by_selection,
            filtered.exclusions.by_category,
            filtered.exclusions.by_confidence
        )?;
        writeln!(
            text,
            "; This report is NOT complete: it describes only what the selection kept."
        )?;
    }
    if let Some(path) = dot {
        writeln!(text, "; Call graph: {} (DOT)", path.display())?;
    }
    writeln!(text)?;
    let resolver = Resolver::for_prepared(prepared);
    let anchors = Anchors::new(&resolver, &prepared.analysis);
    render_function_index(&mut text, &resolver, &anchors, summaries)?;
    render_entities(&mut text, &anchors.entities(facts))?;
    writeln!(
        text,
        "; Columns: subject  anchor  kind  confidence  producer  description  <evidence>"
    )?;
    writeln!(text)?;
    for fact in facts {
        writeln!(
            text,
            "L{:08X}  @{:<18} {:<17} {:<9} {:<18} {}  <{}>",
            fact.subject,
            anchors
                .fact_anchor(fact)
                .map(|anchor| anchor.to_string())
                .unwrap_or_default(),
            fact.kind.label(),
            fact.confidence.label(),
            fact.producer.label(),
            describe(&resolver, fact),
            evidence_text(&fact.evidence)
        )?;
    }
    Ok(text)
}

/// The function index and one header per function.
///
/// The index is what makes a large report navigable: every function with its
/// anchor, its span, and the one line that says what it does. The headers below
/// it repeat nothing the fact list does not carry — they are a fold of it.
fn render_function_index(
    text: &mut String,
    resolver: &Resolver<'_>,
    anchors: &Anchors<'_>,
    summaries: &[amiga_disasm::FunctionSummary],
) -> Result<()> {
    if summaries.is_empty() {
        return Ok(());
    }
    writeln!(text, "; Functions: {}", summaries.len())?;
    writeln!(
        text,
        "; Columns: entry  anchor  span  instructions  callers/callees  summary"
    )?;
    for summary in summaries {
        writeln!(
            text,
            "F{:08X}  @{:<18} {:#x}..{:#x}  {:>5}  {}/{}  {}",
            summary.entry,
            anchors.function_anchor(summary.entry),
            summary.entry,
            summary.end,
            summary.instruction_count,
            summary.callers.len(),
            summary.callees.len(),
            // Config-supplied, so it goes through the same sanitizer every
            // other free text does: an unescaped newline here would inject a
            // row into the index and make the count above it a lie.
            sanitize(resolver.function_name(summary.entry)),
        )?;
        for line in summary_lines(resolver, summary) {
            writeln!(text, "          {line}")?;
        }
    }
    writeln!(text)?;
    Ok(())
}

/// The lines of one function header, omitting everything it has nothing to say
/// about. An empty line would read as "nothing here", which is a claim.
fn summary_lines(resolver: &Resolver<'_>, summary: &amiga_disasm::FunctionSummary) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(signature) = &summary.signature {
        lines.push(format!(
            "prototype {}",
            signature.prototype(&sanitize(resolver.function_name(summary.entry)))
        ));
        if !signature.complete {
            lines.push("signature register walk incomplete".to_owned());
        }
        lines.push(match signature.frame {
            amiga_disasm::FrameStyle::Link {
                register,
                local_bytes,
            } => format!("LINK A{register} frame; stack locals: {local_bytes} bytes"),
            amiga_disasm::FrameStyle::StackPointer { local_bytes } => {
                format!("A7 frame; stack locals: {local_bytes} bytes")
            }
            amiga_disasm::FrameStyle::PathDependent {
                maximum_local_bytes,
            } => format!(
                "path-dependent A7 frame; maximum stack locals: {maximum_local_bytes} bytes"
            ),
            amiga_disasm::FrameStyle::Unknown => "unknown A7 frame".to_owned(),
            amiga_disasm::FrameStyle::Frameless => "frameless".to_owned(),
        });
        if !signature.preserved.is_empty() {
            lines.push(format!(
                "preserves {}",
                signature_registers(&signature.preserved)
            ));
        }
        if !signature.clobbered.is_empty() {
            lines.push(format!(
                "clobbers {}",
                signature_registers(&signature.clobbered)
            ));
        }
        let arguments = signature
            .stack_slots
            .iter()
            .filter(|slot| slot.kind == amiga_disasm::StackSlotKind::Argument)
            .map(|slot| format!("{:+#x}", slot.offset))
            .collect::<Vec<_>>();
        if !arguments.is_empty() {
            lines.push(format!("stack arguments at {}", arguments.join(", ")));
        }
        match signature.returns {
            amiga_disasm::FunctionReturn::Rte => lines.push("interrupt return (RTE)".to_owned()),
            amiga_disasm::FunctionReturn::Rtr => lines.push("exception return (RTR)".to_owned()),
            amiga_disasm::FunctionReturn::Mixed => lines.push("mixed return forms".to_owned()),
            amiga_disasm::FunctionReturn::None | amiga_disasm::FunctionReturn::Rts => {}
        }
        if signature.tail_call {
            lines.push("tail call".to_owned());
        }
    }
    if summary.ownership_truncated {
        lines.push(
            "ownership was capped for some instructions; callers may be incomplete".to_owned(),
        );
    }
    if !summary.callers.is_empty() {
        lines.push(format!(
            "called by {}",
            summary
                .callers
                .iter()
                .map(|entry| sanitize(resolver.function_name(*entry)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !summary.callees.is_empty() {
        lines.push(format!(
            "calls {}",
            summary
                .callees
                .iter()
                .map(|entry| sanitize(resolver.function_name(*entry)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if summary.external_calls > 0 {
        lines.push(format!(
            "leaves this hunk at {} site(s)",
            summary.external_calls
        ));
    }
    if !summary.library_calls.is_empty() {
        lines.push(format!(
            "library {}",
            summary
                .library_calls
                .iter()
                .map(library_call_text)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !summary.globals_read.is_empty() {
        lines.push(format!("reads {}", summary.globals_read.join(", ")));
    }
    if !summary.globals_written.is_empty() {
        lines.push(format!("writes {}", summary.globals_written.join(", ")));
    }
    if !summary.hardware_registers.is_empty() {
        lines.push(format!(
            "hardware {}",
            subsystem_text(&summary.hardware_registers)
        ));
    }
    if !summary.unresolved_exits.is_empty() {
        lines.push(format!(
            "unresolved exits at {}",
            summary
                .unresolved_exits
                .iter()
                .map(|site| format!("{site:#x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    match summary.leaf {
        Some(true) => lines.push("leaf (calls nothing)".to_owned()),
        Some(false) => {}
        // Unknown, because the fact list was narrowed or ownership was capped.
        // Saying nothing is the answer; "not a leaf" would be as wrong as
        // "leaf" and the header already says the report is partial.
        None => {}
    }
    lines
}

fn signature_registers(registers: &[amiga_disasm::FunctionRegister]) -> String {
    registers
        .iter()
        .map(|register| register.label())
        .collect::<Vec<_>>()
        .join("/")
}

/// One library vector as a header states it: the name when it was inferred,
/// the vector offset when it was not, and the offset either way when a caller
/// needs to look it up.
fn library_call_text(call: &amiga_disasm::LibraryCallSummary) -> String {
    let name = match (&call.library, &call.function) {
        (Some(library), Some(function)) => format!("{library}/{function}"),
        (Some(library), None) => format!("{library}/LVO{}", call.lvo),
        _ => format!("LVO{}", call.lvo),
    };
    if call.sites > 1 {
        format!("{name} x{}", call.sites)
    } else {
        name
    }
}

/// Group register offsets into the subsystems a reader thinks in, keeping the
/// count so a busy function does not read like a quiet one.
fn subsystem_text(registers: &[u16]) -> String {
    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for register in registers {
        *counts.entry(amiga_hw::subsystem(*register)).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(subsystem, count)| {
            if count > 1 {
                format!("{subsystem} x{count}")
            } else {
                subsystem.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn evidence_text(evidence: &[Evidence]) -> String {
    evidence
        .iter()
        .map(|item| match item {
            Evidence::Instruction { site } => format!("L{site:08X}"),
            Evidence::Relocation { offset } => format!("reloc@{offset:#x}"),
            Evidence::Config { addr } => format!("config@{addr:#x}"),
            Evidence::Abi { library, lvo } => format!("abi:{library}@{lvo}"),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// A human-readable one-line description of a fact's payload. Config-supplied
/// names are the only free text; control characters are replaced so a hostile
/// name cannot break the one-fact-per-line shape.
pub(crate) fn describe(resolver: &Resolver<'_>, fact: &Fact) -> String {
    let description = match &fact.kind {
        FactKind::Function { entry } => format!(
            "entry {} @ {}",
            resolver.function_name(*entry),
            resolver.offset_location_text(*entry)
        ),
        FactKind::FunctionSignature { signature } => {
            let mut text = signature.prototype(&resolver.function_name(signature.entry));
            if !signature.complete {
                text.push_str(" [incomplete register walk]");
            }
            text
        }
        FactKind::Call {
            callee,
            owners,
            owner_total,
        } => format!(
            "call -> {} @ {} [in {}]",
            resolver.function_name(*callee),
            resolver.offset_location_text(*callee),
            site_list(owners, *owner_total)
        ),
        // The destination lives in a hunk this report does not map, so it is
        // shown in the only frame that means anything: the target hunk's own.
        FactKind::ExternalFlow {
            transfer,
            target_hunk,
            target_offset,
            ..
        } => format!(
            "external {} -> {}",
            transfer.label(),
            resolver.relocation_target_text(*target_hunk, *target_offset)
        ),
        FactKind::LibraryCall {
            register,
            lvo,
            library,
            function,
            arguments,
            public,
        } => match (library, function) {
            (Some(library), Some(function)) => {
                format!(
                    "lvo {lvo} via A{register} = {library}/{function}{}{}",
                    amiga_disasm::private_suffix(*public),
                    argument_signature(arguments)
                )
            }
            (Some(library), None) => format!("lvo {lvo} via A{register} = {library}/?"),
            _ => format!("lvo {lvo} via A{register} = unknown library"),
        },
        FactKind::LibraryConflict {
            register,
            lvo,
            candidates,
        } => {
            let bases = candidates
                .iter()
                .map(|candidate| {
                    if candidate.sites.is_empty() {
                        candidate.library.clone()
                    } else {
                        format!(
                            "{} (via {})",
                            candidate.library,
                            candidate
                                .sites
                                .iter()
                                .map(|site| format!("L{site:08X}"))
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join(" | ");
            format!("lvo {lvo} via A{register}: conflicting bases {bases}")
        }
        FactKind::HardwareAccess {
            offset,
            form,
            access,
        } => {
            // `custom+$096` is the register's own space: an offset from the
            // custom-chip base, not an address in the analyzed image.
            let form = match form {
                amiga_disasm::AccessForm::Absolute => "abs",
                amiga_disasm::AccessForm::BaseRelative => "base-reg",
            };
            format!(
                "{} {} (custom+${:03x}) [{form} operand]",
                access_kind_str(*access),
                hardware_register_label(*offset),
                offset
            )
        }
        FactKind::MemoryAccess {
            target,
            access,
            size,
            value,
            library_base,
        } => {
            let mut description = memory_access_text(resolver, target, *access);
            if let Some(size) = size {
                let _ = write!(description, " size={size}");
            }
            if let Some(value) = value {
                let _ = write!(description, " value={value:#x}");
            }
            if *library_base {
                description.push_str(" library-base");
            }
            description
        }
        FactKind::ReferencedBy { via, sites, total } => {
            format!("{} {}", xref_via_str(*via), site_list(sites, *total))
        }
        // The operand kind goes in brackets so it never reads as another
        // address space next to the parenthesized frames.
        FactKind::Reference {
            target,
            addressing,
            operand,
        } => format!(
            "-> {} {}",
            resolver.named_location(
                resolver.reference_symbol(fact.subject, *target, *addressing, *operand),
                resolver.reference_location_text(fact.subject, *target, *addressing, *operand)
            ),
            reference_operand_text(resolver, fact.subject, *target, *addressing, *operand)
        ),
        FactKind::FixedPoint {
            idiom,
            register,
            fractional_bits,
        } => format!(
            "{} D{register} {}",
            idiom.as_str(),
            q_format(*fractional_bits)
        ),
        FactKind::Clamp {
            register,
            size,
            bound,
            clamp,
        } => format!(
            "{} clamp D{register} bound {bound:#x} size={size}",
            clamp_side(*clamp)
        ),
        FactKind::QScale {
            register,
            fractional_bits,
        } => format!("D{register} = Q{fractional_bits}"),
        FactKind::UnresolvedFlow => "unresolved control flow".to_owned(),
        FactKind::Relocation {
            target_hunk,
            target_offset,
            instruction,
        } => {
            // The operand this relocation patches, when the patched bytes sit
            // inside decoded code rather than in data.
            let operand = instruction
                .map(|site| format!(" (operand of L{site:08X})"))
                .unwrap_or_default();
            match target_offset {
                Some(offset) => format!(
                    "reloc32{operand} -> {}",
                    resolver.relocation_target_text(*target_hunk, *offset)
                ),
                None => {
                    format!("reloc32{operand} -> hunk{target_hunk} (stored pointer unreadable)")
                }
            }
        }
        FactKind::DataRegion { end, preview } => format!(
            "data {} {} {} bytes {}",
            preview.class(),
            resolver.offset_location_text(fact.subject),
            end.saturating_sub(fact.subject),
            preview_text(preview)
        ),
        FactKind::TargetConflict {
            conflict,
            instruction,
        } => {
            let inside = instruction
                .filter(|site| *site != fact.subject)
                .map(|site| format!(" (inside L{site:08X})"))
                .unwrap_or_default();
            format!("disputed target: {}{inside}", conflict_text(*conflict))
        }
        // The configured absolute address stays visible as this fact's
        // evidence; the description shows where it landed.
        FactKind::Symbol { name, .. } => format!(
            "symbol {name} @ {}",
            resolver.offset_location_text(fact.subject)
        ),
    };
    sanitize(description)
}

// --- JSON renderer ---------------------------------------------------------

fn render_json(
    prepared: &Prepared,
    _target: &DisasmTargetArgs,
    filtered: &amiga_disasm::Filtered,
    summaries: &[amiga_disasm::FunctionSummary],
    stats: &ReportStats,
    provenance: &Provenance,
    dot: Option<&Path>,
) -> Result<String> {
    let facts = &filtered.facts;
    let resolver = Resolver::for_prepared(prepared);
    let anchors = Anchors::new(&resolver, &prepared.analysis);
    let facts_json = facts
        .iter()
        .map(|fact| enrich_fact(&resolver, &anchors, fact))
        .collect::<Result<Vec<_>>>()?;
    let entities_json = anchors
        .entities(facts)
        .iter()
        .map(|entity| {
            serde_json::json!({
                "anchor": entity.anchor,
                "kind": entity.anchor.kind(),
                "name": entity.name,
                "location": entity.location,
            })
        })
        .collect::<Vec<_>>();
    let base = prepared.base.map(|base| {
        serde_json::json!({
            "origin": base.origin,
            "entry": base.entry,
        })
    });
    let map = prepared.address_map();
    let mut report = serde_json::json!({
        "schema": REPORT_SCHEMA,
        "version": amiga_disasm::SCHEMA_VERSION,
        "source_sha256": provenance.source_sha256,
        "hunk": prepared.hunk(),
        "entries": prepared.entries,
        "base": base,
        // The address spaces every offset in this report can be resolved
        // into. `runtime_origin` is null when the image has no mapped origin,
        // in which case no fact carries a runtime address.
        "address_spaces": {
            "hunk": map.hunk(),
            "size": map.size(),
            "file_start": map.file_start(),
            "runtime_origin": map.origin(),
        },
        // The anchored entities a cross-reference can point at. Every decoded
        // instruction also has an anchor, derived from its offset by the same
        // rule, so they are not enumerated here.
        "anchor_format": "h<hunk>-<kind>-<offset as 8 hex digits>",
        "entities": entities_json,
        // Split by scope rather than merged: the coverage counters describe the
        // hunk the analysis ran over, and the rest count the facts this report
        // kept. Merged, a narrowed report would read as a smaller program.
        "stats": {
            "hunk": {
                "total_bytes": stats.total_bytes,
                "decoded_bytes": stats.decoded_bytes,
                "instructions": stats.instructions,
                "functions": stats.functions,
                "calls": stats.calls,
            },
            "report": {
                "external_flow": stats.external_flow,
                "unresolved_flow": stats.unresolved_flow,
                "references_resolved": stats.references_resolved,
                "references_unresolved": stats.references_unresolved,
                "references_relocated": stats.references_relocated,
                "hardware_accesses_named": stats.hardware_accesses_named,
                "hardware_accesses_unknown": stats.hardware_accesses_unknown,
                // Library-call naming and argument resolution. `reasons` lists
                // only what occurred, so an absent key is a reason that never
                // fired rather than one this build cannot report.
                "resolution": stats.resolution,
            },
        },
        // What produced this report. A semantic report is an argument about
        // bytes, and an argument whose inputs are unknown cannot be checked.
        "provenance": {
            "tool": provenance.tool,
            "version": provenance.version,
            "config_file": provenance.config_file,
            "config_sha256": provenance.config_sha256,
            "library": provenance.library,
            "base_register": provenance.base_register,
            "call_graph_dot": dot.map(|path| path.display().to_string()),
        },
        // How it was narrowed, and what that hid. Present even when nothing was
        // narrowed, so a consumer never has to infer completeness from absence.
        "selection": {
            "description": provenance.selection,
            "categories": provenance.categories,
            "minimum_confidence": provenance.minimum_confidence,
            "complete": !filtered.exclusions.any(),
            "excluded": serde_json::to_value(filtered.exclusions)?,
        },
        "functions": summaries
            .iter()
            .map(|summary| function_json(&resolver, &anchors, summary))
            .collect::<Result<Vec<_>>>()?,
        "facts": facts_json,
    });
    if prepared.region() == amiga_operations::CodeRegion::Raw
        && let Some(object) = report.as_object_mut()
    {
        // The established HUNK report stays byte-for-byte stable. Raw reports
        // add the discriminator that makes their null hunk unambiguous.
        object.insert(
            "region".to_owned(),
            serde_json::Value::String("raw".to_owned()),
        );
        object.insert("hunk".to_owned(), serde_json::Value::Null);
    }
    Ok(serde_json::to_string_pretty(&report)?)
}

/// One function summary as JSON, with the names and subsystems the text header
/// shows so neither renderer states something the other cannot.
fn function_json(
    resolver: &Resolver<'_>,
    anchors: &Anchors<'_>,
    summary: &amiga_disasm::FunctionSummary,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(summary)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "anchor".to_owned(),
            serde_json::to_value(anchors.function_anchor(summary.entry))?,
        );
        object.insert(
            "name".to_owned(),
            serde_json::Value::String(sanitize(resolver.function_name(summary.entry))),
        );
        object.insert(
            "hardware_subsystems".to_owned(),
            serde_json::to_value(subsystems_of(&summary.hardware_registers))?,
        );
    }
    Ok(value)
}

/// The distinct subsystems a set of register offsets belongs to.
fn subsystems_of(registers: &[u16]) -> Vec<&'static str> {
    let mut subsystems: Vec<&'static str> = registers
        .iter()
        .map(|register| amiga_hw::subsystem(*register))
        .collect();
    subsystems.sort_unstable();
    subsystems.dedup();
    subsystems
}

/// Serialize a fact and attach the derived names both renderers resolve —
/// custom-chip register names and config symbols — so the JSON exposes every
/// fact the text renderer shows.
fn enrich_fact(
    resolver: &Resolver<'_>,
    anchors: &Anchors<'_>,
    fact: &Fact,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(fact)?;
    let Some(object) = value.as_object_mut() else {
        return Ok(value);
    };
    // The entity this fact is about, and where its subject byte lives in every
    // address space that resolves.
    if let Some(anchor) = anchors.fact_anchor(fact) {
        object.insert("anchor".to_owned(), serde_json::to_value(anchor)?);
    }
    if let Some(location) = resolver.locate(fact.subject) {
        object.insert("location".to_owned(), serde_json::to_value(location)?);
    }
    match &fact.kind {
        FactKind::HardwareAccess { offset, .. } => {
            if let Some(name) = amiga_hw::register_name(*offset) {
                object.insert("register_name".to_owned(), serde_json::Value::String(name));
            }
            object.insert(
                "subsystem".to_owned(),
                serde_json::Value::String(amiga_hw::subsystem(*offset).to_owned()),
            );
        }
        FactKind::Function { entry } => {
            object.insert(
                "name".to_owned(),
                serde_json::Value::String(resolver.function_name(*entry)),
            );
        }
        FactKind::FunctionSignature { signature } => {
            object.insert(
                "name".to_owned(),
                serde_json::Value::String(resolver.function_name(signature.entry)),
            );
            object.insert(
                "prototype".to_owned(),
                serde_json::Value::String(
                    signature.prototype(&resolver.function_name(signature.entry)),
                ),
            );
        }
        FactKind::Call { callee, .. } => {
            object.insert(
                "name".to_owned(),
                serde_json::Value::String(resolver.function_name(*callee)),
            );
            insert_location(object, "target_location", resolver.locate(*callee))?;
            insert_anchor(object, "target_anchor", anchors.target_anchor(*callee))?;
        }
        FactKind::Reference {
            target,
            addressing,
            operand,
        } => {
            // A relocated operand points where its relocation says, so the
            // stored addend must not resolve the target: for a cross-hunk
            // relocation it is a small number with no meaning in this hunk.
            let relocated =
                resolver.relocated_reference(fact.subject, *target, *addressing, *operand);
            if let Some(relocation) = relocated {
                object.insert("relocated".to_owned(), serde_json::Value::Bool(true));
                object.insert(
                    "relocation_target".to_owned(),
                    serde_json::json!({
                        "hunk": relocation.hunk,
                        "offset": relocation.offset,
                    }),
                );
            }
            let offset =
                resolver.reference_target_in_image(fact.subject, *target, *addressing, *operand);
            // Name the target that survived relocation, not the addend's.
            let symbol = resolver.reference_symbol(fact.subject, *target, *addressing, *operand);
            if let Some(name) = symbol {
                object.insert(
                    "symbol".to_owned(),
                    serde_json::Value::String(name.to_owned()),
                );
            }
            insert_location(
                object,
                "target_location",
                offset.and_then(|offset| resolver.locate(offset)),
            )?;
            insert_anchor(
                object,
                "target_anchor",
                offset.and_then(|offset| anchors.target_anchor(offset)),
            )?;
        }
        FactKind::MemoryAccess {
            target: MemoryAddressing::Absolute { address },
            ..
        } => {
            if let Some(name) = resolver.target_symbol(None, Some(*address)) {
                object.insert(
                    "symbol".to_owned(),
                    serde_json::Value::String(name.to_owned()),
                );
            }
            insert_location(object, "target_location", resolver.locate_runtime(*address))?;
        }
        // Only the analyzed hunk has resolved address spaces here, so a
        // relocation into another hunk keeps its hunk-frame payload alone.
        FactKind::Relocation {
            target_hunk,
            target_offset: Some(offset),
            ..
        } if resolver.analyzed_hunk() == Some(*target_hunk) => {
            insert_location(object, "target_location", resolver.locate(*offset))?;
            insert_anchor(object, "target_anchor", anchors.target_anchor(*offset))?;
        }
        _ => {}
    }
    Ok(value)
}

/// Attach an anchor under `key`, or nothing when the target has no entity in
/// this report to point at.
fn insert_anchor(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    anchor: Option<amiga_core::Anchor>,
) -> Result<()> {
    if let Some(anchor) = anchor {
        object.insert(key.to_owned(), serde_json::to_value(anchor)?);
    }
    Ok(())
}

/// Attach a resolved location under `key`, or nothing when it did not resolve,
/// so a consumer never sees a half-filled address.
fn insert_location(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    location: Option<amiga_core::Location>,
) -> Result<()> {
    if let Some(location) = location {
        object.insert(key.to_owned(), serde_json::to_value(location)?);
    }
    Ok(())
}

// --- annotated listing (Stage 1) ---------------------------------------------

/// The confidence-marker legend shared by every annotated listing.
pub(crate) const ANNOTATION_LEGEND: &str = "; Annotations: ~ inferred, ? probable, ^ observed; unmarked annotations are exact or user-supplied.";

/// Render the unified annotated listing: every reached instruction with its
/// raw operands and encoded bytes, function labels, and the highest-value
/// annotation inline. `verbose` adds every fact — with confidence, producer,
/// and evidence — on continuation lines. Facts whose subject is not an
/// instruction start (relocations at operand offsets, warnings at
/// undecodable addresses, data symbols) render as `@L`-tagged lines so the
/// listing never hides a fact the report shows.
/// A traversal's instructions in the operation's vocabulary.
///
/// Temporary, and named as such: `disasm annotate` and `disasm report` still
/// compose their own facts, so they have a `ControlFlowAnalysis` and not a
/// response. It goes when those two route through `analysis.code.facts` — the
/// renderer already takes the operation's shape, which is the half that
/// mattered.
pub(crate) fn instructions_of(
    analysis: &amiga_disasm::ControlFlowAnalysis,
) -> Vec<amiga_operations::DisassembledInstruction> {
    analysis
        .instructions
        .values()
        .map(|instruction| amiga_operations::DisassembledInstruction {
            offset: instruction.address,
            address: None,
            bytes: hex::encode(&instruction.encoded),
            text: instruction.text(),
            owners: instruction.owners.iter().copied().collect(),
            owner_total: instruction.owner_total as u64,
        })
        .collect()
}

pub(crate) fn render_annotated(
    instructions: &[amiga_operations::DisassembledInstruction],
    facts: &[Fact],
    resolver: &Resolver<'_>,
    verbose: bool,
) -> Result<String> {
    let index = amiga_disasm::index_by_subject(facts);
    // The function entries come from the facts rather than from a traversal
    // beside them. That is what makes this a rendering: everything it reads is
    // in the fact list, so it cannot disagree with whoever produced it.
    let functions: std::collections::BTreeSet<u32> = facts
        .iter()
        .filter_map(|fact| match fact.kind {
            FactKind::Function { entry } => Some(entry),
            _ => None,
        })
        .collect();
    let mut pending = index.iter().peekable();
    let mut text = String::new();
    for decoded in instructions {
        let offset = &decoded.offset;
        // Facts at addresses before this instruction (data or undecodable
        // bytes between routines).
        while pending.peek().is_some_and(|entry| *entry.0 < *offset) {
            if let Some((&subject, off_facts)) = pending.next() {
                write_off_instruction_facts(&mut text, subject, off_facts, resolver, verbose)?;
            }
        }
        if let Some(label) = line_label(&functions, resolver, *offset) {
            writeln!(text, "{label}:")?;
        }
        let site_facts: &[&Fact] = if pending.peek().is_some_and(|entry| *entry.0 == *offset) {
            pending.next().map_or(&[], |(_, facts)| facts.as_slice())
        } else {
            &[]
        };
        let mut line = format!("L{offset:08X}:  {:<28} ; {}", decoded.text, decoded.bytes);
        if let Some(annotation) = best_annotation(resolver, site_facts) {
            let _ = write!(line, "  ; {annotation}");
        }
        if site_facts
            .iter()
            .any(|fact| matches!(fact.kind, FactKind::UnresolvedFlow))
        {
            line.push_str("  ; !unresolved flow");
        }
        writeln!(text, "{line}")?;
        if verbose {
            for fact in site_facts {
                writeln!(
                    text,
                    "            ;   [{}] {}: {}  <{}>",
                    fact.confidence.label(),
                    fact.producer.label(),
                    describe(resolver, fact),
                    evidence_text(&fact.evidence)
                )?;
            }
        }
        // Facts inside this instruction's byte range (a relocation patching
        // an operand).
        // The instruction's end, from its own encoding: two hex characters a
        // byte, which is the only length the response states.
        let end = decoded
            .offset
            .saturating_add((decoded.bytes.len() / 2) as u32);
        while pending.peek().is_some_and(|entry| *entry.0 < end) {
            if let Some((&subject, inner_facts)) = pending.next() {
                write_off_instruction_facts(&mut text, subject, inner_facts, resolver, verbose)?;
            }
        }
    }
    // Facts beyond the last instruction (trailing data regions).
    for (&subject, off_facts) in pending {
        write_off_instruction_facts(&mut text, subject, off_facts, resolver, verbose)?;
    }
    Ok(text)
}

/// Render facts whose subject is not a rendered instruction start. Compact
/// mode keeps only unresolved-flow warnings (the warning contract); verbose
/// shows every fact, tagged with its own address.
fn write_off_instruction_facts(
    text: &mut String,
    subject: u32,
    facts: &[&Fact],
    resolver: &Resolver<'_>,
    verbose: bool,
) -> Result<()> {
    for fact in facts {
        if verbose {
            writeln!(
                text,
                "            ;   @L{subject:08X} [{}] {}: {}  <{}>",
                fact.confidence.label(),
                fact.producer.label(),
                describe(resolver, fact),
                evidence_text(&fact.evidence)
            )?;
        } else if matches!(fact.kind, FactKind::UnresolvedFlow) {
            writeln!(text, "            ;   @L{subject:08X} !unresolved flow")?;
        }
    }
    Ok(())
}

/// The label printed before an instruction: a config symbol for any labeled
/// address, or the stub name for a discovered function entry.
fn line_label(
    functions: &std::collections::BTreeSet<u32>,
    resolver: &Resolver<'_>,
    offset: u32,
) -> Option<String> {
    if let Some(label) = resolver.label_at(offset) {
        return Some(label);
    }
    functions
        .contains(&offset)
        .then(|| resolver.function_name(offset))
}

/// The compact inline annotation: the present fact with the highest value to a
/// reader, marked by confidence. Unresolved-flow warnings are appended
/// separately so another annotation can never squeeze them out.
fn best_annotation(resolver: &Resolver<'_>, site_facts: &[&Fact]) -> Option<String> {
    site_facts
        .iter()
        .filter_map(|fact| annotation_rank(&fact.kind).map(|rank| (rank, *fact)))
        .min_by_key(|(rank, _)| *rank)
        .and_then(|(_, fact)| {
            compact_annotation(resolver, fact)
                .map(|body| format!("{}{body}", confidence_marker(fact.confidence)))
        })
}

/// Compact-mode priority; `None` never renders inline (labels and warnings
/// have their own channels). Exhaustive so a new fact kind forces a choice.
fn annotation_rank(kind: &FactKind) -> Option<u8> {
    match kind {
        FactKind::LibraryConflict { .. } => Some(0),
        FactKind::LibraryCall { .. } => Some(1),
        FactKind::HardwareAccess { .. } => Some(2),
        FactKind::MemoryAccess { .. } => Some(3),
        // A resolved direct call outranks the raw address reference the same
        // operand produces, so `JSR (abs).L` annotates like `BSR`. A transfer
        // out of the hunk is the same kind of fact, one hunk over.
        FactKind::Call { .. } => Some(4),
        FactKind::ExternalFlow { .. } => Some(5),
        FactKind::FixedPoint { .. } => Some(6),
        FactKind::Clamp { .. } => Some(7),
        FactKind::Reference { .. } => Some(8),
        FactKind::QScale { .. } => Some(9),
        // Regions, reverse links, and disputes belong at the target's own line
        // in the report, not on the instruction that addresses it — which
        // already carries the reference annotation that links there.
        FactKind::DataRegion { .. }
        | FactKind::Function { .. }
        | FactKind::FunctionSignature { .. }
        | FactKind::ReferencedBy { .. }
        | FactKind::TargetConflict { .. }
        | FactKind::UnresolvedFlow
        | FactKind::Relocation { .. }
        | FactKind::Symbol { .. } => None,
    }
}

fn confidence_marker(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Certain | Confidence::User => "",
        Confidence::Inferred => "~",
        Confidence::Probable => "?",
        Confidence::Observed => "^",
    }
}

/// The compact annotation body for a fact, without its confidence marker.
fn compact_annotation(resolver: &Resolver<'_>, fact: &Fact) -> Option<String> {
    let text = match &fact.kind {
        FactKind::LibraryCall {
            lvo,
            library,
            function,
            public,
            ..
        } => match (library, function) {
            (Some(library), Some(function)) => format!(
                "{library}/{function}{}",
                amiga_disasm::private_suffix(*public)
            ),
            (Some(library), None) => format!("{library}/lvo({lvo})"),
            _ => format!("library call lvo({lvo})"),
        },
        FactKind::LibraryConflict {
            lvo, candidates, ..
        } => format!(
            "lvo {lvo}: {}",
            candidates
                .iter()
                .map(|candidate| candidate.library.as_str())
                .collect::<Vec<_>>()
                .join("|")
        ),
        FactKind::HardwareAccess { offset, access, .. } => {
            format!(
                "{} {}",
                access_kind_str(*access),
                hardware_register_label(*offset)
            )
        }
        FactKind::MemoryAccess {
            target,
            access,
            value,
            library_base,
            ..
        } => {
            let mut annotation = memory_access_text(resolver, target, *access);
            if let Some(value) = value {
                let _ = write!(annotation, " = {value:#x}");
            }
            if *library_base {
                annotation.push_str(" (library-base)");
            }
            annotation
        }
        FactKind::Reference {
            target,
            addressing,
            operand,
        } => format!(
            "-> {}",
            resolver.named_location(
                resolver.reference_symbol(fact.subject, *target, *addressing, *operand),
                resolver.reference_short_text(fact.subject, *target, *addressing, *operand)
            )
        ),
        FactKind::FixedPoint {
            idiom,
            fractional_bits,
            ..
        } => format!("{} {}", q_format(*fractional_bits), idiom.as_str()),
        FactKind::Clamp { bound, clamp, .. } => {
            format!("{} clamp {bound:#x}", clamp_side(*clamp))
        }
        FactKind::QScale {
            register,
            fractional_bits,
        } => format!("D{register} = Q{fractional_bits}"),
        // The reviewed contract where one exists, and the name alone where it
        // does not. A signature at the call site is what turns `move.w d1,...`
        // three lines above into an argument with a name.
        FactKind::Call { callee, .. } => match resolver.function_signature(*callee) {
            Some(signature) => format!("call {signature}"),
            None => format!("call {}", resolver.function_name(*callee)),
        },
        FactKind::ExternalFlow {
            transfer,
            target_hunk,
            target_offset,
            ..
        } => format!(
            "{} {}",
            transfer.label(),
            resolver.relocation_target_text(*target_hunk, *target_offset)
        ),
        _ => return None,
    };
    Some(sanitize(text))
}

pub(crate) fn disasm_annotate(
    config_override: Option<&Path>,
    target: &AnalysisArgs,
    library_name: Option<&str>,
    base_register: u8,
    verbose: bool,
) -> Result<()> {
    let mut out = Document::new();
    let prepared = prepare_code_analysis(config_override, target)?;
    let library = parse_library(library_name)?;
    let facts = compose_facts(&prepared, library, base_register)?;
    let resolver = Resolver::for_prepared(&prepared);
    row!(out, "; Unified annotated MC68000 listing by amiga-re");
    row!(out, "; Source SHA-256: {}", sha256(&prepared.bytes));
    if let Some(names) = &prepared.names {
        row!(out, "; Names: {}", names.provenance());
    }
    row!(out, "{ANNOTATION_LEGEND}");
    row!(out);
    part!(
        out,
        "{}",
        render_annotated(
            &instructions_of(&prepared.analysis),
            &facts,
            &resolver,
            verbose,
        )?
    );
    out.print()
}
