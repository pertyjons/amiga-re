//! Everything an operation may reach outside its own arguments.

use amiga_core::{Cancel, Never};

use crate::limits::OperationLimits;
use crate::output::{DestinationResolver, NoDestinations};
use crate::source::SourceResolver;

/// The immutable environment one operation executes in.
///
/// Deliberately passed by reference for the duration of a single execution
/// rather than held in process-global state: an adapter's overrides belong to
/// the request it is serving, not to the process serving it.
pub struct ExecutionContext<'a> {
    resolver: &'a dyn SourceResolver,
    limits: OperationLimits,
    cancel: &'a dyn Cancel,
    destinations: &'a dyn DestinationResolver,
}

/// The signal a context carries when the adapter did not supply one.
///
/// A `'static` value so a borrowed default needs no lifetime gymnastics, and a
/// never-firing one so a command-line caller — which has nobody to cancel on
/// its behalf — pays nothing.
static NEVER: Never = Never;

/// The destination resolver a context carries when the adapter offered none.
///
/// Refusing by default is what makes "this adapter may not write" the state a
/// caller has to leave deliberately, rather than one it has to remember to
/// enter.
static NO_DESTINATIONS: NoDestinations = NoDestinations;

impl<'a> ExecutionContext<'a> {
    /// A context with the default limits.
    #[must_use]
    pub fn new(resolver: &'a dyn SourceResolver) -> Self {
        Self {
            resolver,
            limits: OperationLimits::default(),
            cancel: &NEVER,
            destinations: &NO_DESTINATIONS,
        }
    }

    /// Let operations write beneath the destinations `resolver` serves.
    ///
    /// Without this an operation that wants to write is refused, however its
    /// request is spelled: an adapter that has not named an output root has
    /// not authorized one.
    #[must_use]
    pub const fn with_destinations(mut self, resolver: &'a dyn DestinationResolver) -> Self {
        self.destinations = resolver;
        self
    }

    #[must_use]
    pub const fn destinations(&self) -> &'a dyn DestinationResolver {
        self.destinations
    }

    /// Run under a caller's stop signal.
    ///
    /// The router checks this before dispatch; handlers also poll at their
    /// own checkpoints. An observed cancellation returns
    /// [`crate::protocol::Status::Cancelled`] with no result, so a stopped
    /// operation is never mistaken for one that found nothing.
    #[must_use]
    pub const fn with_cancel(mut self, cancel: &'a dyn Cancel) -> Self {
        self.cancel = cancel;
        self
    }

    #[must_use]
    pub const fn cancel(&self) -> &'a dyn Cancel {
        self.cancel
    }

    #[must_use]
    pub const fn with_limits(mut self, limits: OperationLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub const fn resolver(&self) -> &'a dyn SourceResolver {
        self.resolver
    }

    pub const fn limits(&self) -> OperationLimits {
        self.limits
    }

    /// Resolve one normalized source to the bytes an operation will read.
    ///
    /// A whole file is the resolver's answer unchanged. A member is the
    /// resolver's answer for the container, then each selector handed to
    /// [`crate::recovery::ContainerRecovery`] in turn — the same recoverer
    /// `project.verify` walks a derivation with, so "the member
    /// `s/startup-sequence` inside disk1.adf" means one thing in this toolkit
    /// rather than two.
    ///
    /// `maximum_bytes` bounds *both* ends. The container is refused if it is
    /// over the limit, because reading it is what costs the memory; and so is
    /// the recovered result, because a small archive can hold a large member and
    /// a caller that set a ceiling meant the bytes it would read.
    ///
    /// The pin covers the **recovered** bytes, not the container's: that is what
    /// the operation reads, and a result citing the container's digest would be
    /// reproducible only by someone who already knew which member was meant.
    ///
    /// # Errors
    /// Returns [`crate::source::SourceError`] when the container is missing,
    /// oversized or unreadable, when a selector names nothing, or when the
    /// recovered bytes are over the limit.
    pub fn resolve_source(
        &self,
        source: &crate::normalize::NormalizedSource,
        maximum_bytes: u64,
    ) -> Result<crate::source::ResolvedSource, crate::source::SourceError> {
        use amiga_project::Recover as _;

        let mut resolved = self.resolver.resolve(&source.parent, maximum_bytes)?;
        if source.members.is_empty() {
            return Ok(resolved);
        }

        let name = crate::source::SourceName::parse(source.parent.as_str())
            .unwrap_or_else(|_| source.parent.clone());
        let recovery = crate::recovery::ContainerRecovery::new(maximum_bytes);
        for selector in &source.members {
            let recovered = recovery
                .recover(selector, resolved.bytes())
                .map_err(|message| crate::source::SourceError::Unreadable {
                    name: name.clone(),
                    message: format!(
                        "recovering {} from {}: {message}",
                        selector.container(),
                        source.parent.as_str()
                    ),
                })?;
            let size = recovered.len() as u64;
            if size > maximum_bytes {
                return Err(crate::source::SourceError::TooLarge {
                    name: name.clone(),
                    size,
                    limit: maximum_bytes,
                });
            }
            resolved = crate::source::ResolvedSource::new(name.clone(), recovered.into());
        }
        Ok(resolved)
    }
}
