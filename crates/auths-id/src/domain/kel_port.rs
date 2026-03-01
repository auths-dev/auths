use crate::keri::{Event, IcpEvent, KelError, Prefix};

/// Domain port for Key Event Log operations.
///
/// Abstracts how KERI events are stored and retrieved. The domain
/// provides and receives typed `Event` values without knowledge
/// of the backing store (Git refs, database, in-memory map).
///
/// Args:
/// * `prefix`: The KERI prefix identifying the identity.
///
/// Usage:
/// ```ignore
/// use auths_id::domain::kel_port::KelPort;
/// use auths_id::keri::Prefix;
///
/// fn check_identity(kel: &dyn KelPort, prefix: &Prefix) -> bool {
///     kel.exists(prefix)
/// }
/// ```
pub trait KelPort: Send + Sync {
    /// Returns whether an event log exists for the given prefix.
    ///
    /// Args:
    /// * `prefix`: The KERI prefix to check.
    ///
    /// Usage:
    /// ```ignore
    /// if kel.exists(&prefix) {
    ///     // load events
    /// }
    /// ```
    fn exists(&self, prefix: &Prefix) -> bool;

    /// Returns all events in the log for the given prefix, in order.
    ///
    /// Args:
    /// * `prefix`: The KERI prefix to load events for.
    ///
    /// Usage:
    /// ```ignore
    /// let events = kel.get_events(&prefix)?;
    /// ```
    fn get_events(&self, prefix: &Prefix) -> Result<Vec<Event>, KelError>;

    /// Creates a new event log with an inception event.
    ///
    /// Args:
    /// * `prefix`: The KERI prefix for the new identity.
    /// * `event`: The inception event to store.
    ///
    /// Usage:
    /// ```ignore
    /// kel.create(&prefix, &icp_event)?;
    /// ```
    fn create(&self, prefix: &Prefix, event: &IcpEvent) -> Result<(), KelError>;

    /// Appends an event to an existing log.
    ///
    /// Args:
    /// * `prefix`: The KERI prefix to append to.
    /// * `event`: The event to append.
    ///
    /// Usage:
    /// ```ignore
    /// kel.append(&prefix, &Event::Rot(rot_event))?;
    /// ```
    fn append(&self, prefix: &Prefix, event: &Event) -> Result<(), KelError>;
}
