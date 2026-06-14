//! Validated capability identifiers — the atomic unit of authorization in Auths.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Well-known capability string: permission to sign commits.
pub const SIGN_COMMIT: &str = "sign_commit";
/// Well-known capability string: permission to sign releases.
pub const SIGN_RELEASE: &str = "sign_release";
/// Well-known capability string: permission to add/remove organization members.
pub const MANAGE_MEMBERS: &str = "manage_members";
/// Well-known capability string: permission to rotate keys for an identity.
pub const ROTATE_KEYS: &str = "rotate_keys";

/// Error type for capability parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    /// The capability string is empty.
    #[error("capability is empty")]
    Empty,
    /// The capability string exceeds the maximum length.
    #[error("capability exceeds 64 chars: {0}")]
    TooLong(usize),
    /// The capability string contains invalid characters.
    #[error("invalid characters in capability '{0}': only alphanumeric, ':', '-', '_' allowed")]
    InvalidChars(String),
    /// The capability uses the reserved 'auths:' namespace.
    #[error(
        "reserved namespace 'auths:' — use well-known constructors or choose a different prefix"
    )]
    ReservedNamespace,
    /// The capability uses a reserved infrastructure namespace prefix.
    #[error("the '{0}' prefix is reserved for infrastructure capabilities")]
    ReservedInfraNamespace(String),
}

/// A validated capability identifier.
///
/// Capabilities are the atomic unit of authorization in Auths.
/// They follow a namespace convention:
///
/// - Well-known capabilities: `sign_commit`, `sign_release`, `manage_members`, `rotate_keys`
/// - Custom capabilities: any valid string (alphanumeric + `:` + `-` + `_`, max 64 chars)
///
/// The `auths:` prefix is reserved for future well-known capabilities and cannot be
/// used in custom capabilities created via `parse()`.
///
/// # Examples
///
/// ```
/// use auths_keri::Capability;
///
/// // Well-known capabilities
/// let cap = Capability::sign_commit();
/// assert_eq!(cap.as_str(), "sign_commit");
///
/// // Custom capabilities
/// let custom = Capability::parse("acme:deploy").unwrap();
/// assert_eq!(custom.as_str(), "acme:deploy");
///
/// // Reserved namespace is rejected
/// assert!(Capability::parse("auths:custom").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(try_from = "String", into = "String")]
pub struct Capability(String);

impl Capability {
    /// Maximum length for capability strings.
    pub const MAX_LEN: usize = 64;

    /// Reserved namespace prefix for Auths well-known capabilities.
    const RESERVED_PREFIX: &'static str = "auths:";

    /// Reserved infrastructure capability namespace prefixes.
    const RESERVED_INFRA_PREFIXES: &'static [&'static str] =
        &["compute:", "network:", "storage:", "runtime:", "env:"];

    // ========================================================================
    // Well-known capability constructors
    // ========================================================================

    /// Creates the `sign_commit` capability.
    ///
    /// Grants permission to sign commits.
    #[inline]
    pub fn sign_commit() -> Self {
        Self(SIGN_COMMIT.to_string())
    }

    /// Creates the `sign_release` capability.
    ///
    /// Grants permission to sign releases.
    #[inline]
    pub fn sign_release() -> Self {
        Self(SIGN_RELEASE.to_string())
    }

    /// Creates the `manage_members` capability.
    ///
    /// Grants permission to add/remove members in an organization.
    #[inline]
    pub fn manage_members() -> Self {
        Self(MANAGE_MEMBERS.to_string())
    }

    /// Creates the `rotate_keys` capability.
    ///
    /// Grants permission to rotate keys for an identity.
    #[inline]
    pub fn rotate_keys() -> Self {
        Self(ROTATE_KEYS.to_string())
    }

    // ========================================================================
    // Parsing and validation
    // ========================================================================

    /// Parses and validates a capability string.
    ///
    /// This is the primary way to create custom capabilities. The input is
    /// trimmed and lowercased to produce a canonical form.
    ///
    /// # Validation Rules
    ///
    /// - Non-empty
    /// - Maximum 64 characters
    /// - Only alphanumeric characters, colons (`:`), hyphens (`-`), and underscores (`_`)
    /// - Cannot start with `auths:` (reserved namespace)
    ///
    /// # Examples
    ///
    /// ```
    /// use auths_keri::Capability;
    ///
    /// // Valid custom capabilities
    /// assert!(Capability::parse("deploy").is_ok());
    /// assert!(Capability::parse("acme:deploy").is_ok());
    /// assert!(Capability::parse("org:team:action").is_ok());
    ///
    /// // Invalid capabilities
    /// assert!(Capability::parse("").is_err());           // empty
    /// assert!(Capability::parse("has space").is_err());  // invalid char
    /// assert!(Capability::parse("auths:custom").is_err()); // reserved namespace
    /// ```
    pub fn parse(raw: &str) -> Result<Self, CapabilityError> {
        let canonical = raw.trim().to_lowercase();

        if canonical.is_empty() {
            return Err(CapabilityError::Empty);
        }
        if canonical.len() > Self::MAX_LEN {
            return Err(CapabilityError::TooLong(canonical.len()));
        }
        if !canonical
            .chars()
            .all(|c| c.is_alphanumeric() || c == ':' || c == '-' || c == '_')
        {
            return Err(CapabilityError::InvalidChars(canonical));
        }
        if canonical.starts_with(Self::RESERVED_PREFIX) {
            return Err(CapabilityError::ReservedNamespace);
        }
        for prefix in Self::RESERVED_INFRA_PREFIXES {
            if canonical.starts_with(prefix) {
                return Err(CapabilityError::ReservedInfraNamespace(prefix.to_string()));
            }
        }

        Ok(Self(canonical))
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Returns the canonical string representation of this capability.
    ///
    /// This is the authoritative string form used for comparison, display,
    /// and serialization.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this is a well-known Auths capability.
    pub fn is_well_known(&self) -> bool {
        matches!(
            self.0.as_str(),
            SIGN_COMMIT | SIGN_RELEASE | MANAGE_MEMBERS | ROTATE_KEYS
        )
    }

    /// Returns the namespace portion of the capability (before first colon), if any.
    pub fn namespace(&self) -> Option<&str> {
        self.0.split(':').next().filter(|_| self.0.contains(':'))
    }

    // ========================================================================
    // Capability-claim codec — the single grammar for an ACDC `a.capability`
    // ========================================================================

    /// Separator between capabilities packed into one `a.capability` claim string.
    ///
    /// A capability identifier can never contain a comma ([`Capability::parse`]
    /// only admits alphanumerics, `:`, `-`, `_`), so the comma is an unambiguous
    /// delimiter for the multi-capability claim.
    const CLAIM_SEPARATOR: char = ',';

    /// Encode a set of capabilities into the single `a.capability` claim string.
    ///
    /// This is the one source of truth for the on-wire grammar: capabilities are
    /// joined by [`Self::CLAIM_SEPARATOR`]. The issuer writes the claim with this;
    /// every reader decodes it with [`Self::parse_claim`] — they cannot disagree.
    ///
    /// # Examples
    ///
    /// ```
    /// use auths_keri::Capability;
    /// let caps = [Capability::parse("fs:read").unwrap(), Capability::parse("fs:write").unwrap()];
    /// assert_eq!(Capability::join_claim(&caps), "fs:read,fs:write");
    /// ```
    pub fn join_claim(capabilities: &[Capability]) -> String {
        capabilities
            .iter()
            .map(Capability::as_str)
            .collect::<Vec<_>>()
            .join(&Self::CLAIM_SEPARATOR.to_string())
    }

    /// Decode an `a.capability` claim string into its capabilities.
    ///
    /// The inverse of [`Self::join_claim`]: splits on [`Self::CLAIM_SEPARATOR`] and
    /// parses each segment. Returns `Err` if any segment is not a valid capability,
    /// so an issuer/verifier grammar mismatch fails closed rather than silently
    /// admitting a malformed claim. An empty claim yields no capabilities.
    ///
    /// # Examples
    ///
    /// ```
    /// use auths_keri::Capability;
    /// let caps = Capability::parse_claim("fs:read,fs:write").unwrap();
    /// assert_eq!(caps.len(), 2);
    /// assert!(Capability::parse_claim("").unwrap().is_empty());
    /// ```
    pub fn parse_claim(claim: &str) -> Result<Vec<Capability>, CapabilityError> {
        if claim.is_empty() {
            return Ok(Vec::new());
        }
        claim
            .split(Self::CLAIM_SEPARATOR)
            .map(Capability::parse)
            .collect()
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The well-known resource name of the call-count usage cap (`calls:<N>`).
///
/// A capability of the form `calls:<N>` (or `calls<=<N>`) is not an opaque
/// presence token — it is a *quantitative* predicate bounding how many times the
/// credential may be exercised. [`UsageCap::from_capability`] recognizes it; the
/// verifier enforces the bound against a monotonic usage record so the `(N+1)`-th
/// use is unverifiable rather than merely logged.
const USAGE_CAP_RESOURCE: &str = "calls";

/// A quantitative usage bound parsed from a [`Capability`].
///
/// Capabilities are normally opaque presence tokens (`sign_commit`, `acme:deploy`):
/// holding the credential grants the action, with no notion of "how many times".
/// A *quantitative* capability instead bounds a measured resource. The first such
/// resource is the call count: `calls:<N>` means "at most `N` exercises of this
/// credential". The bound rides in the capability claim, which is part of the ACDC
/// SAID, so it cannot be edited without breaking the credential.
///
/// The verifier consumes a monotonic usage record alongside the credential: a
/// presentation whose observed count has reached the cap is rejected with a
/// distinct cap-exceeded verdict, and a presentation replaying an earlier (lower)
/// count than the highest already observed is rejected as a rolled-back counter.
///
/// # Examples
///
/// ```
/// use auths_keri::{Capability, UsageCap};
///
/// let cap = Capability::parse("calls:3").unwrap();
/// assert_eq!(UsageCap::from_capability(&cap), Some(UsageCap::calls(3)));
///
/// // A presence token carries no quantitative bound.
/// let sign = Capability::sign_commit();
/// assert_eq!(UsageCap::from_capability(&sign), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UsageCap {
    /// The maximum number of calls this credential admits.
    max_calls: u64,
}

impl UsageCap {
    /// Construct a call-count cap admitting at most `max_calls` exercises.
    #[inline]
    pub const fn calls(max_calls: u64) -> Self {
        Self { max_calls }
    }

    /// The maximum number of calls this credential admits.
    #[inline]
    pub const fn max_calls(self) -> u64 {
        self.max_calls
    }

    /// Parse the quantitative usage bound carried by a capability, if any.
    ///
    /// Recognizes the call-count grammar `calls:<N>` and the comparison spelling
    /// `calls<=<N>`, where `<N>` is a non-negative decimal integer. Any other
    /// capability (a presence token, a different resource) carries no bound and
    /// yields `None`. A `calls` resource with a missing or non-numeric bound also
    /// yields `None` — the credential then has no enforceable quantitative cap and
    /// is treated as an ordinary (unbounded) capability, never silently zero.
    pub fn from_capability(cap: &Capability) -> Option<Self> {
        Self::from_claim_segment(cap.as_str())
    }

    /// The first quantitative usage bound among a set of capabilities, if any.
    ///
    /// A credential carries at most one call-count cap; this returns the first one
    /// found so the verifier can enforce it regardless of where it sits among the
    /// granted capabilities.
    pub fn from_capabilities(caps: &[Capability]) -> Option<Self> {
        caps.iter().find_map(Self::from_capability)
    }

    /// Parse one capability-claim segment as a usage bound.
    ///
    /// The `calls<=<N>` spelling is accepted even though [`Capability::parse`] does
    /// not admit `<`/`=` (so it never reaches here through a parsed capability) —
    /// recognizing both spellings keeps the predicate grammar stable if a future
    /// capability charset admits the comparison operator.
    fn from_claim_segment(segment: &str) -> Option<Self> {
        let bound = segment
            .strip_prefix(&format!("{USAGE_CAP_RESOURCE}:"))
            .or_else(|| segment.strip_prefix(&format!("{USAGE_CAP_RESOURCE}<=")))?;
        bound.parse::<u64>().ok().map(Self::calls)
    }
}

impl fmt::Display for UsageCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{USAGE_CAP_RESOURCE}:{}", self.max_calls)
    }
}

impl TryFrom<String> for Capability {
    type Error = CapabilityError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let canonical = s.trim().to_lowercase();

        if canonical.is_empty() {
            return Err(CapabilityError::Empty);
        }
        if canonical.len() > Self::MAX_LEN {
            return Err(CapabilityError::TooLong(canonical.len()));
        }
        if !canonical
            .chars()
            .all(|c| c.is_alphanumeric() || c == ':' || c == '-' || c == '_')
        {
            return Err(CapabilityError::InvalidChars(canonical));
        }

        // During deserialization, allow well-known capabilities and auths: prefix
        // This ensures backward compatibility with existing attestations
        Ok(Self(canonical))
    }
}

impl std::str::FromStr for Capability {
    type Err = CapabilityError;

    /// Parses a capability string with CLI-friendly alias resolution.
    ///
    /// Normalizes the input (trim, lowercase, replace hyphens with underscores)
    /// and matches well-known capabilities before falling through to
    /// `Capability::parse()` for custom capability validation.
    ///
    /// Args:
    /// * `s`: The capability string (e.g., "sign_commit", "Sign-Commit").
    ///
    /// Usage:
    /// ```
    /// use auths_keri::Capability;
    /// let cap: Capability = "sign_commit".parse().unwrap();
    /// assert_eq!(cap.as_str(), "sign_commit");
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_lowercase().replace('-', "_");
        match normalized.as_str() {
            "sign_commit" | "signcommit" => Ok(Capability::sign_commit()),
            "sign_release" | "signrelease" => Ok(Capability::sign_release()),
            "manage_members" | "managemembers" => Ok(Capability::manage_members()),
            "rotate_keys" | "rotatekeys" => Ok(Capability::rotate_keys()),
            _ => Capability::parse(&normalized),
        }
    }
}

impl From<Capability> for String {
    fn from(cap: Capability) -> Self {
        cap.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Capability serialization tests
    // ========================================================================

    #[test]
    fn capability_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&Capability::sign_commit()).unwrap(),
            r#""sign_commit""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::sign_release()).unwrap(),
            r#""sign_release""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::manage_members()).unwrap(),
            r#""manage_members""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::rotate_keys()).unwrap(),
            r#""rotate_keys""#
        );
    }

    #[test]
    fn capability_deserializes_from_snake_case() {
        assert_eq!(
            serde_json::from_str::<Capability>(r#""sign_commit""#).unwrap(),
            Capability::sign_commit()
        );
        assert_eq!(
            serde_json::from_str::<Capability>(r#""sign_release""#).unwrap(),
            Capability::sign_release()
        );
        assert_eq!(
            serde_json::from_str::<Capability>(r#""manage_members""#).unwrap(),
            Capability::manage_members()
        );
        assert_eq!(
            serde_json::from_str::<Capability>(r#""rotate_keys""#).unwrap(),
            Capability::rotate_keys()
        );
    }

    #[test]
    fn capability_custom_serializes_as_string() {
        let cap = Capability::parse("acme:deploy").unwrap();
        assert_eq!(serde_json::to_string(&cap).unwrap(), r#""acme:deploy""#);
    }

    #[test]
    fn capability_custom_deserializes_unknown_strings() {
        // Unknown strings become custom capabilities
        let cap: Capability = serde_json::from_str(r#""custom-capability""#).unwrap();
        assert_eq!(cap, Capability::parse("custom-capability").unwrap());
    }

    // ========================================================================
    // Capability parse() validation tests
    // ========================================================================

    #[test]
    fn capability_parse_accepts_valid_strings() {
        assert!(Capability::parse("deploy").is_ok());
        assert!(Capability::parse("acme:deploy").is_ok());
        assert!(Capability::parse("my-custom-cap").is_ok());
        assert!(Capability::parse("org:team:action").is_ok());
        assert!(Capability::parse("with_underscore").is_ok()); // underscore allowed
    }

    #[test]
    fn capability_parse_rejects_invalid_strings() {
        // Empty
        assert!(matches!(Capability::parse(""), Err(CapabilityError::Empty)));

        // Too long
        assert!(matches!(
            Capability::parse(&"a".repeat(65)),
            Err(CapabilityError::TooLong(65))
        ));

        // Invalid characters
        assert!(matches!(
            Capability::parse("has spaces"),
            Err(CapabilityError::InvalidChars(_))
        ));
        assert!(matches!(
            Capability::parse("has.dot"),
            Err(CapabilityError::InvalidChars(_))
        ));
    }

    #[test]
    fn capability_parse_rejects_reserved_namespace() {
        assert!(matches!(
            Capability::parse("auths:custom"),
            Err(CapabilityError::ReservedNamespace)
        ));
        assert!(matches!(
            Capability::parse("auths:sign_commit"),
            Err(CapabilityError::ReservedNamespace)
        ));
    }

    #[test]
    fn capability_parse_accepts_role_markers() {
        // The org delegation layer encodes role markers ("role:admin") inside
        // capability vecs; "role:" is not a reserved prefix and must round-trip.
        let cap = Capability::parse("role:admin").unwrap();
        assert_eq!(cap.as_str(), "role:admin");

        let json = serde_json::to_string(&cap).unwrap();
        let roundtrip: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, roundtrip);
    }

    #[test]
    fn capability_parse_normalizes_to_lowercase() {
        let cap = Capability::parse("DEPLOY").unwrap();
        assert_eq!(cap.as_str(), "deploy");

        let cap = Capability::parse("ACME:Deploy").unwrap();
        assert_eq!(cap.as_str(), "acme:deploy");
    }

    #[test]
    fn capability_parse_trims_whitespace() {
        let cap = Capability::parse("  deploy  ").unwrap();
        assert_eq!(cap.as_str(), "deploy");
    }

    // ========================================================================
    // Capability equality and hashing tests
    // ========================================================================

    #[test]
    fn capability_is_hashable() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Capability::sign_commit());
        set.insert(Capability::sign_release());
        set.insert(Capability::parse("test").unwrap());
        assert_eq!(set.len(), 3);
        assert!(set.contains(&Capability::sign_commit()));
    }

    #[test]
    fn capability_equality_with_different_construction_paths() {
        // Well-known constructor equals deserialized
        let from_constructor = Capability::sign_commit();
        let from_deser: Capability = serde_json::from_str(r#""sign_commit""#).unwrap();
        assert_eq!(from_constructor, from_deser);

        // Parse equals deserialized for custom capabilities
        let from_parse = Capability::parse("acme:deploy").unwrap();
        let from_deser: Capability = serde_json::from_str(r#""acme:deploy""#).unwrap();
        assert_eq!(from_parse, from_deser);
    }

    // ========================================================================
    // Capability display and accessor tests
    // ========================================================================

    #[test]
    fn capability_display_matches_canonical_form() {
        assert_eq!(Capability::sign_commit().to_string(), "sign_commit");
        assert_eq!(Capability::sign_release().to_string(), "sign_release");
        assert_eq!(Capability::manage_members().to_string(), "manage_members");
        assert_eq!(Capability::rotate_keys().to_string(), "rotate_keys");
        assert_eq!(
            Capability::parse("acme:deploy").unwrap().to_string(),
            "acme:deploy"
        );
    }

    #[test]
    fn capability_as_str_returns_canonical_form() {
        assert_eq!(Capability::sign_commit().as_str(), "sign_commit");
        assert_eq!(Capability::sign_release().as_str(), "sign_release");
        assert_eq!(Capability::manage_members().as_str(), "manage_members");
        assert_eq!(Capability::rotate_keys().as_str(), "rotate_keys");
        assert_eq!(
            Capability::parse("acme:deploy").unwrap().as_str(),
            "acme:deploy"
        );
    }

    #[test]
    fn capability_is_well_known() {
        assert!(Capability::sign_commit().is_well_known());
        assert!(Capability::sign_release().is_well_known());
        assert!(Capability::manage_members().is_well_known());
        assert!(Capability::rotate_keys().is_well_known());
        assert!(!Capability::parse("custom").unwrap().is_well_known());
    }

    #[test]
    fn capability_namespace() {
        assert_eq!(
            Capability::parse("acme:deploy").unwrap().namespace(),
            Some("acme")
        );
        assert_eq!(
            Capability::parse("org:team:action").unwrap().namespace(),
            Some("org")
        );
        assert_eq!(Capability::parse("deploy").unwrap().namespace(), None);
    }

    // ========================================================================
    // Capability vec serialization tests
    // ========================================================================

    #[test]
    fn capability_vec_serializes_as_array() {
        let caps = vec![Capability::sign_commit(), Capability::sign_release()];
        let json = serde_json::to_string(&caps).unwrap();
        assert_eq!(json, r#"["sign_commit","sign_release"]"#);
    }

    #[test]
    fn capability_vec_deserializes_from_array() {
        let json = r#"["sign_commit","manage_members","custom-cap"]"#;
        let caps: Vec<Capability> = serde_json::from_str(json).unwrap();
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0], Capability::sign_commit());
        assert_eq!(caps[1], Capability::manage_members());
        assert_eq!(caps[2], Capability::parse("custom-cap").unwrap());
    }

    // ========================================================================
    // Capability-claim codec tests — issuer and verifier share one grammar
    // ========================================================================

    #[test]
    fn claim_codec_roundtrips_multi_capability() {
        let caps = vec![
            Capability::parse("fs:read").unwrap(),
            Capability::parse("fs:write").unwrap(),
        ];
        let claim = Capability::join_claim(&caps);
        assert_eq!(claim, "fs:read,fs:write");
        assert_eq!(Capability::parse_claim(&claim).unwrap(), caps);
    }

    #[test]
    fn claim_codec_roundtrips_single_capability() {
        let caps = vec![Capability::sign_commit()];
        let claim = Capability::join_claim(&caps);
        assert_eq!(claim, "sign_commit");
        assert_eq!(Capability::parse_claim(&claim).unwrap(), caps);
    }

    #[test]
    fn parse_claim_empty_is_no_capabilities() {
        assert!(Capability::parse_claim("").unwrap().is_empty());
    }

    #[test]
    fn parse_claim_rejects_malformed_segment() {
        // A segment with an invalid char fails closed rather than silently dropping.
        assert!(matches!(
            Capability::parse_claim("fs:read,has space"),
            Err(CapabilityError::InvalidChars(_))
        ));
    }

    #[test]
    fn join_claim_of_empty_is_empty_string() {
        assert_eq!(Capability::join_claim(&[]), "");
    }

    // ========================================================================
    // UsageCap — quantitative capability predicate tests
    // ========================================================================

    #[test]
    fn usage_cap_parses_colon_grammar() {
        let cap = Capability::parse("calls:3").unwrap();
        assert_eq!(UsageCap::from_capability(&cap), Some(UsageCap::calls(3)));
        assert_eq!(UsageCap::from_capability(&cap).unwrap().max_calls(), 3);
    }

    #[test]
    fn usage_cap_parses_comparison_grammar() {
        // `calls<=5` does not pass Capability::parse (charset), but the segment
        // parser recognizes the comparison spelling directly.
        assert_eq!(
            UsageCap::from_claim_segment("calls<=5"),
            Some(UsageCap::calls(5))
        );
    }

    #[test]
    fn usage_cap_zero_is_a_real_bound() {
        let cap = Capability::parse("calls:0").unwrap();
        assert_eq!(UsageCap::from_capability(&cap), Some(UsageCap::calls(0)));
    }

    #[test]
    fn presence_token_carries_no_usage_cap() {
        assert_eq!(UsageCap::from_capability(&Capability::sign_commit()), None);
        let deploy = Capability::parse("acme:deploy").unwrap();
        assert_eq!(UsageCap::from_capability(&deploy), None);
    }

    #[test]
    fn calls_resource_with_non_numeric_bound_is_not_a_cap() {
        // `calls:abc` is a valid capability string but not an enforceable bound —
        // it must not silently become a zero cap.
        let cap = Capability::parse("calls:abc").unwrap();
        assert_eq!(UsageCap::from_capability(&cap), None);
    }

    #[test]
    fn usage_cap_found_among_many_capabilities() {
        let caps = vec![
            Capability::sign_commit(),
            Capability::parse("calls:7").unwrap(),
            Capability::parse("acme:deploy").unwrap(),
        ];
        assert_eq!(UsageCap::from_capabilities(&caps), Some(UsageCap::calls(7)));
    }

    #[test]
    fn usage_cap_displays_canonical_grammar() {
        assert_eq!(UsageCap::calls(3).to_string(), "calls:3");
    }

    // ========================================================================
    // Serde roundtrip tests (critical for backward compat)
    // ========================================================================

    #[test]
    fn capability_serde_roundtrip_well_known() {
        let caps = vec![
            Capability::sign_commit(),
            Capability::sign_release(),
            Capability::manage_members(),
            Capability::rotate_keys(),
        ];
        for cap in caps {
            let json = serde_json::to_string(&cap).unwrap();
            let roundtrip: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, roundtrip);
        }
    }

    #[test]
    fn capability_serde_roundtrip_custom() {
        let caps = vec![
            Capability::parse("deploy").unwrap(),
            Capability::parse("acme:deploy").unwrap(),
            Capability::parse("org:team:action").unwrap(),
        ];
        for cap in caps {
            let json = serde_json::to_string(&cap).unwrap();
            let roundtrip: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, roundtrip);
        }
    }
}
