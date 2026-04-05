//! Forge detection from git remote URLs.
//!
//! Parses git remote URLs (HTTPS, SSH, bare shorthand) into a [`Forge`] variant
//! identifying the hosting platform and repository path.

/// A detected forge (hosting platform) and its repository identifier.
///
/// Usage:
/// ```ignore
/// let forge = Forge::from_url("git@github.com:owner/repo.git");
/// assert_eq!(forge.display_name(), "GitHub");
/// assert_eq!(forge.repo_identifier(), "owner/repo");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forge {
    /// GitHub (github.com or enterprise instances containing "github").
    GitHub {
        /// Repository in `owner/repo` format.
        owner_repo: String,
    },
    /// GitLab (gitlab.com or instances containing "gitlab").
    GitLab {
        /// Repository in `group/project` format (may include subgroups).
        group_project: String,
    },
    /// Bitbucket (bitbucket.org or instances containing "bitbucket").
    Bitbucket {
        /// Repository in `workspace/repo` format.
        workspace_repo: String,
    },
    /// Radicle (hosts containing "radicle").
    Radicle {
        /// Radicle repository identifier.
        rid: String,
    },
    /// Unrecognized hosting platform.
    Unknown {
        /// The original URL or identifier.
        url: String,
    },
}

impl Forge {
    /// Parse any git remote URL or shorthand into a `Forge` variant.
    ///
    /// Handles HTTPS (`https://github.com/owner/repo.git`), SSH
    /// (`git@github.com:owner/repo.git`), and bare shorthand (`owner/repo`).
    /// Strips `.git` suffix automatically.
    ///
    /// Args:
    /// * `url`: The git remote URL string.
    ///
    /// Usage:
    /// ```ignore
    /// let forge = Forge::from_url("https://github.com/auths-dev/auths.git");
    /// assert!(matches!(forge, Forge::GitHub { .. }));
    /// ```
    pub fn from_url(url: &str) -> Self {
        let url = url.trim().trim_end_matches(".git");

        // SSH: git@host:path
        if let Some(rest) = url.strip_prefix("git@")
            && let Some((host, path)) = rest.split_once(':')
        {
            return Self::from_host_and_path(host, path);
        }

        // SSH with explicit protocol: ssh://git@host/path or ssh://git@host:port/path
        if let Some(rest) = url.strip_prefix("ssh://git@")
            && let Some((host_port, path)) = rest.split_once('/')
        {
            let host = host_port.split(':').next().unwrap_or(host_port);
            return Self::from_host_and_path(host, path);
        }

        // HTTPS/HTTP: https://host/path
        if let Some(rest) = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            && let Some((host, path)) = rest.split_once('/')
        {
            return Self::from_host_and_path(host, path);
        }

        // Bare owner/repo — cannot determine forge without hostname
        if url.contains('/') && !url.contains(':') && !url.contains('.') {
            return Forge::Unknown {
                url: url.to_string(),
            };
        }

        Forge::Unknown {
            url: url.to_string(),
        }
    }

    /// Match a hostname and path to a forge variant.
    fn from_host_and_path(host: &str, path: &str) -> Self {
        let path = path
            .trim_start_matches('/')
            .trim_end_matches('/')
            .to_string();
        let host_lower = host.to_lowercase();

        if host_lower.contains("github") {
            Forge::GitHub { owner_repo: path }
        } else if host_lower.contains("gitlab") {
            Forge::GitLab {
                group_project: path,
            }
        } else if host_lower.contains("bitbucket") {
            Forge::Bitbucket {
                workspace_repo: path,
            }
        } else if host_lower.contains("radicle") {
            Forge::Radicle { rid: path }
        } else {
            Forge::Unknown {
                url: format!("{host}/{path}"),
            }
        }
    }

    /// Human-readable name for this forge.
    ///
    /// Usage:
    /// ```ignore
    /// assert_eq!(Forge::GitHub { owner_repo: "a/b".into() }.display_name(), "GitHub");
    /// ```
    pub fn display_name(&self) -> &str {
        match self {
            Forge::GitHub { .. } => "GitHub",
            Forge::GitLab { .. } => "GitLab",
            Forge::Bitbucket { .. } => "Bitbucket",
            Forge::Radicle { .. } => "Radicle",
            Forge::Unknown { .. } => "Unknown",
        }
    }

    /// The repository identifier string (e.g., `owner/repo`).
    ///
    /// Usage:
    /// ```ignore
    /// let forge = Forge::from_url("git@github.com:auths-dev/auths.git");
    /// assert_eq!(forge.repo_identifier(), "auths-dev/auths");
    /// ```
    pub fn repo_identifier(&self) -> &str {
        match self {
            Forge::GitHub { owner_repo } => owner_repo,
            Forge::GitLab { group_project } => group_project,
            Forge::Bitbucket { workspace_repo } => workspace_repo,
            Forge::Radicle { rid } => rid,
            Forge::Unknown { url } => url,
        }
    }
}
