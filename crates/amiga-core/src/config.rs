//! Per-project configuration (`amiga-re.toml`).
//!
//! A downstream preservation project keeps the title-specific knobs the toolkit
//! must not hard-code — source-media paths, the fixed mapped origin / entry,
//! default bitmap geometry, and a symbol table — in an `amiga-re.toml` beside
//! its sources. This module defines that schema, discovers the file upward from
//! a starting directory (like `Cargo.toml`), and loads it.
//!
//! The toolkit stays game-agnostic; the config carries the specifics. All
//! sections are optional, so a minimal or empty file is valid.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The conventional config file name discovered by [`discover`].
pub const CONFIG_FILE_NAME: &str = "amiga-re.toml";

/// A parsed `amiga-re.toml`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub project: Project,
    /// Named source-media files, each optionally pinned by SHA-256.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub media: Vec<Media>,
    /// The fixed mapped origin and default entry for address resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Base>,
    /// Default bitmap geometry and palette.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitmap: Option<Bitmap>,
    /// Address → label table.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<Symbol>,
    /// NDK-style `.fd` function-descriptor tables naming library vectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fd: Vec<FdTable>,
}

/// Top-level project metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Project {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Default output directory for extraction/decode commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<PathBuf>,
}

/// A named source-media file, resolved relative to the config's directory.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Media {
    pub name: String,
    pub path: PathBuf,
    /// Pinned SHA-256 of the file, verified by `config check`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The runtime mapping of a fixed-address image.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Base {
    /// Absolute address at which hunk offset zero is mapped.
    pub origin: u32,
    /// Default execution/analysis entry. Defaults to [`Base::origin`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<u32>,
}

impl Base {
    /// The configured entry point, or the mapped origin when omitted.
    #[must_use]
    pub fn default_entry(self) -> u32 {
        self.entry.unwrap_or(self.origin)
    }

    /// Convert an absolute address to a hunk offset (`abs - origin`).
    #[must_use]
    pub fn abs_to_offset(self, absolute: u32) -> Option<u32> {
        absolute.checked_sub(self.origin)
    }

    /// Convert a hunk offset to an absolute address (`offset + origin`).
    #[must_use]
    pub fn offset_to_abs(self, offset: u32) -> Option<u32> {
        offset.checked_add(self.origin)
    }
}

/// Default bitmap geometry and optional palette for image rendering.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Bitmap {
    pub width: u32,
    pub height: u32,
    pub planes: u8,
    /// Optional palette as 12-bit `$0RGB` Amiga color words.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub palette: Vec<u16>,
}

/// A single address → name binding.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Symbol {
    pub addr: u32,
    pub name: String,
}

/// A library's NDK-style `.fd` function-descriptor file, used to name LVO
/// vectors beyond the toolkit's curated tables. The file itself stays in the
/// downstream project (fd files are frequently not redistributable).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FdTable {
    /// The library the table describes (e.g. `"exec"` or
    /// `"graphics.library"`).
    pub library: String,
    /// Path to the `.fd` file, relative to the config's directory.
    pub path: PathBuf,
}

impl Config {
    /// Parse a config from TOML text.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] if the text is not a valid config.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: "<string>".to_owned(),
            source,
        })
    }

    /// Read and parse a config from `path`.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    /// The media entry with the given `name`, if present.
    #[must_use]
    pub fn media(&self, name: &str) -> Option<&Media> {
        self.media.iter().find(|entry| entry.name == name)
    }

    /// The filesystem path of media `name`, resolved relative to `config_dir`
    /// (the directory that holds the config file). `None` if no such media.
    #[must_use]
    pub fn media_path(&self, config_dir: &Path, name: &str) -> Option<PathBuf> {
        self.media(name).map(|media| config_dir.join(&media.path))
    }

    /// The label bound to `addr`, if any.
    #[must_use]
    pub fn symbol_name(&self, addr: u32) -> Option<&str> {
        self.symbols
            .iter()
            .find(|symbol| symbol.addr == addr)
            .map(|symbol| symbol.name.as_str())
    }
}

/// The media name referenced by a `@name` argument, or `None` when `argument`
/// is an ordinary path. This is the syntax the CLI accepts anywhere a source
/// path is expected, resolving the name through the discovered config's
/// `[[media]]` table.
#[must_use]
pub fn media_reference(argument: &str) -> Option<&str> {
    argument.strip_prefix('@').filter(|name| !name.is_empty())
}

/// Search for [`CONFIG_FILE_NAME`] in `start` and each ancestor directory,
/// returning the first match (nearest first).
#[must_use]
pub fn discover(start: &Path) -> Option<PathBuf> {
    let mut directory = Some(start);
    while let Some(current) = directory {
        let candidate = current.join(CONFIG_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        directory = current.parent();
    }
    None
}

/// A failure while loading a config.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        [project]
        name = "sample-project"
        output = "decoded"

        [[media]]
        name = "exe"
        path = "extracted/sample.hunk"
        sha256 = "4c53f0de63bd881b40615ea5485a4edfb5eed746af31dd6ad513f9f5c9a34382"

        [[media]]
        name = "archive"
        path = "original/sample-archive.lha"

        [base]
        origin = 0x10000
        entry = 0x100c2

        [bitmap]
        width = 320
        height = 200
        planes = 4
        palette = [0x000, 0xFFF]

        [[symbols]]
        addr = 0x10200
        name = "load_track"

        [[fd]]
        library = "exec"
        path = "fd/exec_lib.fd"
    "#;

    #[test]
    fn parses_a_full_config() {
        let config = Config::from_toml(SAMPLE).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.project.name.as_deref(), Some("sample-project"));
        assert_eq!(config.media.len(), 2);
        assert_eq!(
            config
                .media("exe")
                .map(|media| &media.path)
                .unwrap()
                .to_str(),
            Some("extracted/sample.hunk")
        );
        assert!(config.media("archive").unwrap().sha256.is_none());
        let base = config
            .base
            .unwrap_or_else(|| panic!("expected a base section"));
        assert_eq!(base.origin, 0x10000);
        assert_eq!(base.default_entry(), 0x100c2);
        assert_eq!(config.bitmap.as_ref().map(|bitmap| bitmap.planes), Some(4));
        assert_eq!(config.symbol_name(0x10200), Some("load_track"));
        assert_eq!(config.fd.len(), 1);
        assert_eq!(config.fd[0].library, "exec");
        assert_eq!(config.fd[0].path.to_str(), Some("fd/exec_lib.fd"));
    }

    #[test]
    fn base_maps_between_addresses_and_offsets() {
        let base = Base {
            origin: 0x10000,
            entry: Some(0x100c2),
        };
        assert_eq!(base.abs_to_offset(0x100c2), Some(0xc2));
        assert_eq!(base.offset_to_abs(0xc2), Some(0x100c2));
        assert_eq!(base.abs_to_offset(0), None);
    }

    #[test]
    fn empty_config_is_valid() {
        let config = Config::from_toml("").unwrap_or_else(|error| panic!("{error}"));
        assert!(config.media.is_empty());
        assert!(config.base.is_none());
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(matches!(
            Config::from_toml("[base]\norigin = \"not a number\""),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn resolves_media_names_and_references() {
        let config = Config::from_toml(SAMPLE).unwrap_or_else(|error| panic!("{error}"));
        let dir = Path::new("/project");
        assert_eq!(
            config.media_path(dir, "exe").as_deref(),
            Some(Path::new("/project/extracted/sample.hunk"))
        );
        assert!(config.media_path(dir, "missing").is_none());
        assert_eq!(media_reference("@exe"), Some("exe"));
        assert_eq!(media_reference("extracted/sample.hunk"), None);
        assert_eq!(media_reference("@"), None);
    }

    #[test]
    fn discovers_config_upward_from_a_subdirectory() {
        let base = std::env::temp_dir().join(format!("amiga-core-config-{}", std::process::id()));
        let nested = base.join("a").join("b");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&nested).unwrap_or_else(|error| panic!("{error}"));
        let config_path = base.join(CONFIG_FILE_NAME);
        std::fs::write(&config_path, "[project]\nname = \"x\"\n")
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(discover(&nested).as_deref(), Some(config_path.as_path()));
        assert_eq!(discover(&base).as_deref(), Some(config_path.as_path()));

        let _ = std::fs::remove_dir_all(&base);
    }
}
