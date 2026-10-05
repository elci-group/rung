//! Version anchor for [theosis](https://github.com/elci-group/theosis).
//!
//! Theosis reads a literal `A.B.C` from the first `[package]` table in the
//! workspace-root `Cargo.toml`. The `rung` binary lives in `crates/rung-cli`
//! and inherits `[workspace.package].version`. This package is not the binary
//! and is not published.

/// Same number as `[package].version` and `[workspace.package].version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod theosis_contract {
    use std::fs;

    fn table_version(manifest: &str, header: &str) -> Result<String, String> {
        let version = manifest
            .lines()
            .skip_while(|line| line.trim() != header)
            .skip(1)
            .take_while(|line| !line.trim_start().starts_with('['))
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                if key.trim() != "version" {
                    return None;
                }
                Some(
                    value
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string(),
                )
            })
            .ok_or_else(|| format!("{header} has no version"))?;
        let mut parts = version.split('.');
        let major = parts.next().ok_or("missing major")?;
        let minor = parts.next().ok_or("missing minor")?;
        let patch = parts.next().ok_or("missing patch")?;
        if parts.next().is_some()
            || major.parse::<u64>().is_err()
            || minor.parse::<u64>().is_err()
            || patch.parse::<u64>().is_err()
        {
            return Err(format!("version must contain exactly A.B.C, got {version}"));
        }
        Ok(version)
    }

    #[test]
    fn theosis_reads_the_binary_version() -> Result<(), String> {
        let manifest = include_str!("../Cargo.toml");
        let root = table_version(manifest, "[package]")?;
        let workspace = table_version(manifest, "[workspace.package]")?;
        if root != workspace || root != env!("CARGO_PKG_VERSION") {
            return Err(format!(
                "root {root}, workspace {workspace}, package {}",
                env!("CARGO_PKG_VERSION")
            ));
        }
        let recorded = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/VERSION"))
            .map_err(|error| error.to_string())?;
        if recorded.trim() != root {
            return Err(format!("VERSION file is {}", recorded.trim()));
        }
        let recipe = include_str!("../.baby.toml");
        if !recipe.contains("binary = \"rung\"") || !recipe.contains("baby.install/v1") {
            return Err("baby recipe does not install the rung binary".into());
        }
        Ok(())
    }
}
