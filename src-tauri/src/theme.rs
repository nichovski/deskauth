use notify::RecommendedWatcher;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub type Palette = BTreeMap<String, String>;

/// CSS variable, colors.toml key, Tokyo Night fallback.
const COLORS: [(&str, &str, &str); 11] = [
    ("--bg", "background", "#1a1b26"),
    ("--bg-alt", "lighter_background", "#24283b"),
    ("--fg", "foreground", "#a9b1d6"),
    ("--fg-dim", "dark_foreground", "#565f89"),
    ("--fg-bright", "bright_foreground", "#c0caf5"),
    ("--accent", "accent", "#7aa2f7"),
    ("--selection", "selection", "#292e42"),
    ("--muted", "muted", "#414868"),
    ("--danger", "red", "#f7768e"),
    ("--warn", "yellow", "#e0af68"),
    ("--ok", "green", "#9ece6a"),
];

pub fn default_palette() -> Palette {
    COLORS
        .iter()
        .map(|(var, _, default)| (var.to_string(), default.to_string()))
        .collect()
}

fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn parse_colors_toml(text: &str) -> Palette {
    let Ok(table) = text.parse::<toml::Table>() else {
        return default_palette();
    };
    COLORS
        .iter()
        .map(|(var, key, default)| {
            let value = table
                .get(*key)
                .and_then(|v| v.as_str())
                .filter(|v| is_hex_color(v))
                .unwrap_or(default);
            (var.to_string(), value.to_string())
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn omarchy_current_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/state/omarchy/current"))
}

pub fn omarchy_colors_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let path = omarchy_current_dir()?.join("theme/colors.toml");
        path.is_file().then_some(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub fn current_palette() -> Palette {
    omarchy_colors_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| parse_colors_toml(&text))
        .unwrap_or_else(default_palette)
}

/// Calls `on_change` with the new palette after Omarchy switches theme.
/// Omarchy replaces the `theme` directory inside `current`, so the parent is watched.
/// Linux only; returns None elsewhere or when the directory cannot be watched.
#[cfg(target_os = "linux")]
pub fn watch(on_change: impl Fn(Palette) + Send + 'static) -> Option<RecommendedWatcher> {
    use notify::{RecursiveMode, Watcher};
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = omarchy_current_dir()?;
    let (tx, rx) = mpsc::channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            let _ = tx.send(());
        }
    })
    .ok()?;
    watcher.watch(&dir, RecursiveMode::NonRecursive).ok()?;

    // Ends when the watcher (and with it the sender) is dropped.
    std::thread::spawn(move || {
        while rx.recv().is_ok() {
            while rx.recv_timeout(Duration::from_millis(200)).is_ok() {}
            on_change(current_palette());
        }
    });
    Some(watcher)
}

#[cfg(not(target_os = "linux"))]
pub fn watch(_on_change: impl Fn(Palette) + Send + 'static) -> Option<RecommendedWatcher> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_file() {
        let p = parse_colors_toml("accent = \"#ff0000\"\nbackground = \"#000000\"\n");
        assert_eq!(p["--accent"], "#ff0000");
        assert_eq!(p["--bg"], "#000000");
    }

    #[test]
    fn missing_keys_fall_back() {
        let p = parse_colors_toml("accent = \"#ff0000\"\n");
        assert_eq!(p["--ok"], "#9ece6a");
    }

    #[test]
    fn invalid_values_fall_back() {
        let p = parse_colors_toml("accent = \"blue\"\n");
        assert_eq!(p["--accent"], "#7aa2f7");
    }

    #[test]
    fn bad_toml_gives_default() {
        assert_eq!(parse_colors_toml("{{{"), default_palette());
    }

    #[test]
    fn palette_has_all_vars() {
        assert_eq!(default_palette().len(), 11);
    }
}
