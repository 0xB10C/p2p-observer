//! Checks the Grafana dashboards in `dashboards/`, and lists them:
//!
//! ```text
//! cargo test -p metrics --test dashboards -- --nocapture
//! ```
//!
//! Every dashboard is one for a playlist: a single panel, a description, the
//! playlist tag, UTC, and the one datasource uid the readme documents. The
//! description is a dashboard link with the `doc` icon and `#` as its URL,
//! which Grafana shows at the top of the dashboard and which goes nowhere
//! when clicked; its title is the text. The same convention as
//! peer-observer's dashboards.

use std::fs;
use std::path::{Path, PathBuf};

use common::serde_json::Value;

const DASHBOARDS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dashboards");
const PLAYLIST_TAG: &str = "p2p-observer-playlist";
const DATASOURCE_UID: &str = "prometheus-p2p-observer";

/// Every `.json` below `dir`, sorted by path.
fn dashboard_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display())) {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            files.extend(dashboard_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// The description: the title of the first link with the `doc` icon that
/// points to `#`. `None` without one, or with an empty title.
fn description(dashboard: &Value) -> Option<&str> {
    dashboard
        .get("links")?
        .as_array()?
        .iter()
        .find(|link| {
            link.get("type").and_then(Value::as_str) == Some("link")
                && link.get("icon").and_then(Value::as_str) == Some("doc")
                && link.get("url").and_then(Value::as_str) == Some("#")
        })?
        .get("title")?
        .as_str()
        .map(str::trim)
        .filter(|title| !title.is_empty())
}

/// Every `datasource.uid` anywhere in the dashboard, Grafana's own aside.
fn datasource_uids(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(ds) = map.get("datasource").and_then(Value::as_object)
                && ds.get("type").and_then(Value::as_str) != Some("grafana")
                && let Some(uid) = ds.get("uid").and_then(Value::as_str)
            {
                out.push(uid.to_owned());
            }
            for v in map.values() {
                datasource_uids(v, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| datasource_uids(v, out)),
        _ => {}
    }
}

/// What is wrong with a dashboard; empty when nothing.
fn problems(dashboard: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    if description(dashboard).is_none() {
        problems.push("no description link".to_owned());
    }
    let panels = dashboard
        .get("panels")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if panels != 1 {
        problems.push(format!("{panels} panels, a playlist dashboard has one"));
    }
    let tags = dashboard.get("tags").and_then(Value::as_array);
    if !tags.is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some(PLAYLIST_TAG))) {
        problems.push(format!("missing the {PLAYLIST_TAG} tag"));
    }
    if dashboard.get("timezone").and_then(Value::as_str) != Some("utc") {
        problems.push("timezone is not utc".to_owned());
    }
    if dashboard
        .get("uid")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        problems.push("no uid".to_owned());
    }
    let mut uids = Vec::new();
    datasource_uids(dashboard, &mut uids);
    if uids.is_empty() {
        problems.push("no datasource".to_owned());
    }
    for uid in uids {
        if uid != DATASOURCE_UID {
            problems.push(format!("datasource uid {uid}, expected {DATASOURCE_UID}"));
        }
    }
    problems
}

#[test]
fn test_dashboards_are_playlist_dashboards_with_descriptions() {
    let dir = Path::new(DASHBOARDS_DIR);
    let files = dashboard_files(dir);
    assert!(!files.is_empty(), "no dashboards in {}", dir.display());

    let mut failing = Vec::new();
    let mut uids = std::collections::HashSet::new();
    for file in &files {
        let name = file.strip_prefix(dir).unwrap().display().to_string();
        let content = fs::read_to_string(file).unwrap_or_else(|e| panic!("reading {name}: {e}"));
        let dashboard: Value =
            common::serde_json::from_str(&content).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut problems = problems(&dashboard);
        if let Some(uid) = dashboard.get("uid").and_then(Value::as_str)
            && !uids.insert(uid.to_owned())
        {
            problems.push(format!("uid {uid} is used twice"));
        }
        let title = dashboard
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("<no title>");
        println!("{name}: {title}");
        println!(
            "    {}",
            description(&dashboard).unwrap_or("<NO DESCRIPTION>")
        );
        for problem in &problems {
            println!("    PROBLEM: {problem}");
        }
        println!();
        if !problems.is_empty() {
            failing.push(name);
        }
    }
    println!(
        "{} dashboards, {} with problems",
        files.len(),
        failing.len()
    );
    assert!(
        failing.is_empty(),
        "dashboards with problems (see tools/metrics/README.md): {failing:#?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::serde_json::json;

    fn good() -> Value {
        json!({
            "uid": "p2p-x",
            "timezone": "utc",
            "tags": ["pings", PLAYLIST_TAG],
            "links": [{ "type": "link", "icon": "doc", "url": "#", "title": "  A description.  " }],
            "panels": [{ "datasource": { "type": "prometheus", "uid": DATASOURCE_UID },
                         "targets": [{ "datasource": { "type": "prometheus", "uid": DATASOURCE_UID } }] }],
            "annotations": { "list": [{ "datasource": { "type": "grafana", "uid": "-- Grafana --" } }] }
        })
    }

    #[test]
    fn test_description_is_the_doc_link() {
        assert_eq!(description(&good()), Some("A description."));
        let other_links = json!({ "links": [
            { "type": "dashboards", "icon": "external link", "url": "", "title": "other" },
            { "type": "link", "icon": "doc", "url": "#", "title": " " },
        ] });
        assert_eq!(description(&other_links), None);
        assert_eq!(description(&json!({})), None);
    }

    #[test]
    fn test_a_good_dashboard_has_no_problems() {
        assert!(problems(&good()).is_empty());
    }

    #[test]
    fn test_each_rule() {
        let mut d = good();
        d["panels"].as_array_mut().unwrap().push(json!({}));
        assert!(problems(&d).iter().any(|p| p.contains("2 panels")));

        let mut d = good();
        d["tags"] = json!(["pings"]);
        assert!(problems(&d).iter().any(|p| p.contains("tag")));

        let mut d = good();
        d["timezone"] = json!("browser");
        assert!(problems(&d).iter().any(|p| p.contains("utc")));

        let mut d = good();
        d["panels"][0]["targets"][0]["datasource"]["uid"] = json!("P1809F7CD0C75ACF3");
        assert!(problems(&d).iter().any(|p| p.contains("P1809F7CD0C75ACF3")));

        let mut d = good();
        d["links"] = json!([]);
        assert!(problems(&d).iter().any(|p| p.contains("description")));

        let mut d = good();
        d["uid"] = json!("");
        assert!(problems(&d).iter().any(|p| p.contains("uid")));
    }
}
