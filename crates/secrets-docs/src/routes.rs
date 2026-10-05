//! The `b10x-project-routes/v1` inventory of a built site: every page with its sorted rendered
//! element IDs, stamped with the commit the site was built from. The organization Website reads it
//! to redirect the former `/docs/secrets/` pages and to check links into this site.
//!
//! Docusaurus writes a page at `x.html` (`trailingSlash: false`), a directory index at
//! `x/index.html`, and a client redirect wherever a page moved or a trailing-slash form exists.
//! A redirect page is not a route: it carries no content of its own.
//!
//! Every route is listed in its `/x/` form, which the Website requires of an independent route
//! inventory. GitHub Pages answers `/x/` with docs-system's copy of the page at `x/index.html`,
//! which carries the same content and element IDs as `x.html`.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use serde_json::json;

/// Where the site is served, with both slashes.
pub const BASE: &str = "/secrets/";

/// Whether `html` is a client redirect rather than a page: a refresh, or the copy docs-system
/// writes at `x/index.html` that sends `/x/` on to `/x`.
fn is_redirect(html: &str) -> bool {
    html.contains("http-equiv=\"refresh\"")
        || html.contains("http-equiv=refresh")
        || html.contains("<!-- b10x-trailing-slash-copy -->")
}

/// Every value of an `id` attribute in `html`, quoted or not.
pub fn ids(html: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = html;
    while let Some(at) = rest.find(" id=") {
        rest = &rest[at + 4..];
        let value = match rest.as_bytes().first() {
            Some(quote @ (b'"' | b'\'')) => {
                let quote = char::from(*quote);
                rest[1..].split(quote).next().unwrap_or_default()
            }
            _ => rest
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()
                .unwrap_or_default(),
        };
        if !value.is_empty() {
            found.insert(value.to_owned());
        }
    }
    found
}

/// The route a built file answers, or `None` for a file that is no page.
fn route(relative: &str) -> Option<String> {
    if relative == "404.html" {
        return None;
    }
    if let Some(dir) = relative.strip_suffix("index.html") {
        return Some(format!("{BASE}{dir}"));
    }
    relative
        .strip_suffix(".html")
        .map(|page| format!("{BASE}{page}/"))
}

fn pages(site: &Path, dir: &Path, out: &mut BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            pages(site, &path, out)?;
            continue;
        }
        let relative = path
            .strip_prefix(site)?
            .to_str()
            .context("non-UTF-8 path in the built site")?
            .replace('\\', "/");
        let Some(route) = route(&relative) else {
            continue;
        };
        let html = fs::read_to_string(&path)?;
        if is_redirect(&html) {
            continue;
        }
        ensure!(
            out.insert(route.clone(), ids(&html)).is_none(),
            "two built files answer {route}"
        );
    }
    Ok(())
}

/// The inventory of the built site at `site`, as written to `.well-known/b10x-routes.json`.
pub fn inventory(site: &Path, commit: &str) -> Result<String> {
    let mut found = BTreeMap::new();
    pages(site, site, &mut found)?;
    ensure!(
        found.contains_key(BASE),
        "the built site has no landing page"
    );
    let routes: Vec<_> = found
        .into_iter()
        .map(|(path, anchors)| json!({"path": path, "anchors": anchors}))
        .collect();
    Ok(serde_json::to_string_pretty(&json!({
        "schema": "b10x-project-routes/v1",
        "repository": "secrets",
        "commit": commit,
        "baseUrl": BASE,
        "routes": routes,
    }))? + "\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_read_quoted_and_unquoted() {
        let html = r##"<h2 id="threat-model">x</h2><main id=main class=a><a href="#top">"##;
        assert_eq!(
            ids(html).into_iter().collect::<Vec<_>>(),
            ["main", "threat-model"]
        );
    }

    #[test]
    fn pages_become_routes_and_redirects_do_not() {
        let site = std::env::temp_dir().join(format!("secrets-docs-routes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&site);
        fs::create_dir_all(site.join("docs/operations")).unwrap();
        fs::create_dir_all(site.join("docs/status")).unwrap();
        fs::write(site.join("index.html"), r#"<main id="main">"#).unwrap();
        fs::write(
            site.join("docs/status.html"),
            r#"<h2 id="known-limitations">"#,
        )
        .unwrap();
        fs::write(
            site.join("docs/status/index.html"),
            r#"<head><!-- b10x-trailing-slash-copy --></head><h2 id="known-limitations">"#,
        )
        .unwrap();
        fs::write(site.join("404.html"), r#"<main id="lost">"#).unwrap();
        fs::write(site.join("docs.html"), r#"<h1 id="secrets">"#).unwrap();
        fs::write(site.join("docs/operations.html"), r#"<h2 id="probes">"#).unwrap();
        fs::write(
            site.join("docs/operations/index.html"),
            r#"<meta http-equiv="refresh" content="0; url=/secrets/docs/operations">"#,
        )
        .unwrap();
        let inventory: serde_json::Value =
            serde_json::from_str(&inventory(&site, &"a".repeat(40)).unwrap()).unwrap();
        fs::remove_dir_all(&site).unwrap();
        assert_eq!(inventory["schema"], "b10x-project-routes/v1");
        assert_eq!(inventory["baseUrl"], BASE);
        let paths: Vec<_> = inventory["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                "/secrets/",
                "/secrets/docs/",
                "/secrets/docs/operations/",
                "/secrets/docs/status/"
            ]
        );
        assert_eq!(inventory["routes"][2]["anchors"][0], "probes");
    }
}
