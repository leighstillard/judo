//! Danger policy: normalization, built-in categories, layering, strictest-wins,
//! compiled-in hardline floor. Spec §5.
//!
//! ponytail: the built-in taxonomy here is a representative seed, not the full
//! ~72-pattern Hermes corpus — enough to prove classification. Grow the CATEGORIES
//! table as the real corpus is ported.

use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Allow,
    Notify,
    Approve,
    Deny,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "allow" => Level::Allow,
            "notify" => Level::Notify,
            "approve" => Level::Approve,
            "deny" => Level::Deny,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Allow => "allow",
            Level::Notify => "notify",
            Level::Approve => "approve",
            Level::Deny => "deny",
        }
    }
}

/// A hit: which category matched and the level it resolved to after layering.
#[derive(Debug, Clone)]
pub struct Hit {
    pub category: String,
    pub level: Level,
    pub source: String,
    pub ttl_max_mins: Option<u64>,
}

pub struct Decision {
    pub normalized: String,
    pub hits: Vec<Hit>,
    pub hardline: Option<String>,
}

impl Decision {
    /// Strictest-wins across all hits (spec §5.3). Hardline forces Deny.
    pub fn effective(&self) -> Level {
        if self.hardline.is_some() {
            return Level::Deny;
        }
        self.hits.iter().map(|h| h.level).max().unwrap_or(Level::Approve)
    }
    /// The single TTL offer (category, mins) — only when the effective level is
    /// exactly Approve and precisely one matched category permits a TTL grant.
    pub fn ttl_offer(&self) -> Option<(String, u64)> {
        if self.effective() != Level::Approve {
            return None;
        }
        let mut offers = self
            .hits
            .iter()
            .filter(|h| h.level == Level::Approve)
            .filter_map(|h| h.ttl_max_mins.map(|m| (h.category.clone(), m)));
        let first = offers.next()?;
        // ponytail: if two approve-categories both allow TTL, don't offer — ambiguous
        // which category a TTL grant would cover. Once-only is the safe default.
        if offers.next().is_some() {
            None
        } else {
            Some(first)
        }
    }
    pub fn categories(&self) -> Vec<String> {
        self.hits.iter().map(|h| h.category.clone()).collect()
    }
}

struct BuiltinCat {
    id: &'static str,
    default: Level,
    /// Anchored at command position by `compile`.
    pattern: &'static str,
    ttl_default_mins: Option<u64>,
}

// Command-position anchor (spec §5.3): start, or after a shell separator, optionally
// through sudo/env/nohup wrappers.
const CMDPOS: &str = r"(?:^|[;&|]|&&|\|\||\$\(|`)\s*(?:sudo\s+|env\s+|nohup\s+)*";

fn builtins() -> &'static [BuiltinCat] {
    &[
        BuiltinCat { id: "hardline.rm-rf-root", default: Level::Deny, pattern: r"rm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*f?[a-zA-Z]*\s+(?:--\s+)?/(?:\s|$)", ttl_default_mins: None },
        BuiltinCat { id: "fs.recursive-delete", default: Level::Approve, pattern: r"rm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR]", ttl_default_mins: Some(15) },
        BuiltinCat { id: "sudo.exec", default: Level::Approve, pattern: r"", ttl_default_mins: Some(15) }, // matched specially below
        BuiltinCat { id: "svc.restart", default: Level::Approve, pattern: r"systemctl\s+(?:restart|stop|start|disable)", ttl_default_mins: Some(30) },
        BuiltinCat { id: "pkg.install", default: Level::Approve, pattern: r"(?:apt|apt-get|dpkg|yum|dnf|snap)\s+(?:install|remove|purge)", ttl_default_mins: Some(30) },
        BuiltinCat { id: "db.drop", default: Level::Approve, pattern: r"(?i)\b(?:drop\s+table|drop\s+database|truncate\s+table|delete\s+from)\b", ttl_default_mins: None },
        BuiltinCat { id: "net.pipe-to-shell", default: Level::Approve, pattern: r"(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh", ttl_default_mins: None },
        BuiltinCat { id: "policy.write", default: Level::Approve, pattern: r"", ttl_default_mins: None }, // path-based, checked by caller
    ]
}

const HARDLINE: &[(&str, &str)] = &[
    ("hardline.rm-rf-root", r"rm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*f?[a-zA-Z]*\s+(?:--\s+)?/(?:\s|$)"),
    ("hardline.mkfs", r"\bmkfs(?:\.\w+)?\s"),
    ("hardline.dd-to-disk", r"\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|vd|hd)"),
    ("hardline.forkbomb", r":\(\)\s*\{\s*:\s*\|\s*:"),
    ("hardline.shutdown", r"\b(?:shutdown|reboot|poweroff|halt|init\s+0)\b"),
];

/// Normalization pipeline (spec §5.3), ported from Hermes.
pub fn normalize(raw: &str) -> String {
    // strip ANSI CSI + null bytes
    let ansi = Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]").unwrap();
    let s = ansi.replace_all(raw, "");
    let s: String = s.chars().filter(|&c| c != '\0').collect();
    // NFKC (fullwidth → ascii)
    let s: String = s.nfkc().collect();
    // backslash-escape fold: `r\m` → `rm` (drop backslashes not before a space)
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&n) = chars.peek() {
                if !n.is_whitespace() {
                    continue; // drop the backslash, keep next char
                }
            }
        }
        out.push(c);
    }
    // empty-string-literal fold: r''m / r""m → rm
    let empty = Regex::new(r#"(?:''|"")"#).unwrap();
    let out = empty.replace_all(&out, "").into_owned();
    // collapse runs of whitespace
    let ws = Regex::new(r"\s+").unwrap();
    ws.replace_all(out.trim(), " ").into_owned()
}

/// Detect the sudo wrapper at command position (the `sudo.exec` category).
fn hits_sudo(norm: &str) -> bool {
    Regex::new(&format!(r"{CMDPOS}sudo\s")).unwrap().is_match(&format!(" {norm}"))
        || norm.starts_with("sudo ")
}

// ---- workspace / global policy files (spec §5.4/§5.5)

#[derive(Debug, Default, Deserialize)]
pub struct PolicyFile {
    pub default: Option<String>,
    pub timeout: Option<String>,
    pub deny_cooldown: Option<String>,
    #[serde(default)]
    pub categories: BTreeMap<String, CatEntry>,
    #[serde(default)]
    pub agents: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub harness: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct CatEntry {
    pub level: Option<String>,
    pub ttl_max: Option<String>,
    #[serde(default)]
    pub floor: bool,
    #[serde(default)]
    pub r#match: Vec<String>,
}

pub struct Engine {
    global: PolicyFile,
    workspace: PolicyFile,
    custom: Vec<(String, Regex, Level, Option<u64>)>,
}

impl Engine {
    pub fn new(global: PolicyFile, workspace: PolicyFile) -> Self {
        // Compile custom-category match rules from both files.
        let mut custom = Vec::new();
        for (file, _which) in [(&global, "global"), (&workspace, "workspace")] {
            for (id, entry) in &file.categories {
                let lvl = entry.level.as_deref().and_then(Level::parse).unwrap_or(Level::Approve);
                let ttl = parse_mins(entry.ttl_max.as_deref());
                for pat in &entry.r#match {
                    if let Ok(re) = Regex::new(pat) {
                        custom.push((id.clone(), re, lvl, ttl));
                    }
                }
            }
        }
        Engine { global, workspace, custom }
    }

    fn default_level(&self) -> Level {
        self.workspace
            .default
            .as_deref()
            .or(self.global.default.as_deref())
            .and_then(Level::parse)
            .unwrap_or(Level::Approve) // spec §5.7 shipped default
    }

    pub fn timeout_secs(&self) -> u64 {
        parse_secs(self.workspace.timeout.as_deref()).unwrap_or(90)
    }
    pub fn cooldown_secs(&self) -> u64 {
        parse_secs(self.workspace.deny_cooldown.as_deref()).unwrap_or(600)
    }

    /// Resolve a category id to its effective level + ttl through the layer stack
    /// (spec §5.4). `agent_user`/`harness` overrides; floors clamp; harness tightens only.
    fn resolve(&self, cat: &str, base: Level, base_ttl: Option<u64>, agent_user: &str, harness: Option<&str>) -> (Level, String, Option<u64>) {
        let mut level = base;
        let mut source = "builtin-default".to_string();
        let mut ttl = base_ttl;

        // global then workspace category level
        for (file, name) in [(&self.global, "global"), (&self.workspace, "workspace")] {
            if let Some(e) = file.categories.get(cat) {
                if let Some(l) = e.level.as_deref().and_then(Level::parse) {
                    level = l;
                    source = name.to_string();
                }
                if let Some(m) = parse_mins(e.ttl_max.as_deref()) {
                    ttl = Some(m);
                }
            }
        }
        // agent override (loosen or tighten)
        if let Some(tbl) = self.workspace.agents.get(agent_user) {
            if let Some(l) = tbl.get(cat).and_then(|s| Level::parse(s)) {
                level = l;
                source = format!("agents.{agent_user}");
            }
        }
        // harness override (tighten only)
        if let (Some(h), Some(tbl)) = (harness, harness.and_then(|h| self.workspace.harness.get(h))) {
            if let Some(l) = tbl.get(cat).and_then(|s| Level::parse(s)) {
                if l > level {
                    level = l;
                    source = format!("harness.{h}");
                }
            }
        }
        // floor clamp: a global floor=true category can't drop below its global level.
        if let Some(e) = self.global.categories.get(cat) {
            if e.floor {
                if let Some(fl) = e.level.as_deref().and_then(Level::parse) {
                    if level < fl {
                        level = fl;
                        source = format!("{source} (floor-clamped)");
                    }
                }
            }
        }
        (level, source, if level == Level::Approve { ttl } else { None })
    }

    /// Classify a raw command. `policy_write` = the argv targets a protected policy file.
    pub fn classify(&self, raw: &str, agent_user: &str, harness: Option<&str>, policy_write: bool) -> Decision {
        let norm = normalize(raw);

        // hardline first — compiled in, unconditionally Deny (spec §5.1)
        for (id, pat) in HARDLINE {
            if Regex::new(pat).unwrap().is_match(&norm) {
                return Decision { normalized: norm, hits: vec![], hardline: Some(id.to_string()) };
            }
        }

        let mut hits: Vec<Hit> = Vec::new();
        let push = |cat: &str, def: Level, ttl_def: Option<u64>, hits: &mut Vec<Hit>| {
            let (level, source, ttl) = self.resolve(cat, def, ttl_def, agent_user, harness);
            hits.push(Hit { category: cat.to_string(), level, source, ttl_max_mins: ttl });
        };

        for b in builtins() {
            if b.id.starts_with("hardline.") {
                continue;
            }
            let matched = match b.id {
                "sudo.exec" => hits_sudo(&norm),
                "policy.write" => policy_write,
                _ => Regex::new(b.pattern).unwrap().is_match(&norm),
            };
            if matched {
                push(b.id, b.default, b.ttl_default_mins, &mut hits);
            }
        }
        for (id, re, lvl, ttl) in &self.custom {
            if re.is_match(&norm) && !hits.iter().any(|h| &h.category == id) {
                push(id, *lvl, *ttl, &mut hits);
            }
        }

        if hits.is_empty() {
            // unmatched ⇒ tunable default (spec §5.7)
            hits.push(Hit {
                category: "(unmatched)".to_string(),
                level: self.default_level(),
                source: "default".to_string(),
                ttl_max_mins: None,
            });
        }
        Decision { normalized: norm, hits, hardline: None }
    }
}

fn parse_mins(s: Option<&str>) -> Option<u64> {
    let s = s?.trim();
    if let Some(n) = s.strip_suffix('m') {
        n.trim().parse().ok()
    } else if let Some(n) = s.strip_suffix('h') {
        n.trim().parse::<u64>().ok().map(|h| h * 60)
    } else {
        s.parse().ok()
    }
}

fn parse_secs(s: Option<&str>) -> Option<u64> {
    let s = s?.trim();
    if let Some(n) = s.strip_suffix('s') {
        n.trim().parse().ok()
    } else if let Some(n) = s.strip_suffix('m') {
        n.trim().parse::<u64>().ok().map(|m| m * 60)
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::new(PolicyFile::default(), PolicyFile::default())
    }

    #[test]
    fn hardline_beats_everything() {
        let d = engine().classify("sudo rm -rf /", "bot", None, false);
        assert!(d.hardline.is_some());
        assert_eq!(d.effective(), Level::Deny);
    }

    #[test]
    fn normalization_defeats_obfuscation() {
        // backslash-escape + fullwidth digits should still land on recursive-delete
        assert_eq!(normalize(r"r\m -rf ./x"), "rm -rf ./x");
        let d = engine().classify(r"r\m -rf ./build", "bot", None, false);
        assert!(d.categories().iter().any(|c| c == "fs.recursive-delete"));
    }

    #[test]
    fn strictest_wins_across_matches() {
        // sudo systemctl restart: sudo.exec (approve) + svc.restart (approve) → approve
        let d = engine().classify("sudo systemctl restart nginx", "bot", None, false);
        assert_eq!(d.effective(), Level::Approve);
        assert!(d.categories().contains(&"sudo.exec".to_string()));
        assert!(d.categories().contains(&"svc.restart".to_string()));
    }

    #[test]
    fn unmatched_defaults_to_approve() {
        let d = engine().classify("echo hello", "bot", None, false);
        assert_eq!(d.effective(), Level::Approve);
        assert_eq!(d.hits[0].category, "(unmatched)");
    }

    #[test]
    fn workspace_can_loosen_via_agent_override() {
        let ws: PolicyFile = toml::from_str(
            r#"
            [agents.deploy-bot]
            "pkg.install" = "allow"
            "#,
        )
        .unwrap();
        let e = Engine::new(PolicyFile::default(), ws);
        let d = e.classify("apt-get install jq", "deploy-bot", None, false);
        assert_eq!(d.effective(), Level::Allow);
        // a different agent still gets the default approve
        let d2 = e.classify("apt-get install jq", "other-bot", None, false);
        assert_eq!(d2.effective(), Level::Approve);
    }

    #[test]
    fn harness_tightens_only_never_loosens() {
        let ws: PolicyFile = toml::from_str(
            r#"
            [harness.claude-code]
            "pkg.install" = "allow"
            "#,
        )
        .unwrap();
        let e = Engine::new(PolicyFile::default(), ws);
        // harness says allow but builtin default is approve — tighten-only ignores the loosening
        let d = e.classify("apt-get install jq", "bot", Some("claude-code"), false);
        assert_eq!(d.effective(), Level::Approve);
    }

    #[test]
    fn global_floor_clamps_loosening() {
        let global: PolicyFile = toml::from_str(
            r#"
            [categories."pkg.install"]
            level = "approve"
            floor = true
            "#,
        )
        .unwrap();
        let ws: PolicyFile = toml::from_str(
            r#"
            [agents.bot]
            "pkg.install" = "allow"
            "#,
        )
        .unwrap();
        let e = Engine::new(global, ws);
        let d = e.classify("apt-get install jq", "bot", None, false);
        assert_eq!(d.effective(), Level::Approve, "floor must clamp the agent loosening");
    }

    #[test]
    fn ttl_offer_only_when_single_approve_category() {
        let d = engine().classify("apt-get install jq", "bot", None, false);
        assert_eq!(d.ttl_offer(), Some(("pkg.install".to_string(), 30)));
    }
}
