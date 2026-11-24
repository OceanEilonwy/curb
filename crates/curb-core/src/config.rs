use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::presets::SteamPresetConfig;
use crate::verify::BinaryIdentity;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Common web browsers and command shells that are never allowed to silently
/// inherit network access via a parent app's sub-process rule.
pub const RESTRICTED_SUBPROCESS_NAMES: &[&str] = &[
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "arc.exe",
    "iexplore.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wt.exe",
    "curl.exe",
    "wget.exe",
    "winget.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "python.exe",
    "pythonw.exe",
    "node.exe",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnforcementMode {
    Enforcing,
    PausedUntil { until: DateTime<Utc> },
    Disabled,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        Self::Enforcing
    }
}

impl EnforcementMode {
    /// Returns true if traffic should currently be filtered (accounts for expired pauses).
    pub fn is_actively_enforcing(&self, now: DateTime<Utc>) -> bool {
        match self {
            Self::Enforcing => true,
            Self::PausedUntil { until } => now >= *until,
            Self::Disabled => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselinePolicy {
    /// Allow DHCP leases on Wi-Fi / Ethernet adapters.
    pub dhcp: bool,
    /// Allow localhost loopback (127.0.0.1 / ::1) required for local app IPC.
    pub loopback: bool,
    /// Allow NTP time sync (UDP 123) so HTTPS/TLS certificate checks stay valid.
    pub ntp: bool,
    /// Allow Windows NCSI connectivity probes to avoid false "No Internet" flags.
    pub ncsi: bool,
}

impl Default for BaselinePolicy {
    fn default() -> Self {
        Self {
            dhcp: true,
            loopback: true,
            ntp: true,
            ncsi: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerificationMethod {
    Signature {
        subject_cn: String,
        #[serde(default)]
        issuer_cn: Option<String>,
        #[serde(default)]
        product_name: Option<String>,
        #[serde(default)]
        original_filename: Option<String>,
    },
    Hash {
        sha256: String,
        filename_hint: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecutableMatcher {
    SteamGame {
        app_id: u32,
        install_dir: String,
        verification: VerificationMethod,
    },
    Signature {
        subject_cn: String,
        #[serde(default)]
        issuer_cn: Option<String>,
        #[serde(default)]
        product_name: Option<String>,
        #[serde(default)]
        original_filename: Option<String>,
    },
    Hash {
        sha256: String,
        filename_hint: String,
    },
}

impl ExecutableMatcher {
    pub fn is_signed(&self) -> bool {
        matches!(
            self,
            Self::Signature { .. }
                | Self::SteamGame {
                    verification: VerificationMethod::Signature { .. },
                    ..
                }
        )
    }

    /// Evaluates whether a verified binary matches this rule.
    pub fn matches(&self, binary: &BinaryIdentity) -> bool {
        match self {
            Self::SteamGame { verification, .. } => match_verification(verification, binary),
            Self::Signature {
                subject_cn,
                issuer_cn,
                product_name,
                original_filename,
            } => match_signature(
                subject_cn,
                issuer_cn.as_deref(),
                product_name.as_deref(),
                original_filename.as_deref(),
                binary,
            ),
            Self::Hash { sha256, .. } => binary.sha256.eq_ignore_ascii_case(sha256),
        }
    }
}

fn match_verification(method: &VerificationMethod, binary: &BinaryIdentity) -> bool {
    match method {
        VerificationMethod::Signature {
            subject_cn,
            issuer_cn,
            product_name,
            original_filename,
        } => match_signature(
            subject_cn,
            issuer_cn.as_deref(),
            product_name.as_deref(),
            original_filename.as_deref(),
            binary,
        ),
        VerificationMethod::Hash { sha256, .. } => binary.sha256.eq_ignore_ascii_case(sha256),
    }
}

fn match_signature(
    subject_cn: &str,
    issuer_cn: Option<&str>,
    product_name: Option<&str>,
    original_filename: Option<&str>,
    binary: &BinaryIdentity,
) -> bool {
    let Some(sig) = &binary.signature else {
        return false;
    };
    if !sig.trusted {
        return false;
    }
    if !sig.subject_cn.eq_ignore_ascii_case(subject_cn) {
        return false;
    }
    if let Some(expected_issuer) = issuer_cn {
        if !sig.issuer_cn.eq_ignore_ascii_case(expected_issuer) {
            return false;
        }
    }
    if let Some(expected_product) = product_name {
        match &binary.product_name {
            Some(actual) if actual.eq_ignore_ascii_case(expected_product) => {}
            Some(_) => return false,
            None => {
                // When PE version metadata is unavailable, compare against the executable
                // filename stem (e.g. "Signal" for "Signal.exe") so existing rules saved
                // with a display-name fallback still match without over-allowing unrelated
                // binaries from the same signer.
                let stem = binary
                    .filename
                    .strip_suffix(".exe")
                    .or_else(|| binary.filename.strip_suffix(".EXE"))
                    .unwrap_or(&binary.filename);
                if !stem.eq_ignore_ascii_case(expected_product) {
                    return false;
                }
            }
        }
    }
    if let Some(expected_file) = original_filename {
        let actual = binary
            .original_filename
            .as_deref()
            .unwrap_or(&binary.filename);
        if !actual.eq_ignore_ascii_case(expected_file) {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub allow_tcp: bool,
    pub allow_udp: bool,
    /// `None` means any destination IP is permitted for this app.
    /// `Some(domains)` restricts outbound traffic exclusively to IPs resolved
    /// via Curb's local DNS proxy for matching domain patterns.
    #[serde(default)]
    pub dns_whitelist: Option<Vec<String>>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allow_tcp: true,
            allow_udp: true,
            dns_whitelist: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubprocessPolicy {
    Disabled,
    /// Allow child processes sharing the same trusted signer or install directory,
    /// while always excluding browsers and command shells.
    #[default]
    SameSignerOrDir,
    /// Allow any child process except browsers and command shells.
    AnyExceptRestricted,
}

impl SubprocessPolicy {
    pub fn allows_child(&self, parent: &BinaryIdentity, child: &BinaryIdentity) -> bool {
        if !parent.filename.eq_ignore_ascii_case(&child.filename)
            && is_restricted_subprocess(&child.filename)
        {
            return false;
        }
        match self {
            Self::Disabled => false,
            Self::AnyExceptRestricted => true,
            Self::SameSignerOrDir => {
                let same_signer = match (&parent.signature, &child.signature) {
                    (Some(ps), Some(cs)) if ps.trusted && cs.trusted => {
                        ps.subject_cn.eq_ignore_ascii_case(&cs.subject_cn)
                    }
                    _ => false,
                };
                if same_signer {
                    return true;
                }
                let parent_dir = parent_directory(&parent.path);
                let child_dir = parent_directory(&child.path);
                match (parent_dir, child_dir) {
                    (Some(p), Some(c)) => c.to_ascii_lowercase().starts_with(&p.to_ascii_lowercase()),
                    _ => false,
                }
            }
        }
    }
}

pub fn is_restricted_subprocess(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    RESTRICTED_SUBPROCESS_NAMES.iter().any(|r| *r == lower)
}

fn parent_directory(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let (dir, _) = normalized.rsplit_once('/')?;
    if dir.is_empty() {
        None
    } else {
        Some(format!("{dir}/"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub matcher: ExecutableMatcher,
    pub network: NetworkPolicy,
    pub subprocesses: SubprocessPolicy,
    pub exe_hint: String,
    /// Full executable path captured when the rule was created, enabling proactive
    /// 0ms WFP filter installation even before the application launches.
    #[serde(default)]
    pub exe_path: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresetsConfig {
    pub steam: SteamPresetConfig,
}

impl Default for PresetsConfig {
    fn default() -> Self {
        Self {
            steam: SteamPresetConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub schema_version: u32,
    pub mode: EnforcementMode,
    pub baseline: BaselinePolicy,
    pub presets: PresetsConfig,
    pub rules: Vec<Rule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            mode: EnforcementMode::Enforcing,
            baseline: BaselinePolicy::default(),
            presets: PresetsConfig::default(),
            rules: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::SignatureInfo;

    fn sample_signed(name: &str, signer: &str, product: &str, path: &str) -> BinaryIdentity {
        BinaryIdentity {
            path: path.to_string(),
            filename: name.to_string(),
            sha256: "abc123".to_string(),
            signature: Some(SignatureInfo {
                trusted: true,
                subject_cn: signer.to_string(),
                issuer_cn: "DigiCert Trusted G4".to_string(),
            }),
            product_name: Some(product.to_string()),
            original_filename: Some(name.to_string()),
            file_description: Some(product.to_string()),
        }
    }

    #[test]
    fn signature_rule_requires_trusted_chain_and_product_match() {
        let matcher = ExecutableMatcher::Signature {
            subject_cn: "Microsoft Corporation".into(),
            issuer_cn: None,
            product_name: Some("Minecraft".into()),
            original_filename: None,
        };

        let minecraft = sample_signed(
            "Minecraft.exe",
            "Microsoft Corporation",
            "Minecraft",
            r"C:\Games\Minecraft\Minecraft.exe",
        );
        let edge = sample_signed(
            "msedge.exe",
            "Microsoft Corporation",
            "Microsoft Edge",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        );

        assert!(matcher.matches(&minecraft));
        assert!(!matcher.matches(&edge));
    }

    #[test]
    fn signature_rule_matches_signed_app_without_pe_product_metadata() {
        let signal = BinaryIdentity {
            path: r"C:\Users\alice\AppData\Local\Programs\signal-desktop\Signal.exe".into(),
            filename: "Signal.exe".into(),
            sha256: "abc123".into(),
            signature: Some(SignatureInfo {
                trusted: true,
                subject_cn: "Signal Messenger, LLC".into(),
                issuer_cn: "DigiCert Trusted G4".into(),
            }),
            product_name: None,
            original_filename: None,
            file_description: None,
        };
        let unrelated_same_signer = BinaryIdentity {
            path: r"C:\Users\alice\AppData\Local\Programs\signal-desktop\Updater.exe".into(),
            filename: "Updater.exe".into(),
            sha256: "def456".into(),
            signature: signal.signature.clone(),
            product_name: None,
            original_filename: None,
            file_description: None,
        };

        // New-style rule (no product_name, matches by trusted signer + filename)
        let new_rule = ExecutableMatcher::Signature {
            subject_cn: "Signal Messenger, LLC".into(),
            issuer_cn: None,
            product_name: None,
            original_filename: Some("Signal.exe".into()),
        };
        assert!(new_rule.matches(&signal));
        assert!(!new_rule.matches(&unrelated_same_signer));

        // Legacy v0.2.2 rule that stored display-name fallback ("Signal") in product_name
        let legacy_rule = ExecutableMatcher::Signature {
            subject_cn: "Signal Messenger, LLC".into(),
            issuer_cn: None,
            product_name: Some("Signal".into()),
            original_filename: Some("Signal.exe".into()),
        };
        assert!(legacy_rule.matches(&signal));
        assert!(!legacy_rule.matches(&unrelated_same_signer));
    }

    #[test]
    fn subprocess_policy_blocks_browsers_and_shells() {
        let game = sample_signed(
            "game.exe",
            "Ghost Ship Games",
            "DRG",
            r"D:\SteamLibrary\common\DRG\game.exe",
        );
        let helper = sample_signed(
            "helper.exe",
            "Ghost Ship Games",
            "DRG Helper",
            r"D:\SteamLibrary\common\DRG\bin\helper.exe",
        );
        let edge = sample_signed(
            "msedge.exe",
            "Microsoft Corporation",
            "Microsoft Edge",
            r"C:\Program Files\Edge\msedge.exe",
        );

        assert!(SubprocessPolicy::SameSignerOrDir.allows_child(&game, &helper));
        assert!(!SubprocessPolicy::SameSignerOrDir.allows_child(&game, &edge));
        assert!(!SubprocessPolicy::AnyExceptRestricted.allows_child(&game, &edge));
    }

    #[test]
    fn paused_mode_re_enforces_after_expiry() {
        let now = Utc::now();
        let future = EnforcementMode::PausedUntil {
            until: now + chrono::Duration::minutes(15),
        };
        let past = EnforcementMode::PausedUntil {
            until: now - chrono::Duration::seconds(1),
        };
        assert!(!future.is_actively_enforcing(now));
        assert!(past.is_actively_enforcing(now));
    }
}
