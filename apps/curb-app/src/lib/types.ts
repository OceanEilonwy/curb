export type EnforcementMode =
  | { kind: "enforcing" }
  | { kind: "paused_until"; until: string }
  | { kind: "disabled" };

export interface BaselinePolicy {
  dhcp: boolean;
  loopback: boolean;
  ntp: boolean;
  ncsi: boolean;
}

export interface SteamPresetConfig {
  enabled: boolean;
  store_and_library: boolean;
  community_and_workshop: boolean;
  friends_and_voice: boolean;
}

export type VerificationMethod =
  | {
      type: "signature";
      subject_cn: string;
      issuer_cn?: string | null;
      product_name?: string | null;
      original_filename?: string | null;
    }
  | {
      type: "hash";
      sha256: string;
      filename_hint: string;
    };

export type ExecutableMatcher =
  | {
      kind: "steam_game";
      app_id: number;
      install_dir: string;
      verification: VerificationMethod;
    }
  | {
      kind: "signature";
      subject_cn: string;
      issuer_cn?: string | null;
      product_name?: string | null;
      original_filename?: string | null;
    }
  | {
      kind: "hash";
      sha256: string;
      filename_hint: string;
    };

export interface NetworkPolicy {
  allow_tcp: boolean;
  allow_udp: boolean;
  dns_whitelist: string[] | null;
}

export type SubprocessPolicy =
  | "disabled"
  | "same_signer_or_dir"
  | "any_except_restricted";

export interface Rule {
  id: string;
  name: string;
  enabled: boolean;
  matcher: ExecutableMatcher;
  network: NetworkPolicy;
  subprocesses: SubprocessPolicy;
  exe_hint: string;
  created_at: string;
}

export interface Config {
  schema_version: number;
  mode: EnforcementMode;
  baseline: BaselinePolicy;
  presets: {
    steam: SteamPresetConfig;
  };
  rules: Rule[];
}

export interface RunningAppInfo {
  key: string;
  name: string;
  exe: string;
  path: string;
  process_count: number;
  background: boolean;
  tried_connect: boolean;
  tried_host: string | null;
  signed: boolean;
  signer: string | null;
  sha256: string;
}

export interface DiscoveredSteamGame {
  app_id: number;
  name: string;
  install_dir: string;
  exe_path: string;
  exe_name: string;
  signed: boolean;
  signer: string | null;
  sha256: string;
}

export interface BlockedEvent {
  id: string;
  timestamp: string;
  app_name: string;
  exe: string;
  path: string;
  destination: string;
  signed: boolean;
  signer: string | null;
  is_steam_community: boolean;
}

export type ProtectionTier = "unconfigured" | "full_service" | "standard_user";

export interface ServiceSnapshot {
  config: Config;
  password_configured: boolean;
  blocked_events: BlockedEvent[];
  active_wfp_filters: number;
  protection_tier: ProtectionTier;
}

export interface BinaryIdentity {
  path: string;
  filename: string;
  sha256: string;
  signature: {
    trusted: boolean;
    subject_cn: string;
    issuer_cn: string;
  } | null;
  product_name: string | null;
  original_filename: string | null;
  file_description: string | null;
}

export function isMatcherSigned(matcher: ExecutableMatcher): boolean {
  if (matcher.kind === "signature") return true;
  if (matcher.kind === "steam_game") {
    return matcher.verification.type === "signature";
  }
  return false;
}

export function matcherDetail(matcher: ExecutableMatcher): string {
  if (matcher.kind === "signature") {
    return `Signer: ${matcher.subject_cn}`;
  }
  if (matcher.kind === "hash") {
    return `SHA-256: ${matcher.sha256.slice(0, 12)}…`;
  }
  if (matcher.verification.type === "signature") {
    return `Signer: ${matcher.verification.subject_cn}`;
  }
  return `SHA-256: ${matcher.verification.sha256.slice(0, 12)}…`;
}
