import { invoke } from "@tauri-apps/api/core";
import type {
  BaselinePolicy,
  BinaryIdentity,
  DiscoveredSteamGame,
  EnforcementMode,
  Rule,
  RunningAppInfo,
  ServiceSnapshot,
  SteamPresetConfig,
} from "./types";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

// ---------- Interactive Mock Backend (used automatically in `pnpm dev` browser preview) ----------
let mockSnapshot: ServiceSnapshot = {
  password_configured: true,
  active_wfp_filters: 14,
  config: {
    schema_version: 1,
    mode: { kind: "enforcing" },
    baseline: { dhcp: true, loopback: true, ntp: true, ncsi: true },
    presets: {
      steam: {
        enabled: true,
        store_and_library: true,
        community_and_workshop: false,
        friends_and_voice: false,
      },
    },
    rules: [
      {
        id: "11111111-1111-4111-8111-111111111111",
        name: "Deep Rock Galactic",
        enabled: true,
        exe_hint: "FSD-Win64-Shipping.exe",
        created_at: new Date().toISOString(),
        matcher: {
          kind: "steam_game",
          app_id: 548430,
          install_dir: "Deep Rock Galactic",
          verification: {
            type: "signature",
            subject_cn: "Ghost Ship Games ApS",
          },
        },
        network: { allow_tcp: true, allow_udp: true, dns_whitelist: null },
        subprocesses: "same_signer_or_dir",
      },
      {
        id: "22222222-2222-4222-8222-222222222222",
        name: "Balatro",
        enabled: true,
        exe_hint: "Balatro.exe",
        created_at: new Date().toISOString(),
        matcher: {
          kind: "steam_game",
          app_id: 2379780,
          install_dir: "Balatro",
          verification: {
            type: "hash",
            sha256: "9f4a82d17c1090ab44e1c21e00a19f02",
            filename_hint: "Balatro.exe",
          },
        },
        network: { allow_tcp: true, allow_udp: false, dns_whitelist: null },
        subprocesses: "disabled",
      },
    ],
  },
  blocked_events: [
    {
      id: "blk-1",
      timestamp: new Date().toISOString(),
      app_name: "Microsoft Edge",
      exe: "msedge.exe",
      path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      destination: "youtube.com",
      signed: true,
      signer: "Microsoft Corporation",
      is_steam_community: false,
    },
    {
      id: "blk-2",
      timestamp: new Date(Date.now() - 60_000).toISOString(),
      app_name: "Steam Community",
      exe: "steamwebhelper.exe",
      path: "C:\\Program Files (x86)\\Steam\\bin\\cef\\steamwebhelper.exe",
      destination: "steamcommunity.com",
      signed: true,
      signer: "Valve Corp.",
      is_steam_community: true,
    },
    {
      id: "blk-3",
      timestamp: new Date(Date.now() - 240_000).toISOString(),
      app_name: "Discord",
      exe: "Discord.exe",
      path: "C:\\Users\\Alex\\AppData\\Local\\Discord\\app-1.0.9162\\Discord.exe",
      destination: "discord.gg",
      signed: true,
      signer: "Discord Inc.",
      is_steam_community: false,
    },
  ],
};

const mockRunningApps: RunningAppInfo[] = [
  {
    key: "run-obsidian",
    name: "Obsidian",
    exe: "Obsidian.exe",
    path: "C:\\Users\\Alex\\AppData\\Local\\Obsidian\\Obsidian.exe",
    process_count: 4,
    background: false,
    tried_connect: true,
    tried_host: "sync.obsidian.md",
    signed: true,
    signer: "Dynalist Inc.",
    sha256: "2b01aa9100ee8811",
  },
  {
    key: "run-discord",
    name: "Discord",
    exe: "Discord.exe",
    path: "C:\\Users\\Alex\\AppData\\Local\\Discord\\app-1.0.9162\\Discord.exe",
    process_count: 6,
    background: false,
    tried_connect: true,
    tried_host: "discord.gg",
    signed: true,
    signer: "Discord Inc.",
    sha256: "78cc12ab009911ff",
  },
  {
    key: "run-prism",
    name: "Prism Launcher",
    exe: "prismlauncher.exe",
    path: "C:\\Users\\Alex\\AppData\\Local\\Programs\\PrismLauncher\\prismlauncher.exe",
    process_count: 1,
    background: false,
    tried_connect: false,
    tried_host: null,
    signed: false,
    signer: null,
    sha256: "6c3a9f2d8e411c9a",
  },
  {
    key: "run-spotify",
    name: "Spotify",
    exe: "Spotify.exe",
    path: "C:\\Users\\Alex\\AppData\\Roaming\\Spotify\\Spotify.exe",
    process_count: 5,
    background: false,
    tried_connect: false,
    tried_host: null,
    signed: true,
    signer: "Spotify AB",
    sha256: "44ff01ab33229911",
  },
  {
    key: "run-onedrive",
    name: "Microsoft OneDrive",
    exe: "OneDrive.exe",
    path: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
    process_count: 2,
    background: true,
    tried_connect: true,
    tried_host: "onedrive.live.com",
    signed: true,
    signer: "Microsoft Corporation",
    sha256: "99aa1122bb334455",
  },
  {
    key: "run-tailscale",
    name: "Tailscale",
    exe: "tailscaled.exe",
    path: "C:\\Program Files\\Tailscale\\tailscaled.exe",
    process_count: 2,
    background: true,
    tried_connect: false,
    tried_host: null,
    signed: true,
    signer: "Tailscale Inc.",
    sha256: "554433221100aabb",
  },
];

const mockSteamGames: DiscoveredSteamGame[] = [
  {
    app_id: 1145350,
    name: "Hades II",
    install_dir: "D:\\SteamLibrary\\steamapps\\common\\Hades II",
    exe_path: "D:\\SteamLibrary\\steamapps\\common\\Hades II\\Hades2.exe",
    exe_name: "Hades2.exe",
    signed: true,
    signer: "Supergiant Games, LLC",
    sha256: "1029384756abcdef",
  },
  {
    app_id: 553850,
    name: "HELLDIVERS 2",
    install_dir: "D:\\SteamLibrary\\steamapps\\common\\Helldivers 2",
    exe_path: "D:\\SteamLibrary\\steamapps\\common\\Helldivers 2\\bin\\helldivers2.exe",
    exe_name: "helldivers2.exe",
    signed: true,
    signer: "Arrowhead Game Studios AB",
    sha256: "abcdef1234567890",
  },
  {
    app_id: 413150,
    name: "Stardew Valley",
    install_dir: "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Stardew Valley",
    exe_path: "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Stardew Valley\\Stardew Valley.exe",
    exe_name: "Stardew Valley.exe",
    signed: false,
    signer: null,
    sha256: "4b8291a033445566",
  },
];

let mockPassword: string | null = null;

function cloneSnapshot(): ServiceSnapshot {
  return JSON.parse(JSON.stringify(mockSnapshot));
}

// ---------- Unified API Bridge ----------
export const curbApi = {
  async getSnapshot(): Promise<ServiceSnapshot> {
    if (isTauriRuntime()) {
      return invoke<ServiceSnapshot>("get_snapshot");
    }
    return cloneSnapshot();
  },

  async listRunningApps(): Promise<RunningAppInfo[]> {
    if (isTauriRuntime()) {
      return invoke<RunningAppInfo[]>("list_running_apps");
    }
    return [...mockRunningApps];
  },

  async listSteamGames(): Promise<DiscoveredSteamGame[]> {
    if (isTauriRuntime()) {
      return invoke<DiscoveredSteamGame[]>("list_steam_games");
    }
    return [...mockSteamGames];
  },

  async inspectExecutable(path: string): Promise<BinaryIdentity> {
    if (isTauriRuntime()) {
      return invoke<BinaryIdentity>("inspect_executable", { path });
    }
    const filename = path.split(/[\\/]/).pop() || "app.exe";
    return {
      path,
      filename,
      sha256: "3f88c01b9d1244aa",
      signature: null,
      product_name: filename.replace(/\.exe$/i, ""),
      original_filename: filename,
      file_description: null,
    };
  },

  async unlock(password: string): Promise<string> {
    if (isTauriRuntime()) {
      return invoke<string>("unlock", { password });
    }
    if (password.trim().length < 1) {
      throw new Error("Please enter your Curb password.");
    }
    if (mockPassword !== null && password !== mockPassword) {
      throw new Error("Incorrect Curb password.");
    }
    if (mockPassword === null) {
      mockPassword = password;
    }
    return "mock-session-token";
  },

  async lock(token: string): Promise<void> {
    if (isTauriRuntime()) {
      await invoke("lock", { token });
    }
  },

  async setMode(token: string, mode: EnforcementMode): Promise<ServiceSnapshot> {
    if (isTauriRuntime()) {
      return invoke<ServiceSnapshot>("set_mode", { token, mode });
    }
    mockSnapshot.config.mode = mode;
    return cloneSnapshot();
  },

  async updateSteamPreset(
    token: string,
    steam: SteamPresetConfig
  ): Promise<ServiceSnapshot> {
    if (isTauriRuntime()) {
      return invoke<ServiceSnapshot>("update_steam_preset", { token, steam });
    }
    mockSnapshot.config.presets.steam = steam;
    return cloneSnapshot();
  },

  async updateBaseline(
    token: string,
    baseline: BaselinePolicy
  ): Promise<ServiceSnapshot> {
    if (isTauriRuntime()) {
      return invoke<ServiceSnapshot>("update_baseline", { token, baseline });
    }
    mockSnapshot.config.baseline = baseline;
    return cloneSnapshot();
  },

  async upsertRule(token: string, rule: Rule): Promise<ServiceSnapshot> {
    if (isTauriRuntime()) {
      return invoke<ServiceSnapshot>("upsert_rule", { token, rule });
    }
    const idx = mockSnapshot.config.rules.findIndex((r) => r.id === rule.id);
    if (idx >= 0) mockSnapshot.config.rules[idx] = rule;
    else mockSnapshot.config.rules.unshift(rule);
    mockSnapshot.blocked_events = mockSnapshot.blocked_events.filter(
      (b) => b.exe.toLowerCase() !== rule.exe_hint.toLowerCase()
    );
    return cloneSnapshot();
  },

  async deleteRule(token: string, id: string): Promise<ServiceSnapshot> {
    if (isTauriRuntime()) {
      return invoke<ServiceSnapshot>("delete_rule", { token, id });
    }
    mockSnapshot.config.rules = mockSnapshot.config.rules.filter(
      (r) => r.id !== id
    );
    return cloneSnapshot();
  },

  async changePassword(
    token: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    if (isTauriRuntime()) {
      await invoke("change_password", {
        token,
        currentPassword,
        newPassword,
      });
      return;
    }
    if (mockPassword !== null && currentPassword !== mockPassword) {
      throw new Error("Current password is incorrect.");
    }
    if (newPassword.length < 4) {
      throw new Error("Password must be at least 4 characters.");
    }
    mockPassword = newPassword;
  },

  async hideToTray(token: string | null): Promise<void> {
    if (isTauriRuntime()) {
      await invoke("hide_to_tray", { token });
    }
  },
};
