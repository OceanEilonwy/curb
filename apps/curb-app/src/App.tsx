import { createEffect, createSignal, Show } from "solid-js";
import { curbApi } from "./lib/api";
import type {
  BaselinePolicy,
  BlockedEvent,
  DiscoveredSteamGame,
  EnforcementMode,
  Rule,
  RunningAppInfo,
  ServiceSnapshot,
  SteamPresetConfig,
} from "./lib/types";
import { AllowAppSheet } from "./components/AllowAppSheet";
import { AllowedView } from "./components/AllowedView";
import { BlockedView } from "./components/BlockedView";
import { LockIcon, PlusIcon, ShieldIcon, UnlockIcon } from "./components/Icons";
import { SettingsView } from "./components/SettingsView";
import { UnlockModal } from "./components/UnlockModal";

export default function App() {
  const [theme, setTheme] = createSignal<"dark" | "light">("dark");
  const [screen, setScreen] = createSignal<"main" | "add">("main");
  const [tab, setTab] = createSignal<"allowed" | "blocked" | "settings">(
    "allowed"
  );
  const [token, setToken] = createSignal<string | null>(null);
  const [unlockOpen, setUnlockOpen] = createSignal(false);
  const [toast, setToast] = createSignal<string | null>(null);

  const [snapshot, setSnapshot] = createSignal<ServiceSnapshot | null>(null);
  const [runningApps, setRunningApps] = createSignal<RunningAppInfo[]>([]);
  const [steamGames, setSteamGames] = createSignal<DiscoveredSteamGame[]>([]);

  let toastTimer: number | undefined;
  function showToast(msg: string) {
    setToast(msg);
    if (toastTimer) window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => setToast(null), 2400);
  }

  // Sync data-theme attribute on <html>
  createEffect(
    () => theme(),
    (t) => {
      document.documentElement.dataset.theme = t;
    }
  );

  // Initial load + global Escape handler
  void refreshSnapshot();
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (unlockOpen()) setUnlockOpen(false);
      else if (screen() === "add") setScreen("main");
    }
  });

  async function refreshSnapshot() {
    try {
      const data = await curbApi.getSnapshot();
      setSnapshot(data);
    } catch (err) {
      showToast(`Service error: ${err instanceof Error ? err.message : err}`);
    }
  }

  async function refreshPickerSources() {
    const [apps, games] = await Promise.all([
      curbApi.listRunningApps(),
      curbApi.listSteamGames(),
    ]);
    setRunningApps(apps);
    setSteamGames(games);
  }

  function requireToken(): string | null {
    const t = token();
    if (!t) {
      setUnlockOpen(true);
      return null;
    }
    return t;
  }

  async function handleUnlock(password: string) {
    const newToken = await curbApi.unlock(password);
    setToken(newToken);
    setUnlockOpen(false);
    showToast("Unlocked · auto-locks when closed");
    await refreshSnapshot();
  }

  async function handleLock() {
    const t = token();
    if (t) await curbApi.lock(t);
    setToken(null);
    if (screen() === "add") setScreen("main");
    showToast("Locked");
  }

  async function handleCloseToTray() {
    const t = token();
    setToken(null);
    setScreen("main");
    await curbApi.hideToTray(t);
    showToast("Hidden to taskbar tray · locked");
  }

  async function openAllowSheet() {
    if (!requireToken()) return;
    await refreshPickerSources();
    setScreen("add");
  }

  async function handleUpdateSteam(steam: SteamPresetConfig) {
    const t = requireToken();
    if (!t) return;
    setSnapshot(await curbApi.updateSteamPreset(t, steam));
  }

  async function handleUpdateBaseline(baseline: BaselinePolicy) {
    const t = requireToken();
    if (!t) return;
    setSnapshot(await curbApi.updateBaseline(t, baseline));
  }

  async function handleSetMode(mode: EnforcementMode) {
    const t = requireToken();
    if (!t) return;
    setSnapshot(await curbApi.setMode(t, mode));
    showToast(
      mode.kind === "enforcing"
        ? "Protection on"
        : mode.kind === "paused_until"
        ? "Paused for 15 minutes"
        : "Protection off"
    );
  }

  async function handleUpsertRule(rule: Rule) {
    const t = requireToken();
    if (!t) return;
    setSnapshot(await curbApi.upsertRule(t, rule));
    setScreen("main");
    setTab("allowed");
    showToast(`Saved ${rule.name}`);
  }

  async function handleDeleteRule(id: string) {
    const t = requireToken();
    if (!t) return;
    setSnapshot(await curbApi.deleteRule(t, id));
    showToast("Removed rule");
  }

  async function handleAllowBlocked(ev: BlockedEvent) {
    const t = requireToken();
    if (!t) return;
    const snap = snapshot();
    if (!snap) return;

    if (ev.is_steam_community) {
      await handleUpdateSteam({
        ...snap.config.presets.steam,
        enabled: true,
        community_and_workshop: true,
      });
      setTab("allowed");
      showToast("Enabled Steam Community");
      return;
    }

    await openAllowSheet();
  }

  async function handleInspectPath(path: string): Promise<RunningAppInfo | null> {
    try {
      const id = await curbApi.inspectExecutable(path);
      return {
        key: `browse-${id.path.toLowerCase()}`,
        name: id.product_name ?? id.filename.replace(/\.exe$/i, ""),
        exe: id.filename,
        path: id.path,
        process_count: 1,
        background: false,
        tried_connect: false,
        tried_host: null,
        signed: !!id.signature?.trusted,
        signer: id.signature?.subject_cn ?? null,
        sha256: id.sha256,
      };
    } catch (err) {
      showToast(`Could not read file: ${err instanceof Error ? err.message : err}`);
      return null;
    }
  }

  async function handleChangePassword(current: string, next: string) {
    const t = requireToken();
    if (!t) return;
    await curbApi.changePassword(t, current, next);
    await refreshSnapshot();
    showToast("Curb password updated");
  }

  const modeVisual = () => {
    const mode = snapshot()?.config.mode.kind ?? "enforcing";
    if (mode === "enforcing") {
      return {
        key: "on" as const,
        bg: "var(--c-green-soft)",
        color: "var(--c-green-text)",
        label: "Internet limited",
      };
    }
    if (mode === "paused_until") {
      return {
        key: "paused" as const,
        bg: "var(--c-amber-soft)",
        color: "var(--c-amber-text)",
        label: "Paused (15 min)",
      };
    }
    return {
      key: "off" as const,
      bg: "var(--c-red-soft)",
      color: "var(--c-red-text)",
      label: "Protection off",
    };
  };

  const activeAllowedCount = () => {
    const snap = snapshot();
    if (!snap) return 0;
    return (
      snap.config.rules.filter((r) => r.enabled).length +
      (snap.config.presets.steam.enabled ? 1 : 0)
    );
  };

  return (
    <div
      role="application"
      aria-label="Curb Internet Limiter"
      class="h-full w-full flex flex-col relative overflow-hidden"
      style={{ background: "var(--c-surface)", color: "var(--c-text)" }}
    >
      <Show
        when={snapshot()}
        fallback={
          <div
            class="flex-1 flex items-center justify-center text-xs"
            style={{ color: "var(--c-text-sec)" }}
          >
            Connecting to Curb service…
          </div>
        }
      >
        {(snap) => (
          <Show
            when={screen() === "main"}
            fallback={
              <AllowAppSheet
                runningApps={runningApps()}
                steamGames={steamGames()}
                existingRules={snap().config.rules}
                onRefresh={() => void refreshPickerSources()}
                onInspectPath={handleInspectPath}
                onCancel={() => setScreen("main")}
                onConfirm={(rule) => void handleUpsertRule(rule)}
              />
            }
          >
            {/* Main Header */}
            <div
              class="px-4 pt-3 pb-3 shrink-0 space-y-2.5"
              style={{
                background: "var(--c-bg)",
                "border-bottom": "1px solid var(--c-border)",
              }}
            >
              <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2 min-w-0">
                  <div
                    class="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                    style={{
                      background: modeVisual().bg,
                      color: modeVisual().color,
                    }}
                  >
                    <ShieldIcon mode={modeVisual().key} />
                  </div>
                  <span
                    class="text-sm font-bold"
                    style={{ color: "var(--c-text)" }}
                  >
                    Curb
                  </span>
                  <span
                    class="text-xs font-semibold px-2 py-0.5 rounded-full truncate"
                    style={{
                      background: modeVisual().bg,
                      color: modeVisual().color,
                    }}
                  >
                    {modeVisual().label}
                  </span>
                </div>

                <div class="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() =>
                      token() ? void handleLock() : setUnlockOpen(true)
                    }
                    class="text-xs font-semibold px-2.5 py-1.5 rounded-lg inline-flex items-center gap-1.5 cursor-pointer"
                    style={{
                      background: token()
                        ? "var(--c-amber-soft)"
                        : "var(--c-pill)",
                      color: token()
                        ? "var(--c-amber-text)"
                        : "var(--c-text)",
                    }}
                  >
                    {token() ? <UnlockIcon /> : <LockIcon />}
                    {token() ? "Lock" : "Unlock"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleCloseToTray()}
                    aria-label="Hide to taskbar tray"
                    class="w-8 h-8 rounded-lg flex items-center justify-center cursor-pointer text-base"
                    style={{ color: "var(--c-text-sec)" }}
                  >
                    &times;
                  </button>
                </div>
              </div>

              <div
                role="tablist"
                aria-label="Curb sections"
                class="p-1 rounded-lg grid grid-cols-3 gap-1 text-xs font-semibold"
                style={{ background: "var(--c-sub)" }}
              >
                {(["allowed", "blocked", "settings"] as const).map((t) => (
                  <button
                    type="button"
                    role="tab"
                    aria-selected={tab() === t ? "true" : "false"}
                    onClick={() => setTab(t)}
                    class="py-1.5 rounded-md cursor-pointer capitalize flex items-center justify-center gap-1.5"
                    style={{
                      background:
                        tab() === t ? "var(--c-surface)" : "transparent",
                      color:
                        tab() === t ? "var(--c-text)" : "var(--c-text-muted)",
                    }}
                  >
                    <span>{t}</span>
                    <Show
                      when={t === "blocked" && snap().blocked_events.length > 0}
                    >
                      <span
                        class="text-xs font-bold px-1.5 rounded-full leading-tight"
                        style={{
                          background: "var(--c-red-soft)",
                          color: "var(--c-red-text)",
                        }}
                      >
                        {snap().blocked_events.length}
                      </span>
                    </Show>
                  </button>
                ))}
              </div>
            </div>

            {/* Scrollable Tab Body */}
            <div class="flex-1 overflow-y-auto curb-scroll p-4 min-h-0">
              <Show when={tab() === "allowed"}>
                <AllowedView
                  unlocked={!!token()}
                  steam={snap().config.presets.steam}
                  rules={snap().config.rules}
                  onRequireUnlock={() => setUnlockOpen(true)}
                  onUpdateSteam={(s) => void handleUpdateSteam(s)}
                  onUpdateRule={(r) => void handleUpsertRule(r)}
                  onDeleteRule={(id) => void handleDeleteRule(id)}
                />
              </Show>

              <Show when={tab() === "blocked"}>
                <BlockedView
                  events={snap().blocked_events}
                  onAllowEvent={(ev) => void handleAllowBlocked(ev)}
                />
              </Show>

              <Show when={tab() === "settings"}>
                <SettingsView
                  unlocked={!!token()}
                  passwordConfigured={snap().password_configured}
                  mode={snap().config.mode}
                  baseline={snap().config.baseline}
                  theme={theme()}
                  onRequireUnlock={() => setUnlockOpen(true)}
                  onToggleTheme={() =>
                    setTheme((t) => (t === "dark" ? "light" : "dark"))
                  }
                  onSetMode={(m) => void handleSetMode(m)}
                  onUpdateBaseline={(b) => void handleUpdateBaseline(b)}
                  onChangePassword={handleChangePassword}
                />
              </Show>
            </div>

            {/* Footer on Allowed Tab */}
            <Show when={tab() === "allowed"}>
              <div
                class="px-4 py-3 shrink-0 flex items-center justify-between"
                style={{
                  background: "var(--c-bg)",
                  "border-top": "1px solid var(--c-border)",
                }}
              >
                <span
                  class="text-xs font-medium"
                  style={{ color: "var(--c-text-sec)" }}
                >
                  {activeAllowedCount()} allowed
                </span>
                <button
                  type="button"
                  onClick={() => void openAllowSheet()}
                  class="px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                  style={{ background: "var(--c-accent)", color: "#ffffff" }}
                >
                  <PlusIcon />
                  Allow App or Game
                </button>
              </div>
            </Show>
          </Show>
        )}
      </Show>

      {/* Live Toast */}
      <Show when={toast()}>
        {(msg) => (
          <div
            role="status"
            aria-live="polite"
            class="fixed bottom-16 left-1/2 -translate-x-1/2 px-3.5 py-2 rounded-lg text-xs font-medium shadow-xl z-40 whitespace-nowrap"
            style={{
              background: "var(--c-sub)",
              border: "1px solid var(--c-border-strong)",
              color: "var(--c-text)",
            }}
          >
            {msg()}
          </div>
        )}
      </Show>

      {/* Admin Unlock Modal */}
      <UnlockModal
        open={unlockOpen()}
        passwordConfigured={snapshot()?.password_configured ?? true}
        onClose={() => setUnlockOpen(false)}
        onUnlock={handleUnlock}
      />
    </div>
  );
}
