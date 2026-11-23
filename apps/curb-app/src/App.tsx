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
import { LockIcon, PlusIcon, ShieldIcon, SpinnerIcon, UnlockIcon } from "./components/Icons";
import { SettingsView } from "./components/SettingsView";
import { SetupView } from "./components/SetupView";
import { UnlockModal } from "./components/UnlockModal";

export default function App() {
  const [theme, setTheme] = createSignal<"dark" | "light">("dark");
  const [screen, setScreen] = createSignal<"main" | "add">("main");
  const [tab, setTab] = createSignal<"allowed" | "blocked" | "settings">(
    "allowed"
  );
  const [token, setToken] = createSignal<string | null>(null);
  const [unlockOpen, setUnlockOpen] = createSignal(false);
  const [pendingOpenAllow, setPendingOpenAllow] = createSignal(false);
  const [toast, setToast] = createSignal<string | null>(null);

  const [snapshot, setSnapshot] = createSignal<ServiceSnapshot | null>(null);
  const [runningApps, setRunningApps] = createSignal<RunningAppInfo[]>([]);
  const [steamGames, setSteamGames] = createSignal<DiscoveredSteamGame[]>([]);
  const [loadingRunningApps, setLoadingRunningApps] = createSignal(false);
  const [loadingSteamGames, setLoadingSteamGames] = createSignal(false);

  const [locking, setLocking] = createSignal(false);
  const [hidingToTray, setHidingToTray] = createSignal(false);
  const [busySteam, setBusySteam] = createSignal(false);
  const [busyBaseline, setBusyBaseline] = createSignal(false);
  const [pendingMode, setPendingMode] = createSignal<
    EnforcementMode["kind"] | null
  >(null);
  const [busyRuleIds, setBusyRuleIds] = createSignal<Record<string, boolean>>(
    {}
  );
  const [deletingRuleId, setDeletingRuleId] = createSignal<string | null>(null);
  const [allowingBlockedId, setAllowingBlockedId] = createSignal<string | null>(
    null
  );

  let toastTimer: number | undefined;
  let runningReqId = 0;
  let steamReqId = 0;

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
      if (unlockOpen()) {
        setUnlockOpen(false);
        setPendingOpenAllow(false);
      } else if (screen() === "add") {
        setScreen("main");
      }
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

  async function refreshRunningApps() {
    const reqId = ++runningReqId;
    setLoadingRunningApps(true);
    try {
      const apps = await curbApi.listRunningApps();
      if (reqId === runningReqId) {
        setRunningApps(apps);
      }
    } catch (err) {
      if (reqId === runningReqId) {
        showToast(
          `Could not list running apps: ${err instanceof Error ? err.message : err}`
        );
      }
    } finally {
      if (reqId === runningReqId) {
        setLoadingRunningApps(false);
      }
    }
  }

  async function refreshSteamGames() {
    const reqId = ++steamReqId;
    setLoadingSteamGames(true);
    try {
      const games = await curbApi.listSteamGames();
      if (reqId === steamReqId) {
        setSteamGames(games);
      }
    } catch (err) {
      if (reqId === steamReqId) {
        showToast(
          `Could not scan Steam games: ${err instanceof Error ? err.message : err}`
        );
      }
    } finally {
      if (reqId === steamReqId) {
        setLoadingSteamGames(false);
      }
    }
  }

  function refreshPickerSources() {
    void refreshRunningApps();
    void refreshSteamGames();
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
    if (pendingOpenAllow()) {
      setPendingOpenAllow(false);
      setScreen("add");
      refreshPickerSources();
    }
  }

  async function handleLock() {
    if (locking()) return;
    setLocking(true);
    try {
      const t = token();
      if (t) await curbApi.lock(t);
      setToken(null);
      setPendingOpenAllow(false);
      if (screen() === "add") setScreen("main");
      showToast("Locked");
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
    } finally {
      setLocking(false);
    }
  }

  async function handleCloseToTray() {
    if (hidingToTray()) return;
    setHidingToTray(true);
    try {
      const t = token();
      setToken(null);
      setPendingOpenAllow(false);
      setScreen("main");
      await curbApi.hideToTray(t);
      showToast("Hidden to taskbar tray · locked");
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
    } finally {
      setHidingToTray(false);
    }
  }

  function openAllowSheet() {
    if (!requireToken()) {
      setPendingOpenAllow(true);
      return;
    }
    // Open immediately so the button responds instantaneously while sources load in parallel.
    setScreen("add");
    refreshPickerSources();
  }

  async function handleUpdateSteam(steam: SteamPresetConfig): Promise<boolean> {
    const t = requireToken();
    if (!t || busySteam()) return false;
    setBusySteam(true);
    try {
      setSnapshot(await curbApi.updateSteamPreset(t, steam));
      return true;
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      setBusySteam(false);
    }
  }

  async function handleUpdateBaseline(baseline: BaselinePolicy) {
    const t = requireToken();
    if (!t || busyBaseline()) return;
    setBusyBaseline(true);
    try {
      setSnapshot(await curbApi.updateBaseline(t, baseline));
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyBaseline(false);
    }
  }

  async function handleSetMode(mode: EnforcementMode) {
    const t = requireToken();
    if (!t || pendingMode() !== null) return;
    setPendingMode(mode.kind);
    try {
      setSnapshot(await curbApi.setMode(t, mode));
      showToast(
        mode.kind === "enforcing"
          ? "Protection on"
          : mode.kind === "paused_until"
          ? "Paused for 15 minutes"
          : "Protection off"
      );
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
    } finally {
      setPendingMode(null);
    }
  }

  async function handleUpsertRule(rule: Rule) {
    const t = requireToken();
    if (!t) return;
    setBusyRuleIds((prev) => ({ ...prev, [rule.id]: true }));
    try {
      setSnapshot(await curbApi.upsertRule(t, rule));
      setScreen("main");
      setTab("allowed");
      showToast(`Saved ${rule.name}`);
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyRuleIds((prev) => {
        const next = { ...prev };
        delete next[rule.id];
        return next;
      });
    }
  }

  async function handleDeleteRule(id: string) {
    const t = requireToken();
    if (!t || deletingRuleId() !== null) return;
    setDeletingRuleId(id);
    try {
      setSnapshot(await curbApi.deleteRule(t, id));
      showToast("Removed rule");
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
    } finally {
      setDeletingRuleId(null);
    }
  }

  async function handleAllowBlocked(ev: BlockedEvent) {
    const t = requireToken();
    if (!t || allowingBlockedId() !== null) return;
    const snap = snapshot();
    if (!snap) return;

    if (ev.is_steam_community) {
      setAllowingBlockedId(ev.id);
      try {
        const ok = await handleUpdateSteam({
          ...snap.config.presets.steam,
          enabled: true,
          community_and_workshop: true,
        });
        if (ok) {
          setTab("allowed");
          showToast("Enabled Steam Community");
        }
      } finally {
        setAllowingBlockedId(null);
      }
      return;
    }

    openAllowSheet();
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

  async function handleSetupFull() {
    const snap = await curbApi.setupFullProtection();
    setSnapshot(snap);
    showToast("Full Protection active");
    if (!snap.password_configured) {
      setUnlockOpen(true);
    }
  }

  async function handleSetupStandard(password: string) {
    const [newToken, snap] = await curbApi.setupStandardMode(password);
    setToken(newToken);
    setSnapshot(snap);
    showToast("Standard Mode active");
  }

  async function handleUpgradeToFull() {
    try {
      const snap = await curbApi.setupFullProtection();
      setSnapshot(snap);
      showToast("Upgraded to Full Protection");
      if (!snap.password_configured) {
        setUnlockOpen(true);
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleUninstallService() {
    try {
      await curbApi.uninstallFullProtection();
      setToken(null);
      await refreshSnapshot();
      showToast("System service removed");
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err));
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
    const snap = snapshot();
    const mode = snap?.config.mode.kind ?? "enforcing";
    const isStandard = snap?.protection_tier === "standard_user";
    if (mode === "enforcing") {
      return {
        key: "on" as const,
        bg: "var(--c-green-soft)",
        color: "var(--c-green-text)",
        label: isStandard ? "Standard mode" : "Internet limited",
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
            role="status"
            class="flex-1 flex items-center justify-center gap-2 text-xs"
            style={{ color: "var(--c-text-sec)" }}
          >
            <SpinnerIcon size={14} />
            <span>Connecting to Curb…</span>
          </div>
        }
      >
        {(snap) => (
          <Show
            when={snap().protection_tier !== "unconfigured"}
            fallback={
              <SetupView
                onSelectFull={handleSetupFull}
                onSelectStandard={handleSetupStandard}
              />
            }
          >
            <Show
              when={screen() === "main"}
              fallback={
                <AllowAppSheet
                  runningApps={runningApps()}
                  steamGames={steamGames()}
                  loadingRunning={loadingRunningApps()}
                  loadingSteam={loadingSteamGames()}
                  existingRules={snap().config.rules}
                  onRefresh={refreshPickerSources}
                  onInspectPath={handleInspectPath}
                  onCancel={() => setScreen("main")}
                  onConfirm={handleUpsertRule}
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
                    disabled={locking() || hidingToTray()}
                    aria-busy={locking() ? "true" : "false"}
                    onClick={() =>
                      token() ? void handleLock() : setUnlockOpen(true)
                    }
                    class="text-xs font-semibold px-2.5 py-1.5 rounded-lg inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-60"
                    style={{
                      background: token()
                        ? "var(--c-amber-soft)"
                        : "var(--c-pill)",
                      color: token()
                        ? "var(--c-amber-text)"
                        : "var(--c-text)",
                    }}
                  >
                    <Show
                      when={!locking()}
                      fallback={<SpinnerIcon size={12} />}
                    >
                      {token() ? <UnlockIcon /> : <LockIcon />}
                    </Show>
                    <span>
                      {locking() ? "Locking…" : token() ? "Lock" : "Unlock"}
                    </span>
                  </button>
                  <button
                    type="button"
                    disabled={hidingToTray()}
                    aria-busy={hidingToTray() ? "true" : "false"}
                    onClick={() => void handleCloseToTray()}
                    aria-label="Hide to taskbar tray"
                    class="w-8 h-8 rounded-lg flex items-center justify-center cursor-pointer text-base disabled:opacity-60"
                    style={{ color: "var(--c-text-sec)" }}
                  >
                    <Show when={!hidingToTray()} fallback={<SpinnerIcon size={13} />}>
                      &times;
                    </Show>
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
                  busySteam={busySteam()}
                  busyRuleIds={busyRuleIds()}
                  deletingRuleId={deletingRuleId()}
                  onRequireUnlock={() => setUnlockOpen(true)}
                  onUpdateSteam={(s) => void handleUpdateSteam(s)}
                  onUpdateRule={(r) => void handleUpsertRule(r)}
                  onDeleteRule={(id) => void handleDeleteRule(id)}
                />
              </Show>

              <Show when={tab() === "blocked"}>
                <BlockedView
                  events={snap().blocked_events}
                  allowingId={allowingBlockedId()}
                  onAllowEvent={(ev) => void handleAllowBlocked(ev)}
                />
              </Show>

              <Show when={tab() === "settings"}>
                <SettingsView
                  unlocked={!!token()}
                  passwordConfigured={snap().password_configured}
                  protectionTier={snap().protection_tier}
                  mode={snap().config.mode}
                  pendingMode={pendingMode()}
                  baseline={snap().config.baseline}
                  busyBaseline={busyBaseline()}
                  theme={theme()}
                  onRequireUnlock={() => setUnlockOpen(true)}
                  onUpgradeToFull={handleUpgradeToFull}
                  onUninstallService={handleUninstallService}
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
                  disabled={locking() || hidingToTray()}
                  onClick={openAllowSheet}
                  class="px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-60"
                  style={{ background: "var(--c-accent)", color: "#ffffff" }}
                >
                  <PlusIcon />
                  Allow App or Game
                </button>
              </div>
            </Show>
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
        onClose={() => {
          setUnlockOpen(false);
          setPendingOpenAllow(false);
        }}
        onUnlock={handleUnlock}
      />
    </div>
  );
}
