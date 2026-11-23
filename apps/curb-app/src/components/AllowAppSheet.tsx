import { createMemo, createSignal, For, Show } from "solid-js";
import type {
  DiscoveredSteamGame,
  ExecutableMatcher,
  Rule,
  RunningAppInfo,
  SubprocessPolicy,
} from "../lib/types";
import {
  AlertCircleIcon,
  BackIcon,
  CheckIcon,
  FolderIcon,
  RefreshIcon,
  SearchIcon,
  WarnIcon,
} from "./Icons";

interface AllowAppSheetProps {
  runningApps: RunningAppInfo[];
  steamGames: DiscoveredSteamGame[];
  existingRules: Rule[];
  onRefresh: () => void;
  onInspectPath: (path: string) => Promise<RunningAppInfo | null>;
  onCancel: () => void;
  onConfirm: (rule: Rule) => void;
}

const AVATAR_COLORS = [
  "#5c42cc",
  "#4752c4",
  "#187e45",
  "#0369a1",
  "#be123c",
  "#b45309",
  "#0e7490",
  "#475569",
];

function colorFor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  }
  return AVATAR_COLORS[hash % AVATAR_COLORS.length];
}

function initialsFor(name: string): string {
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return name.slice(0, 2).toUpperCase();
}

export function AllowAppSheet(props: AllowAppSheetProps) {
  const [tab, setTab] = createSignal<"running" | "steam">("running");
  const [search, setSearch] = createSignal("");
  const [showBg, setShowBg] = createSignal(false);
  const [selectedKey, setSelectedKey] = createSignal<string | null>(null);
  const [browsed, setBrowsed] = createSignal<RunningAppInfo | null>(null);

  const [advOpen, setAdvOpen] = createSignal(false);
  const [allowTcp, setAllowTcp] = createSignal(true);
  const [allowUdp, setAllowUdp] = createSignal(true);
  const [subPolicy, setSubPolicy] =
    createSignal<SubprocessPolicy>("same_signer_or_dir");
  const [dnsText, setDnsText] = createSignal("");
  const [forceHash, setForceHash] = createSignal(false);

  const isAlreadyAllowed = (exe: string) =>
    props.existingRules.some(
      (r) => r.exe_hint.toLowerCase() === exe.toLowerCase()
    );

  const filteredRunning = createMemo(() => {
    const q = search().trim().toLowerCase();
    return props.runningApps
      .filter((a) => showBg() || !a.background)
      .filter(
        (a) =>
          !q ||
          a.name.toLowerCase().includes(q) ||
          a.exe.toLowerCase().includes(q) ||
          (a.signer && a.signer.toLowerCase().includes(q))
      )
      .sort((a, b) => {
        const aAl = isAlreadyAllowed(a.exe) ? 1 : 0;
        const bAl = isAlreadyAllowed(b.exe) ? 1 : 0;
        if (aAl !== bAl) return aAl - bAl;
        return (b.tried_connect ? 1 : 0) - (a.tried_connect ? 1 : 0);
      });
  });

  const triedApps = createMemo(() =>
    filteredRunning().filter(
      (a) => a.tried_connect && !isAlreadyAllowed(a.exe)
    )
  );
  const otherApps = createMemo(() =>
    filteredRunning().filter(
      (a) => !(a.tried_connect && !isAlreadyAllowed(a.exe))
    )
  );

  const filteredSteam = createMemo(() => {
    const q = search().trim().toLowerCase();
    return props.steamGames.filter(
      (g) =>
        !q ||
        g.name.toLowerCase().includes(q) ||
        g.exe_name.toLowerCase().includes(q)
    );
  });

  const selectedSummary = createMemo(() => {
    const key = selectedKey();
    if (!key) return null;

    const b = browsed();
    if (b && b.key === key) {
      return {
        kind: "app" as const,
        name: b.name,
        exe: b.exe,
        path: b.path,
        signed: b.signed,
        signer: b.signer,
        sha256: b.sha256,
        appId: null as number | null,
        installDir: null as string | null,
      };
    }

    const run = props.runningApps.find((a) => a.key === key);
    if (run) {
      return {
        kind: "app" as const,
        name: run.name,
        exe: run.exe,
        path: run.path,
        signed: run.signed,
        signer: run.signer,
        sha256: run.sha256,
        appId: null as number | null,
        installDir: null as string | null,
      };
    }

    const game = props.steamGames.find((g) => `steam-${g.app_id}` === key);
    if (game) {
      return {
        kind: "steam" as const,
        name: game.name,
        exe: game.exe_name,
        path: game.exe_path,
        signed: game.signed,
        signer: game.signer,
        sha256: game.sha256,
        appId: game.app_id,
        installDir: game.install_dir,
      };
    }
    return null;
  });

  async function handleBrowse() {
    const path = window.prompt(
      "Enter the full path to an executable (.exe):",
      "C:\\Program Files\\Example\\App.exe"
    );
    if (!path || !path.trim()) return;
    const inspected = await props.onInspectPath(path.trim());
    if (inspected) {
      setBrowsed(inspected);
      setSelectedKey(inspected.key);
    }
  }

  function handleConfirm() {
    const sel = selectedSummary();
    if (!sel) return;

    const dnsList = dnsText()
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const useSigned = sel.signed && !forceHash() && !!sel.signer;

    let matcher: ExecutableMatcher;
    if (sel.kind === "steam" && sel.appId !== null && sel.installDir !== null) {
      matcher = {
        kind: "steam_game",
        app_id: sel.appId,
        install_dir: sel.installDir,
        verification: useSigned
          ? {
              type: "signature",
              subject_cn: sel.signer!,
              original_filename: sel.exe,
            }
          : {
              type: "hash",
              sha256: sel.sha256,
              filename_hint: sel.exe,
            },
      };
    } else if (useSigned) {
      matcher = {
        kind: "signature",
        subject_cn: sel.signer!,
        product_name: sel.name,
        original_filename: sel.exe,
      };
    } else {
      matcher = {
        kind: "hash",
        sha256: sel.sha256,
        filename_hint: sel.exe,
      };
    }

    const rule: Rule = {
      id: crypto.randomUUID(),
      name: sel.name,
      enabled: true,
      matcher,
      network: {
        allow_tcp: allowTcp(),
        allow_udp: allowUdp(),
        dns_whitelist: dnsList.length > 0 ? dnsList : null,
      },
      subprocesses: subPolicy(),
      exe_hint: sel.exe,
      created_at: new Date().toISOString(),
    };

    props.onConfirm(rule);
  }

  function renderAppRow(app: RunningAppInfo) {
    const already = () => isAlreadyAllowed(app.exe);
    const active = () => selectedKey() === app.key && !already();

    return (
      <button
        type="button"
        disabled={already()}
        role="radio"
        aria-checked={active() ? "true" : "false"}
        onClick={() => setSelectedKey(app.key)}
        class={`w-full text-left px-3 py-2.5 rounded-xl flex items-center gap-3 transition-colors ${
          already() ? "cursor-default" : "cursor-pointer"
        }`}
        style={{
          background: active() ? "var(--c-accent-soft)" : "var(--c-card)",
          border: `1px solid ${active() ? "var(--c-focus)" : "var(--c-border)"}`,
        }}
      >
        <div
          aria-hidden="true"
          class="w-9 h-9 rounded-lg flex items-center justify-center text-white text-xs font-bold shrink-0"
          style={{ background: colorFor(app.name) }}
        >
          {initialsFor(app.name)}
        </div>

        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span
              class="text-[13px] font-semibold truncate"
              style={{ color: "var(--c-text)" }}
            >
              {app.name}
            </span>
            <Show when={app.background}>
              <span
                class="text-xs px-1.5 py-0.5 rounded font-medium leading-none"
                style={{
                  background: "var(--c-pill)",
                  color: "var(--c-text-sec)",
                }}
              >
                Background
              </span>
            </Show>
            <Show when={app.process_count > 1 && !app.background}>
              <span class="text-xs" style={{ color: "var(--c-text-muted)" }}>
                {app.process_count} tasks
              </span>
            </Show>
          </div>

          <div class="text-xs truncate mt-0.5 flex items-center gap-1.5">
            <Show
              when={app.tried_connect && !already() && app.tried_host}
              fallback={
                <span
                  class="inline-flex items-center gap-1"
                  style={{
                    color: app.signed
                      ? "var(--c-green-text)"
                      : "var(--c-amber-text)",
                  }}
                >
                  {app.signed ? <CheckIcon /> : <WarnIcon />}
                  <span>
                    {app.signed
                      ? "Updates automatically"
                      : "Re-approve after updates"}
                  </span>
                </span>
              }
            >
              <span
                class="inline-flex items-center gap-1 font-medium"
                style={{ color: "var(--c-amber-text)" }}
              >
                <AlertCircleIcon />
                <span>Tried to reach {app.tried_host}</span>
              </span>
            </Show>
          </div>
        </div>

        <div class="shrink-0">
          <Show
            when={already()}
            fallback={
              <span
                aria-hidden="true"
                class="w-5 h-5 rounded-full flex items-center justify-center"
                style={{
                  border: `2px solid ${
                    active() ? "var(--c-accent)" : "var(--c-border-strong)"
                  }`,
                  background: active() ? "var(--c-accent)" : "transparent",
                  color: "#ffffff",
                }}
              >
                <Show when={active()}>
                  <CheckIcon />
                </Show>
              </span>
            }
          >
            <span
              class="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-1 rounded-full"
              style={{
                background: "var(--c-green-soft)",
                color: "var(--c-green-text)",
              }}
            >
              <CheckIcon />
              <span>Allowed</span>
            </span>
          </Show>
        </div>
      </button>
    );
  }

  return (
    <div class="flex-1 flex flex-col min-h-0">
      {/* Header */}
      <div
        class="px-4 pt-3 pb-3 shrink-0 space-y-2.5"
        style={{
          background: "var(--c-bg)",
          "border-bottom": "1px solid var(--c-border)",
        }}
      >
        <div class="flex items-center justify-between">
          <button
            type="button"
            onClick={props.onCancel}
            class="inline-flex items-center gap-1 text-xs font-semibold px-1.5 py-1 -ml-1.5 rounded-md cursor-pointer"
            style={{ color: "var(--c-text-sec)" }}
          >
            <BackIcon />
            Back
          </button>
          <h1
            class="text-sm font-semibold"
            style={{ color: "var(--c-text)" }}
          >
            Allow an App or Game
          </h1>
          <button
            type="button"
            onClick={props.onRefresh}
            aria-label="Refresh running apps"
            class="w-8 h-8 rounded-md flex items-center justify-center cursor-pointer"
            style={{ color: "var(--c-text-sec)" }}
          >
            <RefreshIcon />
          </button>
        </div>

        <div
          role="tablist"
          aria-label="App source"
          class="p-1 rounded-lg grid grid-cols-2 gap-1 text-xs font-semibold"
          style={{ background: "var(--c-sub)" }}
        >
          <button
            type="button"
            role="tab"
            aria-selected={tab() === "running" ? "true" : "false"}
            onClick={() => setTab("running")}
            class="py-1.5 rounded-md cursor-pointer"
            style={{
              background:
                tab() === "running" ? "var(--c-surface)" : "transparent",
              color:
                tab() === "running" ? "var(--c-text)" : "var(--c-text-muted)",
            }}
          >
            Running Apps
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab() === "steam" ? "true" : "false"}
            onClick={() => setTab("steam")}
            class="py-1.5 rounded-md cursor-pointer"
            style={{
              background:
                tab() === "steam" ? "var(--c-surface)" : "transparent",
              color:
                tab() === "steam" ? "var(--c-text)" : "var(--c-text-muted)",
            }}
          >
            Steam Games
          </button>
        </div>

        <div class="relative">
          <label for="curb-picker-search" class="sr-only">
            Search apps
          </label>
          <span
            class="absolute left-3 top-1/2 -translate-y-1/2"
            style={{ color: "var(--c-text-muted)" }}
          >
            <SearchIcon />
          </span>
          <input
            id="curb-picker-search"
            type="search"
            value={search()}
            onInput={(e) => setSearch(e.currentTarget.value)}
            placeholder={
              tab() === "running"
                ? "Search running apps…"
                : "Search installed Steam games…"
            }
            class="w-full pl-9 pr-3 py-2 rounded-lg text-xs"
            style={{
              background: "var(--c-sub)",
              border: "1px solid var(--c-border-strong)",
              color: "var(--c-text)",
            }}
          />
        </div>
      </div>

      {/* Scrollable Picker List */}
      <div class="flex-1 overflow-y-auto curb-scroll p-3.5 space-y-3.5 min-h-0">
        <Show
          when={tab() === "running"}
          fallback={
            <div class="space-y-2">
              <p class="text-xs px-0.5" style={{ color: "var(--c-text-sec)" }}>
                Installed games found in your Steam library:
              </p>
              <div
                class="space-y-1.5"
                role="radiogroup"
                aria-label="Installed Steam games"
              >
                <For each={filteredSteam()}>
                  {(game) => {
                    const key = `steam-${game.app_id}`;
                    const already = () => isAlreadyAllowed(game.exe_name);
                    const active = () => selectedKey() === key && !already();
                    return (
                      <button
                        type="button"
                        disabled={already()}
                        role="radio"
                        aria-checked={active() ? "true" : "false"}
                        onClick={() => setSelectedKey(key)}
                        class={`w-full text-left px-3 py-2.5 rounded-xl flex items-center gap-3 ${
                          already() ? "cursor-default" : "cursor-pointer"
                        }`}
                        style={{
                          background: active()
                            ? "var(--c-accent-soft)"
                            : "var(--c-card)",
                          border: `1px solid ${
                            active() ? "var(--c-focus)" : "var(--c-border)"
                          }`,
                        }}
                      >
                        <div
                          aria-hidden="true"
                          class="w-9 h-9 rounded-lg flex items-center justify-center text-white text-xs font-bold shrink-0"
                          style={{ background: colorFor(game.name) }}
                        >
                          {initialsFor(game.name)}
                        </div>
                        <div class="min-w-0 flex-1">
                          <div
                            class="text-[13px] font-semibold truncate"
                            style={{ color: "var(--c-text)" }}
                          >
                            {game.name}
                          </div>
                          <div
                            class="text-xs truncate mt-0.5 inline-flex items-center gap-1"
                            style={{
                              color: game.signed
                                ? "var(--c-green-text)"
                                : "var(--c-amber-text)",
                            }}
                          >
                            {game.signed ? <CheckIcon /> : <WarnIcon />}
                            <span>
                              {game.signed
                                ? "Updates automatically"
                                : "Unsigned · Re-approve after updates"}
                            </span>
                          </div>
                        </div>
                        <div class="shrink-0">
                          <Show
                            when={already()}
                            fallback={
                              <span
                                aria-hidden="true"
                                class="w-5 h-5 rounded-full flex items-center justify-center"
                                style={{
                                  border: `2px solid ${
                                    active()
                                      ? "var(--c-accent)"
                                      : "var(--c-border-strong)"
                                  }`,
                                  background: active()
                                    ? "var(--c-accent)"
                                    : "transparent",
                                  color: "#ffffff",
                                }}
                              >
                                <Show when={active()}>
                                  <CheckIcon />
                                </Show>
                              </span>
                            }
                          >
                            <span
                              class="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-1 rounded-full"
                              style={{
                                background: "var(--c-green-soft)",
                                color: "var(--c-green-text)",
                              }}
                            >
                              <CheckIcon />
                              <span>Allowed</span>
                            </span>
                          </Show>
                        </div>
                      </button>
                    );
                  }}
                </For>
              </div>
            </div>
          }
        >
          <Show when={browsed()}>
            {(b) => (
              <div class="space-y-1.5">
                <div
                  class="text-xs font-semibold px-1"
                  style={{ color: "var(--c-text-sec)" }}
                >
                  Chosen file
                </div>
                {renderAppRow(b())}
              </div>
            )}
          </Show>

          <Show when={triedApps().length > 0}>
            <div
              class="space-y-1.5"
              role="radiogroup"
              aria-label="Apps that recently tried to go online"
            >
              <div
                class="text-xs font-semibold px-1 flex items-center gap-1.5"
                style={{ color: "var(--c-amber-text)" }}
              >
                <AlertCircleIcon />
                <span>Recently tried to go online</span>
              </div>
              <For each={triedApps()}>{(app) => renderAppRow(app)}</For>
            </div>
          </Show>

          <div
            class="space-y-1.5"
            role="radiogroup"
            aria-label="Open apps on this computer"
          >
            <div
              class="text-xs font-semibold px-1 flex items-center justify-between gap-2"
              style={{ color: "var(--c-text-sec)" }}
            >
              <span>Open on this computer</span>
              <label class="inline-flex items-center gap-1.5 cursor-pointer font-medium">
                <input
                  type="checkbox"
                  checked={showBg()}
                  onChange={(e) => setShowBg(e.currentTarget.checked)}
                  class="w-3.5 h-3.5 cursor-pointer"
                />
                <span>
                  Show background (
                  {props.runningApps.filter((a) => a.background).length})
                </span>
              </label>
            </div>
            <Show
              when={otherApps().length > 0}
              fallback={
                <div
                  class="text-center py-6 text-xs"
                  style={{ color: "var(--c-text-muted)" }}
                >
                  No matching running apps.
                </div>
              }
            >
              <For each={otherApps()}>{(app) => renderAppRow(app)}</For>
            </Show>
          </div>

          <button
            type="button"
            onClick={handleBrowse}
            class="w-full py-2.5 px-3 rounded-xl text-xs font-medium flex items-center justify-center gap-2 cursor-pointer"
            style={{
              background: "transparent",
              border: "1px dashed var(--c-border-strong)",
              color: "var(--c-text-sec)",
            }}
          >
            <FolderIcon />
            App not open? Browse for a file (.exe)&hellip;
          </button>
        </Show>
      </div>

      {/* Bottom Sticky Confirmation & Collapsible Advanced */}
      <div
        class="px-4 py-3 shrink-0 space-y-2.5"
        style={{
          background: "var(--c-bg)",
          "border-top": "1px solid var(--c-border)",
        }}
      >
        <Show
          when={selectedSummary()}
          fallback={
            <div class="flex items-center justify-between text-xs">
              <span style={{ color: "var(--c-text-sec)" }}>
                Select an app above to allow it online
              </span>
              <button
                type="button"
                onClick={props.onCancel}
                class="px-3 py-1.5 rounded-lg font-semibold cursor-pointer"
                style={{ color: "var(--c-text-sec)" }}
              >
                Cancel
              </button>
            </div>
          }
        >
          {(sel) => {
            const useSigned = () => sel().signed && !forceHash();
            return (
              <>
                <div class="flex items-start justify-between gap-2">
                  <div class="min-w-0">
                    <div
                      class="text-[13px] font-semibold truncate"
                      style={{ color: "var(--c-text)" }}
                    >
                      {sel().name}
                    </div>
                    <div
                      class="text-xs mt-0.5 flex items-center gap-1"
                      style={{
                        color: useSigned()
                          ? "var(--c-green-text)"
                          : "var(--c-amber-text)",
                      }}
                    >
                      {useSigned() ? <CheckIcon /> : <WarnIcon />}
                      <span class="truncate">
                        {useSigned()
                          ? `Verified (${sel().signer}) · updates automatically`
                          : "Exact file lock · re-approve after updates"}
                      </span>
                    </div>
                  </div>
                  <button
                    type="button"
                    aria-expanded={advOpen() ? "true" : "false"}
                    onClick={() => setAdvOpen((v) => !v)}
                    class="text-xs font-semibold shrink-0 px-2.5 py-1.5 rounded-lg cursor-pointer"
                    style={{
                      background: "var(--c-card)",
                      border: "1px solid var(--c-border-strong)",
                      color: "var(--c-text)",
                    }}
                  >
                    {advOpen() ? "Hide advanced" : "Advanced"}
                  </button>
                </div>

                <Show when={advOpen()}>
                  <div
                    class="p-3 rounded-xl space-y-2.5 text-xs"
                    style={{
                      background: "var(--c-surface)",
                      border: "1px solid var(--c-border-strong)",
                    }}
                  >
                    <div class="flex items-center justify-between">
                      <span style={{ color: "var(--c-text-sec)" }}>
                        Protocols
                      </span>
                      <div class="flex gap-1.5">
                        <button
                          type="button"
                          aria-pressed={allowTcp() ? "true" : "false"}
                          onClick={() => setAllowTcp((v) => !v)}
                          class="px-2.5 py-1 rounded-md font-semibold cursor-pointer"
                          style={{
                            background: allowTcp()
                              ? "var(--c-accent)"
                              : "var(--c-pill)",
                            color: allowTcp() ? "#ffffff" : "var(--c-text)",
                          }}
                        >
                          TCP
                        </button>
                        <button
                          type="button"
                          aria-pressed={allowUdp() ? "true" : "false"}
                          onClick={() => setAllowUdp((v) => !v)}
                          class="px-2.5 py-1 rounded-md font-semibold cursor-pointer"
                          style={{
                            background: allowUdp()
                              ? "var(--c-accent)"
                              : "var(--c-pill)",
                            color: allowUdp() ? "#ffffff" : "var(--c-text)",
                          }}
                        >
                          UDP
                        </button>
                      </div>
                    </div>

                    <div class="flex items-center justify-between gap-2">
                      <label
                        for="curb-adv-sub"
                        style={{ color: "var(--c-text-sec)" }}
                      >
                        Sub-processes
                      </label>
                      <select
                        id="curb-adv-sub"
                        value={subPolicy()}
                        onChange={(e) =>
                          setSubPolicy(
                            e.currentTarget.value as SubprocessPolicy
                          )
                        }
                        class="rounded-md px-2 py-1 text-xs"
                        style={{
                          background: "var(--c-bg)",
                          border: "1px solid var(--c-border-strong)",
                          color: "var(--c-text)",
                        }}
                      >
                        <option value="disabled">Disabled</option>
                        <option value="same_signer_or_dir">
                          Same signer or folder
                        </option>
                        <option value="any_except_restricted">
                          Any (except browsers)
                        </option>
                      </select>
                    </div>

                    <Show when={sel().signed}>
                      <label class="flex items-center justify-between gap-2 cursor-pointer">
                        <span style={{ color: "var(--c-text-sec)" }}>
                          Lock by SHA-256 hash instead of signer
                        </span>
                        <input
                          type="checkbox"
                          checked={forceHash()}
                          onChange={(e) =>
                            setForceHash(e.currentTarget.checked)
                          }
                          class="w-4 h-4 cursor-pointer"
                        />
                      </label>
                    </Show>

                    <div>
                      <label
                        for="curb-adv-dns"
                        class="block mb-1"
                        style={{ color: "var(--c-text-sec)" }}
                      >
                        DNS whitelist (optional)
                      </label>
                      <input
                        id="curb-adv-dns"
                        value={dnsText()}
                        onInput={(e) => setDnsText(e.currentTarget.value)}
                        placeholder="Leave blank for any destination IP"
                        class="w-full px-2.5 py-1.5 rounded-md font-mono text-xs"
                        style={{
                          background: "var(--c-bg)",
                          border: "1px solid var(--c-border-strong)",
                          color: "var(--c-text)",
                        }}
                      />
                    </div>

                    <div
                      class="pt-2 font-mono text-xs truncate"
                      style={{
                        "border-top": "1px solid var(--c-border)",
                        color: "var(--c-text-muted)",
                      }}
                    >
                      {sel().path}
                    </div>
                  </div>
                </Show>

                <div class="flex items-center justify-end gap-2">
                  <button
                    type="button"
                    onClick={props.onCancel}
                    class="px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
                    style={{ color: "var(--c-text-sec)" }}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={handleConfirm}
                    class="px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer"
                    style={{ background: "var(--c-accent)", color: "#ffffff" }}
                  >
                    Allow {sel().name}
                  </button>
                </div>
              </>
            );
          }}
        </Show>
      </div>
    </div>
  );
}
