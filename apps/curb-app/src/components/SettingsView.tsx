import { createSignal, Show } from "solid-js";
import type { BaselinePolicy, EnforcementMode } from "../lib/types";
import { Switch } from "./Switch";

interface SettingsViewProps {
  unlocked: boolean;
  passwordConfigured: boolean;
  mode: EnforcementMode;
  baseline: BaselinePolicy;
  theme: "dark" | "light";
  onRequireUnlock: () => void;
  onToggleTheme: () => void;
  onSetMode: (mode: EnforcementMode) => void;
  onUpdateBaseline: (baseline: BaselinePolicy) => void;
  onChangePassword: (current: string, next: string) => Promise<void>;
}

export function SettingsView(props: SettingsViewProps) {
  const [advOpen, setAdvOpen] = createSignal(false);
  const [pwOpen, setPwOpen] = createSignal(false);
  const [currentPw, setCurrentPw] = createSignal("");
  const [newPw, setNewPw] = createSignal("");
  const [confirmPw, setConfirmPw] = createSignal("");
  const [showPw, setShowPw] = createSignal(false);
  const [pwBusy, setPwBusy] = createSignal(false);
  const [pwError, setPwError] = createSignal<string | null>(null);

  const isOn = () => props.mode.kind === "enforcing";
  const isPaused = () => props.mode.kind === "paused_until";
  const isOff = () => props.mode.kind === "disabled";

  function handleTogglePwForm() {
    if (!props.unlocked) {
      props.onRequireUnlock();
      return;
    }
    setPwError(null);
    setCurrentPw("");
    setNewPw("");
    setConfirmPw("");
    setShowPw(false);
    setPwOpen((v) => !v);
  }

  async function submitPasswordChange(e: SubmitEvent) {
    e.preventDefault();
    setPwError(null);

    if (props.passwordConfigured && currentPw().length === 0) {
      setPwError("Enter your current Curb password.");
      return;
    }
    if (newPw().length < 4) {
      setPwError("New password must be at least 4 characters.");
      return;
    }
    if (newPw() !== confirmPw()) {
      setPwError("New passwords do not match.");
      return;
    }

    setPwBusy(true);
    try {
      await props.onChangePassword(currentPw(), newPw());
      setCurrentPw("");
      setNewPw("");
      setConfirmPw("");
      setShowPw(false);
      setPwOpen(false);
    } catch (err) {
      setPwError(err instanceof Error ? err.message : String(err));
    } finally {
      setPwBusy(false);
    }
  }

  return (
    <div class="space-y-3">
      {/* Protection Switch */}
      <div
        class="p-3.5 rounded-xl space-y-2.5"
        style={{
          background: "var(--c-card)",
          border: "1px solid var(--c-border)",
        }}
      >
        <div>
          <div
            class="text-[13px] font-semibold"
            style={{ color: "var(--c-text)" }}
          >
            Internet Protection
          </div>
          <div class="text-xs mt-0.5" style={{ color: "var(--c-text-sec)" }}>
            Blocks all apps except the ones you’ve allowed
          </div>
        </div>
        <div class="grid grid-cols-3 gap-2 text-xs">
          <button
            type="button"
            disabled={!props.unlocked}
            onClick={() => props.onSetMode({ kind: "enforcing" })}
            class="py-2 rounded-lg font-semibold cursor-pointer disabled:opacity-55"
            style={{
              background: isOn() ? "var(--c-green-solid)" : "var(--c-surface)",
              color: isOn() ? "#ffffff" : "var(--c-text)",
              border: "1px solid var(--c-border-strong)",
            }}
          >
            On
          </button>
          <button
            type="button"
            disabled={!props.unlocked}
            onClick={() =>
              props.onSetMode({
                kind: "paused_until",
                until: new Date(Date.now() + 15 * 60_000).toISOString(),
              })
            }
            class="py-2 rounded-lg font-semibold cursor-pointer disabled:opacity-55"
            style={{
              background: isPaused()
                ? "var(--c-amber-solid)"
                : "var(--c-surface)",
              color: isPaused() ? "var(--c-amber-on-solid)" : "var(--c-text)",
              border: "1px solid var(--c-border-strong)",
            }}
          >
            Pause 15m
          </button>
          <button
            type="button"
            disabled={!props.unlocked}
            onClick={() => props.onSetMode({ kind: "disabled" })}
            class="py-2 rounded-lg font-semibold cursor-pointer disabled:opacity-55"
            style={{
              background: isOff() ? "var(--c-red-solid)" : "var(--c-surface)",
              color: isOff() ? "#ffffff" : "var(--c-text)",
              border: "1px solid var(--c-border-strong)",
            }}
          >
            Off
          </button>
        </div>
      </div>

      {/* Theme */}
      <div
        class="p-3.5 rounded-xl flex items-center justify-between gap-2"
        style={{
          background: "var(--c-card)",
          border: "1px solid var(--c-border)",
        }}
      >
        <div>
          <div
            class="text-[13px] font-semibold"
            style={{ color: "var(--c-text)" }}
          >
            Appearance
          </div>
          <div class="text-xs" style={{ color: "var(--c-text-sec)" }}>
            Dark or light theme
          </div>
        </div>
        <button
          type="button"
          onClick={props.onToggleTheme}
          class="px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
          style={{ background: "var(--c-pill)", color: "var(--c-text)" }}
        >
          Switch to {props.theme === "dark" ? "Light" : "Dark"}
        </button>
      </div>

      {/* Curb Admin Password */}
      <div
        class="p-3.5 rounded-xl space-y-2.5"
        style={{
          background: "var(--c-card)",
          border: "1px solid var(--c-border)",
        }}
      >
        <div class="flex items-center justify-between gap-2">
          <div>
            <div
              class="text-[13px] font-semibold"
              style={{ color: "var(--c-text)" }}
            >
              Curb Password
            </div>
            <div class="text-xs" style={{ color: "var(--c-text-sec)" }}>
              Protects your rules &amp; pause controls
            </div>
          </div>
          <button
            type="button"
            onClick={handleTogglePwForm}
            class="px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
            style={{ background: "var(--c-pill)", color: "var(--c-text)" }}
          >
            {pwOpen() && props.unlocked ? "Cancel" : "Change"}
          </button>
        </div>

        <Show when={pwOpen() && props.unlocked}>
          <form
            onSubmit={submitPasswordChange}
            class="space-y-2.5 pt-2"
            style={{ "border-top": "1px solid var(--c-border)" }}
          >
            <Show when={props.passwordConfigured}>
              <div>
                <label
                  for="curb-pw-current"
                  class="block text-xs font-medium mb-1"
                  style={{ color: "var(--c-text-sec)" }}
                >
                  Current password
                </label>
                <input
                  id="curb-pw-current"
                  type={showPw() ? "text" : "password"}
                  autocomplete="current-password"
                  value={currentPw()}
                  onInput={(e) => setCurrentPw(e.currentTarget.value)}
                  placeholder="Enter current password"
                  class="w-full px-3 py-2 rounded-lg text-xs"
                  style={{
                    background: "var(--c-surface)",
                    border: "1px solid var(--c-border-strong)",
                    color: "var(--c-text)",
                  }}
                />
              </div>
            </Show>

            <div>
              <label
                for="curb-pw-new"
                class="block text-xs font-medium mb-1"
                style={{ color: "var(--c-text-sec)" }}
              >
                New password
              </label>
              <input
                id="curb-pw-new"
                type={showPw() ? "text" : "password"}
                autocomplete="new-password"
                value={newPw()}
                onInput={(e) => setNewPw(e.currentTarget.value)}
                placeholder="At least 4 characters"
                class="w-full px-3 py-2 rounded-lg text-xs"
                style={{
                  background: "var(--c-surface)",
                  border: "1px solid var(--c-border-strong)",
                  color: "var(--c-text)",
                }}
              />
            </div>

            <div>
              <label
                for="curb-pw-confirm"
                class="block text-xs font-medium mb-1"
                style={{ color: "var(--c-text-sec)" }}
              >
                Confirm new password
              </label>
              <input
                id="curb-pw-confirm"
                type={showPw() ? "text" : "password"}
                autocomplete="new-password"
                value={confirmPw()}
                onInput={(e) => setConfirmPw(e.currentTarget.value)}
                placeholder="Re-enter new password"
                class="w-full px-3 py-2 rounded-lg text-xs"
                style={{
                  background: "var(--c-surface)",
                  border: "1px solid var(--c-border-strong)",
                  color: "var(--c-text)",
                }}
              />
            </div>

            <Show when={pwError()}>
              {(msg) => (
                <p
                  role="alert"
                  class="text-xs font-medium"
                  style={{ color: "var(--c-red-text)" }}
                >
                  {msg()}
                </p>
              )}
            </Show>

            <div class="flex items-center justify-between pt-1">
              <label
                class="inline-flex items-center gap-1.5 text-xs cursor-pointer"
                style={{ color: "var(--c-text-sec)" }}
              >
                <input
                  type="checkbox"
                  checked={showPw()}
                  onChange={(e) => setShowPw(e.currentTarget.checked)}
                  class="w-3.5 h-3.5 cursor-pointer"
                />
                <span>Show passwords</span>
              </label>

              <button
                type="submit"
                disabled={pwBusy()}
                class="px-3.5 py-1.5 rounded-lg text-xs font-semibold cursor-pointer disabled:opacity-60"
                style={{ background: "var(--c-accent)", color: "#ffffff" }}
              >
                {pwBusy() ? "Updating…" : "Update Password"}
              </button>
            </div>
          </form>
        </Show>
      </div>

      {/* Collapsible Advanced Settings */}
      <div
        class="rounded-xl overflow-hidden"
        style={{
          background: "var(--c-card)",
          border: "1px solid var(--c-border)",
        }}
      >
        <button
          type="button"
          aria-expanded={advOpen() ? "true" : "false"}
          onClick={() => setAdvOpen((v) => !v)}
          class="w-full px-3.5 py-2.5 flex items-center justify-between text-xs font-semibold cursor-pointer"
          style={{ color: "var(--c-text)" }}
        >
          <span>Advanced Settings</span>
          <span style={{ color: "var(--c-text-sec)" }}>
            {advOpen() ? "Hide" : "Show"}
          </span>
        </button>

        <Show when={advOpen()}>
          <div
            class="p-3.5 space-y-3 text-xs"
            style={{
              "border-top": "1px solid var(--c-border)",
              background: "var(--c-surface)",
            }}
          >
            <div class="font-semibold" style={{ color: "var(--c-text-sec)" }}>
              Windows System Essentials (WFP Baseline)
            </div>

            <div class="flex items-center justify-between gap-2">
              <div>
                <div class="font-semibold">DHCP</div>
                <div style={{ color: "var(--c-text-muted)" }}>
                  Wi-Fi &amp; Ethernet IP assignment
                </div>
              </div>
              <Switch
                checked={props.baseline.dhcp}
                disabled={!props.unlocked}
                label="DHCP"
                onChange={() =>
                  props.onUpdateBaseline({
                    ...props.baseline,
                    dhcp: !props.baseline.dhcp,
                  })
                }
              />
            </div>

            <div class="flex items-center justify-between gap-2">
              <div>
                <div class="font-semibold">Loopback</div>
                <div style={{ color: "var(--c-text-muted)" }}>
                  127.0.0.1 / ::1 local app IPC
                </div>
              </div>
              <Switch
                checked={props.baseline.loopback}
                disabled={!props.unlocked}
                label="Loopback"
                onChange={() =>
                  props.onUpdateBaseline({
                    ...props.baseline,
                    loopback: !props.baseline.loopback,
                  })
                }
              />
            </div>

            <div class="flex items-center justify-between gap-2">
              <div>
                <div class="font-semibold">NTP Time Sync</div>
                <div style={{ color: "var(--c-text-muted)" }}>
                  Clock accuracy for HTTPS certificates
                </div>
              </div>
              <Switch
                checked={props.baseline.ntp}
                disabled={!props.unlocked}
                label="NTP Time Sync"
                onChange={() =>
                  props.onUpdateBaseline({
                    ...props.baseline,
                    ntp: !props.baseline.ntp,
                  })
                }
              />
            </div>

            <div class="flex items-center justify-between gap-2">
              <div>
                <div class="font-semibold">Windows NCSI</div>
                <div style={{ color: "var(--c-text-muted)" }}>
                  Prevents false &ldquo;No Internet&rdquo; icon
                </div>
              </div>
              <Switch
                checked={props.baseline.ncsi}
                disabled={!props.unlocked}
                label="Windows NCSI"
                onChange={() =>
                  props.onUpdateBaseline({
                    ...props.baseline,
                    ncsi: !props.baseline.ncsi,
                  })
                }
              />
            </div>

            <div
              class="pt-2.5 text-xs font-mono space-y-0.5"
              style={{
                "border-top": "1px solid var(--c-border)",
                color: "var(--c-text-muted)",
              }}
            >
              <div>Firewall: Windows Filtering Platform (IPv4/IPv6)</div>
              <div>Adapter DNS: 127.0.0.1 (auto-restored when off)</div>
              <div>Admin recovery: curb-cli set-password</div>
            </div>
          </div>
        </Show>
      </div>
    </div>
  );
}
