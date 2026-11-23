import { createSignal, Show } from "solid-js";
import { SpinnerIcon } from "./Icons";

interface UnlockModalProps {
  open: boolean;
  passwordConfigured: boolean;
  onClose: () => void;
  onUnlock: (password: string) => Promise<void>;
}

export function UnlockModal(props: UnlockModalProps) {
  const [password, setPassword] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    setError(null);
    if (!props.passwordConfigured) {
      if (password().length < 4) {
        setError("Password must be at least 4 characters.");
        return;
      }
      if (password() !== confirm()) {
        setError("Passwords do not match.");
        return;
      }
    }
    setBusy(true);
    try {
      await props.onUnlock(password());
      setPassword("");
      setConfirm("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Show when={props.open}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="unlock-dialog-title"
        class="fixed inset-0 z-30 flex items-center justify-center p-5"
        style={{ background: "rgba(0,0,0,0.60)", "backdrop-filter": "blur(3px)" }}
      >
        <form
          onSubmit={handleSubmit}
          class="w-full max-w-[330px] rounded-xl p-4 shadow-2xl space-y-3"
          style={{
            background: "var(--c-surface)",
            border: "1px solid var(--c-border-strong)",
          }}
        >
          <div>
            <h2
              id="unlock-dialog-title"
              class="text-sm font-semibold"
              style={{ color: "var(--c-text)" }}
            >
              {props.passwordConfigured
                ? "Enter Curb Password"
                : "Set Curb Admin Password"}
            </h2>
            <p class="text-xs mt-1" style={{ color: "var(--c-text-sec)" }}>
              {props.passwordConfigured
                ? "Needed to change allowed apps or pause protection."
                : "Choose a password to protect your rules and pause controls."}
            </p>
          </div>

          <div class="space-y-2">
            <div>
              <label for="curb-unlock-input" class="sr-only">
                Curb password
              </label>
              <input
                id="curb-unlock-input"
                type="password"
                autofocus
                disabled={busy()}
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
                placeholder={
                  props.passwordConfigured
                    ? "Password"
                    : "New password (min 4 characters)"
                }
                class="w-full px-3 py-2 rounded-lg text-xs disabled:opacity-60"
                style={{
                  background: "var(--c-sub)",
                  border: "1px solid var(--c-border-strong)",
                  color: "var(--c-text)",
                }}
              />
            </div>

            <Show when={!props.passwordConfigured}>
              <div>
                <label for="curb-unlock-confirm" class="sr-only">
                  Confirm password
                </label>
                <input
                  id="curb-unlock-confirm"
                  type="password"
                  disabled={busy()}
                  value={confirm()}
                  onInput={(e) => setConfirm(e.currentTarget.value)}
                  placeholder="Confirm password"
                  class="w-full px-3 py-2 rounded-lg text-xs disabled:opacity-60"
                  style={{
                    background: "var(--c-sub)",
                    border: "1px solid var(--c-border-strong)",
                    color: "var(--c-text)",
                  }}
                />
              </div>
            </Show>

            <Show when={error()}>
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
          </div>

          <div class="flex justify-end gap-2">
            <button
              type="button"
              disabled={busy()}
              onClick={() => {
                setError(null);
                setPassword("");
                setConfirm("");
                props.onClose();
              }}
              class="px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer disabled:opacity-55"
              style={{ color: "var(--c-text-sec)" }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy()}
              aria-busy={busy() ? "true" : "false"}
              class="px-3.5 py-1.5 rounded-lg text-xs font-semibold cursor-pointer inline-flex items-center gap-1.5 disabled:opacity-60"
              style={{ background: "var(--c-accent)", color: "#ffffff" }}
            >
              <Show when={busy()}>
                <SpinnerIcon size={12} />
              </Show>
              <span>
                {busy()
                  ? "Checking…"
                  : props.passwordConfigured
                  ? "Unlock"
                  : "Set Password"}
              </span>
            </button>
          </div>
        </form>
      </div>
    </Show>
  );
}
