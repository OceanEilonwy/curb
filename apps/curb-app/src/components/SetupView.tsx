import { createSignal, Show } from "solid-js";
import { CheckIcon, ShieldIcon, SpinnerIcon, WarnIcon } from "./Icons";

interface SetupViewProps {
  onSelectFull: () => Promise<void>;
  onSelectStandard: (password: string) => Promise<void>;
}

export function SetupView(props: SetupViewProps) {
  const [choice, setChoice] = createSignal<"full" | "standard">("full");
  const [password, setPassword] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  async function handleContinue(e: SubmitEvent) {
    e.preventDefault();
    setError(null);

    if (choice() === "standard") {
      if (password().length < 4) {
        setError("Choose a password with at least 4 characters.");
        return;
      }
      if (password() !== confirm()) {
        setError("Passwords do not match.");
        return;
      }
    }

    setBusy(true);
    try {
      if (choice() === "full") {
        await props.onSelectFull();
      } else {
        await props.onSelectStandard(password());
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      onSubmit={handleContinue}
      class="h-full w-full flex flex-col min-h-0"
      style={{ background: "var(--c-surface)", color: "var(--c-text)" }}
    >
      {/* Header */}
      <div
        class="px-5 pt-5 pb-4 shrink-0"
        style={{
          background: "var(--c-bg)",
          "border-bottom": "1px solid var(--c-border)",
        }}
      >
        <div class="flex items-center gap-2.5">
          <div
            class="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
            style={{
              background: "var(--c-green-soft)",
              color: "var(--c-green-text)",
            }}
          >
            <ShieldIcon mode="on" />
          </div>
          <div>
            <h1 class="text-sm font-bold" style={{ color: "var(--c-text)" }}>
              Welcome to Curb
            </h1>
            <p class="text-xs mt-0.5" style={{ color: "var(--c-text-sec)" }}>
              Choose how you want to set up protection on this PC.
            </p>
          </div>
        </div>
      </div>

      {/* Scrollable Option Cards */}
      <div
        class="flex-1 overflow-y-auto curb-scroll p-4 space-y-3 min-h-0"
        role="radiogroup"
        aria-label="Protection setup mode"
      >
        {/* Option 1: Full Protection */}
        <button
          type="button"
          role="radio"
          disabled={busy()}
          aria-checked={choice() === "full" ? "true" : "false"}
          onClick={() => {
            setChoice("full");
            setError(null);
          }}
          class="w-full text-left p-4 rounded-xl space-y-2 cursor-pointer transition-colors disabled:opacity-65"
          style={{
            background:
              choice() === "full" ? "var(--c-accent-soft)" : "var(--c-card)",
            border: `1.5px solid ${
              choice() === "full" ? "var(--c-focus)" : "var(--c-border)"
            }`,
          }}
        >
          <div class="flex items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <span
                class="text-[13px] font-bold"
                style={{ color: "var(--c-text)" }}
              >
                Full Protection
              </span>
              <span
                class="text-xs font-semibold px-2 py-0.5 rounded-full leading-none"
                style={{
                  background: "var(--c-green-soft)",
                  color: "var(--c-green-text)",
                }}
              >
                Recommended
              </span>
            </div>
            <span
              aria-hidden="true"
              class="w-5 h-5 rounded-full flex items-center justify-center shrink-0"
              style={{
                border: `2px solid ${
                  choice() === "full"
                    ? "var(--c-accent)"
                    : "var(--c-border-strong)"
                }`,
                background:
                  choice() === "full" ? "var(--c-accent)" : "transparent",
                color: "#ffffff",
              }}
            >
              <Show when={choice() === "full"}>
                <CheckIcon />
              </Show>
            </span>
          </div>

          <p class="text-xs leading-relaxed" style={{ color: "var(--c-text-sec)" }}>
            Blocks every app and game across all network adapters using the
            Windows Firewall. Standard users cannot turn it off or bypass it.
          </p>

          <div
            class="text-xs flex items-center gap-1.5 font-medium pt-0.5"
            style={{ color: "var(--c-green-text)" }}
          >
            <CheckIcon />
            <span>One-time Windows Administrator prompt during setup</span>
          </div>
        </button>

        {/* Option 2: Standard Mode (No Admin) */}
        <button
          type="button"
          role="radio"
          disabled={busy()}
          aria-checked={choice() === "standard" ? "true" : "false"}
          onClick={() => {
            setChoice("standard");
            setError(null);
          }}
          class="w-full text-left p-4 rounded-xl space-y-2 cursor-pointer transition-colors disabled:opacity-65"
          style={{
            background:
              choice() === "standard"
                ? "var(--c-accent-soft)"
                : "var(--c-card)",
            border: `1.5px solid ${
              choice() === "standard" ? "var(--c-focus)" : "var(--c-border)"
            }`,
          }}
        >
          <div class="flex items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <span
                class="text-[13px] font-bold"
                style={{ color: "var(--c-text)" }}
              >
                Standard Mode
              </span>
              <span
                class="text-xs font-semibold px-2 py-0.5 rounded-full leading-none"
                style={{
                  background: "var(--c-pill)",
                  color: "var(--c-text)",
                }}
              >
                No Admin
              </span>
            </div>
            <span
              aria-hidden="true"
              class="w-5 h-5 rounded-full flex items-center justify-center shrink-0"
              style={{
                border: `2px solid ${
                  choice() === "standard"
                    ? "var(--c-accent)"
                    : "var(--c-border-strong)"
                }`,
                background:
                  choice() === "standard" ? "var(--c-accent)" : "transparent",
                color: "#ffffff",
              }}
            >
              <Show when={choice() === "standard"}>
                <CheckIcon />
              </Show>
            </span>
          </div>

          <p class="text-xs leading-relaxed" style={{ color: "var(--c-text-sec)" }}>
            Starts immediately without a Windows Administrator account. Limits
            websites and browsers via a per-user proxy. You can upgrade to Full
            Protection later in Settings.
          </p>

          <div
            class="text-xs flex items-center gap-1.5 font-medium pt-0.5"
            style={{ color: "var(--c-amber-text)" }}
          >
            <WarnIcon />
            <span>Voluntary — can’t block raw game sockets or Task Manager</span>
          </div>
        </button>

        {/* Inline password fields when Standard Mode is selected */}
        <Show when={choice() === "standard"}>
          <div
            class="p-3.5 rounded-xl space-y-2.5"
            style={{
              background: "var(--c-card)",
              border: "1px solid var(--c-border)",
            }}
          >
            <div
              class="text-xs font-semibold"
              style={{ color: "var(--c-text)" }}
            >
              Create a Curb Password
            </div>
            <div>
              <label for="setup-pw" class="sr-only">
                Curb password
              </label>
              <input
                id="setup-pw"
                type="password"
                disabled={busy()}
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
                placeholder="New password (min 4 characters)"
                class="w-full px-3 py-2 rounded-lg text-xs disabled:opacity-60"
                style={{
                  background: "var(--c-surface)",
                  border: "1px solid var(--c-border-strong)",
                  color: "var(--c-text)",
                }}
              />
            </div>
            <div>
              <label for="setup-pw-confirm" class="sr-only">
                Confirm password
              </label>
              <input
                id="setup-pw-confirm"
                type="password"
                disabled={busy()}
                value={confirm()}
                onInput={(e) => setConfirm(e.currentTarget.value)}
                placeholder="Confirm password"
                class="w-full px-3 py-2 rounded-lg text-xs disabled:opacity-60"
                style={{
                  background: "var(--c-surface)",
                  border: "1px solid var(--c-border-strong)",
                  color: "var(--c-text)",
                }}
              />
            </div>
          </div>
        </Show>

        <Show when={error()}>
          {(msg) => (
            <p
              role="alert"
              class="text-xs font-medium px-1"
              style={{ color: "var(--c-red-text)" }}
            >
              {msg()}
            </p>
          )}
        </Show>
      </div>

      {/* Footer CTA */}
      <div
        class="px-5 py-3.5 shrink-0 flex items-center justify-between gap-2"
        style={{
          background: "var(--c-bg)",
          "border-top": "1px solid var(--c-border)",
        }}
      >
        <span class="text-xs" style={{ color: "var(--c-text-muted)" }}>
          {choice() === "full"
            ? "Will prompt for Windows Admin"
            : "Runs in your user account"}
        </span>
        <button
          type="submit"
          disabled={busy()}
          aria-busy={busy() ? "true" : "false"}
          class="px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer inline-flex items-center gap-1.5 disabled:opacity-60"
          style={{ background: "var(--c-accent)", color: "#ffffff" }}
        >
          <Show when={busy()}>
            <SpinnerIcon size={12} />
          </Show>
          <span>
            {busy()
              ? choice() === "full"
                ? "Installing Service…"
                : "Starting…"
              : choice() === "full"
              ? "Set Up Full Protection"
              : "Start Standard Mode"}
          </span>
        </button>
      </div>
    </form>
  );
}
