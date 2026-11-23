import { createEffect, createSignal, Show } from "solid-js";
import { SpinnerIcon } from "./Icons";

let nextPromptModalId = 0;

interface PromptModalProps {
  open: boolean;
  title: string;
  description?: string;
  label: string;
  placeholder?: string;
  initialValue?: string;
  submitLabel?: string;
  busyLabel?: string;
  mono?: boolean;
  onClose: () => void;
  onSubmit: (value: string) => Promise<void> | void;
}

export function PromptModal(props: PromptModalProps) {
  const modalId = ++nextPromptModalId;
  const titleId = `curb-prompt-title-${modalId}`;
  const inputId = `curb-prompt-input-${modalId}`;

  const [value, setValue] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  let inputRef: HTMLInputElement | undefined;

  createEffect(
    () => props.open,
    (open) => {
      if (!open) return;
      setValue(props.initialValue ?? "");
      setError(null);
      queueMicrotask(() => {
        inputRef?.focus();
        inputRef?.select();
      });

      const onKeyDown = (e: KeyboardEvent) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          e.preventDefault();
          if (!busy()) {
            props.onClose();
          }
        }
      };

      window.addEventListener("keydown", onKeyDown, true);
      return () => window.removeEventListener("keydown", onKeyDown, true);
    }
  );

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (busy()) return;
    const trimmed = value().trim();
    if (!trimmed) {
      setError("Please enter a value.");
      return;
    }

    setError(null);
    setBusy(true);
    try {
      await props.onSubmit(trimmed);
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
        aria-labelledby={titleId}
        onClick={(e) => {
          if (e.target === e.currentTarget && !busy()) {
            props.onClose();
          }
        }}
        class="fixed inset-0 z-30 flex items-center justify-center p-5"
        style={{
          background: "rgba(0,0,0,0.60)",
          "backdrop-filter": "blur(3px)",
        }}
      >
        <form
          onSubmit={handleSubmit}
          class="w-full max-w-[360px] rounded-xl p-4 shadow-2xl space-y-3"
          style={{
            background: "var(--c-surface)",
            border: "1px solid var(--c-border-strong)",
          }}
        >
          <div>
            <h2
              id={titleId}
              class="text-sm font-semibold"
              style={{ color: "var(--c-text)" }}
            >
              {props.title}
            </h2>
            <Show when={props.description}>
              {(desc) => (
                <p class="text-xs mt-1" style={{ color: "var(--c-text-sec)" }}>
                  {desc()}
                </p>
              )}
            </Show>
          </div>

          <div class="space-y-2">
            <div>
              <label for={inputId} class="sr-only">
                {props.label}
              </label>
              <input
                ref={inputRef}
                id={inputId}
                type="text"
                disabled={busy()}
                value={value()}
                onInput={(e) => {
                  setValue(e.currentTarget.value);
                  if (error()) setError(null);
                }}
                placeholder={props.placeholder}
                class={`w-full px-3 py-2 rounded-lg text-xs disabled:opacity-60 ${
                  props.mono ? "font-mono" : ""
                }`}
                style={{
                  background: "var(--c-sub)",
                  border: "1px solid var(--c-border-strong)",
                  color: "var(--c-text)",
                }}
              />
            </div>

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
              onClick={() => props.onClose()}
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
                  ? props.busyLabel ?? "Saving…"
                  : props.submitLabel ?? "OK"}
              </span>
            </button>
          </div>
        </form>
      </div>
    </Show>
  );
}
