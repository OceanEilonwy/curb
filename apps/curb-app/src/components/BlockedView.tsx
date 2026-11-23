import { For, Show } from "solid-js";
import type { BlockedEvent } from "../lib/types";
import { SpinnerIcon } from "./Icons";

interface BlockedViewProps {
  events: BlockedEvent[];
  allowingId: string | null;
  onAllowEvent: (event: BlockedEvent) => void;
}

function formatRelative(iso: string): string {
  const diffSec = Math.max(
    0,
    Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  );
  if (diffSec < 45) return "Just now";
  const mins = Math.floor(diffSec / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ago`;
}

export function BlockedView(props: BlockedViewProps) {
  return (
    <Show
      when={props.events.length > 0}
      fallback={
        <div
          class="text-center py-12 text-xs"
          style={{ color: "var(--c-text-muted)" }}
        >
          Nothing blocked recently.
        </div>
      }
    >
      <div class="space-y-3">
        <p class="text-xs px-0.5" style={{ color: "var(--c-text-sec)" }}>
          Apps that recently tried to go online. Helpful when setting up a new
          game.
        </p>
        <div class="space-y-2">
          <For each={props.events}>
            {(ev) => {
              const isAllowing = () => props.allowingId === ev.id;
              return (
                <div
                  class="px-3.5 py-2.5 rounded-xl flex items-center justify-between gap-2"
                  style={{
                    background: "var(--c-card)",
                    border: "1px solid var(--c-border)",
                  }}
                >
                  <div class="min-w-0">
                    <div
                      class="text-[13px] font-semibold truncate"
                      style={{ color: "var(--c-text)" }}
                    >
                      {ev.app_name}{" "}
                      <span
                        class="font-normal text-xs"
                        style={{ color: "var(--c-text-muted)" }}
                      >
                        &middot; {formatRelative(ev.timestamp)}
                      </span>
                    </div>
                    <div
                      class="text-xs truncate mt-0.5"
                      style={{ color: "var(--c-text-sec)" }}
                    >
                      Tried to reach{" "}
                      <span
                        class="font-medium"
                        style={{ color: "var(--c-text)" }}
                      >
                        {ev.destination}
                      </span>
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={props.allowingId !== null}
                    aria-busy={isAllowing() ? "true" : "false"}
                    onClick={() => props.onAllowEvent(ev)}
                    class="px-3 py-1.5 rounded-lg text-xs font-semibold shrink-0 cursor-pointer inline-flex items-center gap-1.5 disabled:opacity-60"
                    style={{
                      background: "var(--c-pill)",
                      color: "var(--c-text)",
                    }}
                  >
                    <Show when={isAllowing()}>
                      <SpinnerIcon size={12} />
                    </Show>
                    <span>{isAllowing() ? "Allowing…" : "Allow"}</span>
                  </button>
                </div>
              );
            }}
          </For>
        </div>
      </div>
    </Show>
  );
}
