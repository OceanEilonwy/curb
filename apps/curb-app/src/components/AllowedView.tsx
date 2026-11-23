import { createSignal, For, Show } from "solid-js";
import type { Rule, SteamPresetConfig, SubprocessPolicy } from "../lib/types";
import { isMatcherSigned, matcherDetail } from "../lib/types";
import { CheckIcon, ChevronDownIcon, SpinnerIcon, WarnIcon } from "./Icons";
import { PromptModal } from "./PromptModal";
import { Switch } from "./Switch";

interface AllowedViewProps {
  unlocked: boolean;
  steam: SteamPresetConfig;
  rules: Rule[];
  busySteam: boolean;
  busyRuleIds: Record<string, boolean>;
  deletingRuleId: string | null;
  onRequireUnlock: () => void;
  onUpdateSteam: (steam: SteamPresetConfig) => void;
  onUpdateRule: (rule: Rule) => void;
  onDeleteRule: (id: string) => void;
}

const STEAM_STORE_DOMAINS = [
  "store.steampowered.com",
  "checkout.steampowered.com",
  "login.steampowered.com",
  "api.steampowered.com",
  "*.steamstatic.com",
  "*.steamcontent.com",
];

export function AllowedView(props: AllowedViewProps) {
  const [expandedId, setExpandedId] = createSignal<string | null>("steam");
  const [advOpen, setAdvOpen] = createSignal<Record<string, boolean>>({});
  const [domainPromptRule, setDomainPromptRule] = createSignal<Rule | null>(
    null
  );

  function toggleExpand(id: string) {
    setExpandedId((prev) => (prev === id ? null : id));
  }

  function toggleAdv(id: string) {
    setAdvOpen((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  const isRuleBusy = (id: string) =>
    !!props.busyRuleIds[id] || props.deletingRuleId === id;

  const steamSummary = () => {
    if (!props.steam.enabled) return "Blocked";
    return [
      "Downloads",
      props.steam.store_and_library ? "Store" : null,
      props.steam.community_and_workshop ? "Community" : null,
      props.steam.friends_and_voice ? "Friends" : null,
    ]
      .filter(Boolean)
      .join(" · ");
  };

  const steamDomains = () => {
    const list: string[] = [];
    if (props.steam.store_and_library) list.push(...STEAM_STORE_DOMAINS);
    if (props.steam.community_and_workshop) {
      list.push("steamcommunity.com", "*.steamusercontent.com");
    }
    if (props.steam.friends_and_voice) {
      list.push("*.steam-chat.com");
    }
    return list;
  };

  function addDomain(rule: Rule) {
    if (!props.unlocked) {
      props.onRequireUnlock();
      return;
    }
    setDomainPromptRule(rule);
  }

  function handleAddDomainSubmit(domain: string) {
    const rule = domainPromptRule();
    if (!rule) return;
    const cleaned = domain.trim();
    if (!cleaned) {
      throw new Error("Please enter a website pattern.");
    }
    const current = rule.network.dns_whitelist ?? [];
    props.onUpdateRule({
      ...rule,
      network: {
        ...rule.network,
        dns_whitelist: [...current, cleaned],
      },
    });
    setDomainPromptRule(null);
  }

  function removeDomain(rule: Rule, index: number) {
    if (!props.unlocked) {
      props.onRequireUnlock();
      return;
    }
    const next = (rule.network.dns_whitelist ?? []).filter((_, i) => i !== index);
    props.onUpdateRule({
      ...rule,
      network: {
        ...rule.network,
        dns_whitelist: next.length ? next : null,
      },
    });
  }

  return (
    <div class="space-y-3">
      <p class="text-xs px-0.5" style={{ color: "var(--c-text-sec)" }}>
        Everything on this computer is offline unless it’s turned on below.
      </p>

      {/* Built-in Steam Preset Card */}
      <div
        class="rounded-xl overflow-hidden"
        style={{
          background: "var(--c-card)",
          border: "1px solid var(--c-border)",
        }}
      >
        <div class="px-3.5 py-2.5 flex items-center justify-between gap-2">
          <button
            type="button"
            aria-expanded={expandedId() === "steam" ? "true" : "false"}
            onClick={() => toggleExpand("steam")}
            class="min-w-0 flex-1 text-left cursor-pointer rounded-md py-0.5"
          >
            <div class="flex items-center gap-2">
              <span
                class="text-[13px] font-semibold"
                style={{ color: "var(--c-text)" }}
              >
                Steam
              </span>
              <span
                class="text-xs font-semibold px-2 py-0.5 rounded-full leading-none"
                style={{
                  background: "var(--c-accent-soft)",
                  color: "var(--c-accent-text)",
                }}
              >
                Built-in
              </span>
            </div>
            <div
              class="text-xs mt-1 truncate"
              style={{ color: "var(--c-text-muted)" }}
            >
              {steamSummary()}
            </div>
          </button>

          <div class="flex items-center gap-2.5 shrink-0">
            <Switch
              checked={props.steam.enabled}
              disabled={!props.unlocked || props.busySteam}
              label="Allow Steam"
              onChange={() =>
                props.onUpdateSteam({
                  ...props.steam,
                  enabled: !props.steam.enabled,
                })
              }
            />
            <button
              type="button"
              aria-label="Expand Steam options"
              aria-expanded={expandedId() === "steam" ? "true" : "false"}
              onClick={() => toggleExpand("steam")}
              class="w-7 h-7 rounded-md flex items-center justify-center cursor-pointer"
              style={{ color: "var(--c-text-sec)" }}
            >
              <ChevronDownIcon rotated={expandedId() === "steam"} />
            </button>
          </div>
        </div>

        <Show when={expandedId() === "steam"}>
          <div
            class="px-3.5 py-3 space-y-3 text-xs"
            style={{
              "border-top": "1px solid var(--c-border)",
              background: "var(--c-surface)",
            }}
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <div class="font-semibold" style={{ color: "var(--c-text)" }}>
                  Store &amp; Library
                </div>
                <div style={{ color: "var(--c-text-muted)" }}>
                  Browse store &amp; download games (blocks external links)
                </div>
              </div>
              <Switch
                checked={props.steam.store_and_library}
                disabled={!props.unlocked || props.busySteam}
                label="Steam Store and Library"
                onChange={() =>
                  props.onUpdateSteam({
                    ...props.steam,
                    store_and_library: !props.steam.store_and_library,
                  })
                }
              />
            </div>

            <div class="flex items-center justify-between gap-3">
              <div>
                <div class="font-semibold" style={{ color: "var(--c-text)" }}>
                  Community &amp; Workshop
                </div>
                <div style={{ color: "var(--c-text-muted)" }}>
                  Mods, guides, and forums
                </div>
              </div>
              <Switch
                checked={props.steam.community_and_workshop}
                disabled={!props.unlocked || props.busySteam}
                label="Steam Community and Workshop"
                onChange={() =>
                  props.onUpdateSteam({
                    ...props.steam,
                    community_and_workshop: !props.steam.community_and_workshop,
                  })
                }
              />
            </div>

            <div class="flex items-center justify-between gap-3">
              <div>
                <div class="font-semibold" style={{ color: "var(--c-text)" }}>
                  Friends &amp; Voice
                </div>
                <div style={{ color: "var(--c-text-muted)" }}>
                  Chat and voice with Steam friends
                </div>
              </div>
              <Switch
                checked={props.steam.friends_and_voice}
                disabled={!props.unlocked || props.busySteam}
                label="Steam Friends and Voice"
                onChange={() =>
                  props.onUpdateSteam({
                    ...props.steam,
                    friends_and_voice: !props.steam.friends_and_voice,
                  })
                }
              />
            </div>

            <div
              class="pt-2.5"
              style={{ "border-top": "1px solid var(--c-border)" }}
            >
              <button
                type="button"
                aria-expanded={advOpen()["steam"] ? "true" : "false"}
                onClick={() => toggleAdv("steam")}
                class="w-full flex items-center justify-between text-xs font-semibold cursor-pointer py-0.5"
                style={{ color: "var(--c-text-sec)" }}
              >
                <span>Advanced</span>
                <span>{advOpen()["steam"] ? "Hide" : "Show"}</span>
              </button>

              <Show when={advOpen()["steam"]}>
                <div
                  class="mt-2 p-2.5 rounded-lg space-y-2 text-xs font-mono"
                  style={{
                    background: "var(--c-bg)",
                    border: "1px solid var(--c-border-strong)",
                  }}
                >
                  <div style={{ color: "var(--c-text-sec)" }}>
                    steam.exe, steamservice.exe (Valve Corp. · TCP/UDP)
                  </div>
                  <div style={{ color: "var(--c-text-muted)" }}>
                    steamwebhelper.exe DNS whitelist:
                  </div>
                  <div class="flex flex-wrap gap-1.5">
                    <For each={steamDomains()}>
                      {(domain) => (
                        <span
                          class="px-2 py-0.5 rounded text-xs"
                          style={{
                            background: "var(--c-pill)",
                            color: "var(--c-text)",
                          }}
                        >
                          {domain}
                        </span>
                      )}
                    </For>
                  </div>
                </div>
              </Show>
            </div>
          </div>
        </Show>
      </div>

      {/* User Allowed Rules */}
      <div class="space-y-2">
        <For each={props.rules}>
          {(rule) => {
            const signed = () => isMatcherSigned(rule.matcher);
            const open = () => expandedId() === rule.id;
            const adv = () => !!advOpen()[rule.id];
            const busy = () => isRuleBusy(rule.id);
            const deleting = () => props.deletingRuleId === rule.id;

            return (
              <div
                class="rounded-xl overflow-hidden"
                style={{
                  background: "var(--c-card)",
                  border: "1px solid var(--c-border)",
                }}
              >
                <div class="px-3.5 py-2.5 flex items-center justify-between gap-2">
                  <button
                    type="button"
                    aria-expanded={open() ? "true" : "false"}
                    onClick={() => toggleExpand(rule.id)}
                    class="min-w-0 flex-1 text-left cursor-pointer rounded-md py-0.5"
                  >
                    <div
                      class="text-[13px] font-semibold truncate"
                      style={{ color: "var(--c-text)" }}
                    >
                      {rule.name}
                    </div>
                    <div
                      class="text-xs flex items-center gap-1.5 mt-0.5"
                      style={{
                        color: signed()
                          ? "var(--c-green-text)"
                          : "var(--c-amber-text)",
                      }}
                    >
                      {signed() ? <CheckIcon /> : <WarnIcon />}
                      <span class="truncate">
                        {signed()
                          ? "Updates automatically"
                          : "Needs re-approval after updates"}
                      </span>
                    </div>
                  </button>

                  <div class="flex items-center gap-2.5 shrink-0">
                    <Switch
                      checked={rule.enabled}
                      disabled={!props.unlocked || busy()}
                      label={`Allow ${rule.name}`}
                      onChange={() =>
                        props.onUpdateRule({ ...rule, enabled: !rule.enabled })
                      }
                    />
                    <button
                      type="button"
                      aria-label={`Expand ${rule.name} options`}
                      aria-expanded={open() ? "true" : "false"}
                      onClick={() => toggleExpand(rule.id)}
                      class="w-7 h-7 rounded-md flex items-center justify-center cursor-pointer"
                      style={{ color: "var(--c-text-sec)" }}
                    >
                      <ChevronDownIcon rotated={open()} />
                    </button>
                  </div>
                </div>

                <Show when={open()}>
                  <div
                    class="px-3.5 py-3 space-y-2.5 text-xs"
                    style={{
                      "border-top": "1px solid var(--c-border)",
                      background: "var(--c-surface)",
                    }}
                  >
                    <div class="flex items-center justify-between gap-3">
                      <div>
                        <div
                          class="font-semibold"
                          style={{ color: "var(--c-text)" }}
                        >
                          Allow helper apps
                        </div>
                        <div style={{ color: "var(--c-text-muted)" }}>
                          Lets launchers &amp; anti-cheat connect (blocks
                          browsers)
                        </div>
                      </div>
                      <Switch
                        checked={rule.subprocesses !== "disabled"}
                        disabled={!props.unlocked || busy()}
                        label={`Allow helper apps for ${rule.name}`}
                        onChange={() =>
                          props.onUpdateRule({
                            ...rule,
                            subprocesses:
                              rule.subprocesses === "disabled"
                                ? "same_signer_or_dir"
                                : "disabled",
                          })
                        }
                      />
                    </div>

                    <div
                      class="pt-2"
                      style={{ "border-top": "1px solid var(--c-border)" }}
                    >
                      <button
                        type="button"
                        aria-expanded={adv() ? "true" : "false"}
                        onClick={() => toggleAdv(rule.id)}
                        class="w-full flex items-center justify-between text-xs font-semibold cursor-pointer py-0.5"
                        style={{ color: "var(--c-text-sec)" }}
                      >
                        <span>Advanced</span>
                        <span>{adv() ? "Hide" : "Show"}</span>
                      </button>

                      <Show when={adv()}>
                        <div
                          class="mt-2 p-2.5 rounded-lg space-y-2.5 text-xs"
                          style={{
                            background: "var(--c-bg)",
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
                                disabled={!props.unlocked || busy()}
                                aria-pressed={rule.network.allow_tcp ? "true" : "false"}
                                onClick={() =>
                                  props.onUpdateRule({
                                    ...rule,
                                    network: {
                                      ...rule.network,
                                      allow_tcp: !rule.network.allow_tcp,
                                    },
                                  })
                                }
                                class="px-2.5 py-0.5 rounded font-semibold cursor-pointer disabled:opacity-55"
                                style={{
                                  background: rule.network.allow_tcp
                                    ? "var(--c-accent)"
                                    : "var(--c-pill)",
                                  color: rule.network.allow_tcp
                                    ? "#ffffff"
                                    : "var(--c-text)",
                                }}
                              >
                                TCP
                              </button>
                              <button
                                type="button"
                                disabled={!props.unlocked || busy()}
                                aria-pressed={rule.network.allow_udp ? "true" : "false"}
                                onClick={() =>
                                  props.onUpdateRule({
                                    ...rule,
                                    network: {
                                      ...rule.network,
                                      allow_udp: !rule.network.allow_udp,
                                    },
                                  })
                                }
                                class="px-2.5 py-0.5 rounded font-semibold cursor-pointer disabled:opacity-55"
                                style={{
                                  background: rule.network.allow_udp
                                    ? "var(--c-accent)"
                                    : "var(--c-pill)",
                                  color: rule.network.allow_udp
                                    ? "#ffffff"
                                    : "var(--c-text)",
                                }}
                              >
                                UDP
                              </button>
                            </div>
                          </div>

                          <div class="flex items-center justify-between gap-2">
                            <span style={{ color: "var(--c-text-sec)" }}>
                              Sub-process scope
                            </span>
                            <select
                              disabled={!props.unlocked || busy()}
                              value={rule.subprocesses}
                              onChange={(e) =>
                                props.onUpdateRule({
                                  ...rule,
                                  subprocesses: e.currentTarget
                                    .value as SubprocessPolicy,
                                })
                              }
                              class="rounded-md px-2 py-1 text-xs disabled:opacity-55"
                              style={{
                                background: "var(--c-surface)",
                                border: "1px solid var(--c-border-strong)",
                                color: "var(--c-text)",
                              }}
                            >
                              <option value="disabled">Disabled</option>
                              <option value="same_signer_or_dir">
                                Same signer or folder
                              </option>
                              <option value="any_except_restricted">
                                Any (except browsers/shells)
                              </option>
                            </select>
                          </div>

                          <div>
                            <div class="flex items-center justify-between mb-1">
                              <span style={{ color: "var(--c-text-sec)" }}>
                                DNS whitelist
                              </span>
                              <Show when={props.unlocked}>
                                <button
                                  type="button"
                                  disabled={busy()}
                                  onClick={() => addDomain(rule)}
                                  class="font-semibold cursor-pointer disabled:opacity-55"
                                  style={{ color: "var(--c-accent-text)" }}
                                >
                                  + Add
                                </button>
                              </Show>
                            </div>
                            <Show
                              when={
                                rule.network.dns_whitelist &&
                                rule.network.dns_whitelist.length > 0
                              }
                              fallback={
                                <span
                                  class="italic"
                                  style={{ color: "var(--c-text-muted)" }}
                                >
                                  Any destination IP allowed
                                </span>
                              }
                            >
                              <div class="flex flex-wrap gap-1.5">
                                <For each={rule.network.dns_whitelist ?? []}>
                                  {(domain, idx) => (
                                    <span
                                      class="px-2 py-0.5 rounded font-mono text-xs inline-flex items-center gap-1"
                                      style={{
                                        background: "var(--c-pill)",
                                        color: "var(--c-text)",
                                      }}
                                    >
                                      {domain}
                                      <Show when={props.unlocked}>
                                        <button
                                          type="button"
                                          disabled={busy()}
                                          aria-label={`Remove ${domain}`}
                                          onClick={() =>
                                            removeDomain(rule, idx())
                                          }
                                          class="cursor-pointer font-bold disabled:opacity-55"
                                        >
                                          &times;
                                        </button>
                                      </Show>
                                    </span>
                                  )}
                                </For>
                              </div>
                            </Show>
                          </div>

                          <div
                            class="pt-2 font-mono space-y-0.5"
                            style={{
                              "border-top": "1px solid var(--c-border)",
                              color: "var(--c-text-muted)",
                            }}
                          >
                            <div>File: {rule.exe_hint}</div>
                            <div>{matcherDetail(rule.matcher)}</div>
                          </div>
                        </div>
                      </Show>
                    </div>

                    <div class="flex items-center justify-between pt-1">
                      <span style={{ color: "var(--c-text-muted)" }}>
                        {rule.matcher.kind === "steam_game"
                          ? "Steam Game"
                          : "App"}
                      </span>
                      <Show
                        when={props.unlocked}
                        fallback={
                          <button
                            type="button"
                            onClick={props.onRequireUnlock}
                            class="font-semibold cursor-pointer hover:underline"
                            style={{ color: "var(--c-accent-text)" }}
                          >
                            Unlock to edit
                          </button>
                        }
                      >
                        <button
                          type="button"
                          disabled={busy()}
                          aria-busy={deleting() ? "true" : "false"}
                          onClick={() => props.onDeleteRule(rule.id)}
                          class="font-semibold cursor-pointer hover:underline inline-flex items-center gap-1.5 disabled:opacity-55"
                          style={{ color: "var(--c-red-text)" }}
                        >
                          <Show when={deleting()}>
                            <SpinnerIcon size={12} />
                          </Show>
                          <span>{deleting() ? "Removing…" : "Remove"}</span>
                        </button>
                      </Show>
                    </div>
                  </div>
                </Show>
              </div>
            );
          }}
        </For>
      </div>

      <PromptModal
        open={domainPromptRule() !== null}
        title="Add Allowed Website"
        description="Allow this app to connect to a specific domain or wildcard pattern."
        label="Website pattern"
        placeholder="*.example.com"
        submitLabel="Add"
        mono={true}
        onClose={() => setDomainPromptRule(null)}
        onSubmit={handleAddDomainSubmit}
      />
    </div>
  );
}
