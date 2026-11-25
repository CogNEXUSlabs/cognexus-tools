/**
 * Whether the agent id a decide carries is one this host announced.
 *
 * The hosted service denies an agent id its account has not declared, and a
 * Bot is declared under the id `announce` sent: a profile's folder name, or
 * the name the operator set. Nothing on a shared computer tells this command
 * which Bot is calling, so the Bot gives its id on each call, and a Bot has
 * given its display name with its title, and the product's name.
 *
 * Two readings, both made before the engine is asked:
 *   - an announced id followed by a title is sent as the announced id;
 *   - any other id this host did not announce is sent as given, with a note.
 * A host with no profiles and no recorded announce has nothing to compare
 * with, and nothing is said. The engine's answer is never changed here.
 */

import { listProfileAgentIds, resolveSandRoot } from "./profiles.js";
import {
  announceScope,
  announceStateKey,
  announcedNames,
  readEnrollState,
  type EnrollState,
} from "./state.js";

export interface AgentIdCheck {
  /** The id the decide sends. */
  agentDid: string;
  /** True when `agentDid` is an announced id that replaced the given one. */
  replaced: boolean;
  /** What to tell the caller. Absent when the given id is an announced one. */
  note?: string;
}

/**
 * What separates a name from a title: a mark set off by a space before it
 * (`Mira · Research lead`, `Mira - lead`, `Mira (lead)`), or a comma or a
 * colon with a space after it. `Mira-2`, `Mira/eu` and `probe:latency` are
 * ids of their own, and so is `Mira B`.
 */
const TITLE_AFTER_ID = /^(?:\s+[·•|–—\-/([]|[,:]\s)/u;

/** How many announced ids a note lists. */
const MAX_LISTED = 12;
const MAX_SHOWN_LEN = 80;

/** A name as a note prints it: bounded, and with no control or format character. */
function plain(name: string): string {
  return Array.from(name).slice(0, MAX_SHOWN_LEN).join("").replace(/[\p{Cc}\p{Cf}]/gu, "?");
}

function quoted(name: string): string {
  return JSON.stringify(plain(name));
}

/**
 * The announced id `given` starts with, when what follows it reads as a
 * title. Undefined when none fits, and when more than one does.
 */
export function announcedIdUnderTitle(given: string, announced: readonly string[]): string | undefined {
  const fits = announced.filter(
    (id) => id.length > 0 && given.startsWith(id) && TITLE_AFTER_ID.test(given.slice(id.length)),
  );
  return fits.length === 1 ? fits[0] : undefined;
}

/** The id to send for `given`, read against the ids this host announced. */
export function checkAgentId(given: string, announced: readonly string[]): AgentIdCheck {
  if (announced.length === 0 || announced.includes(given)) {
    return { agentDid: given, replaced: false };
  }
  const under = announcedIdUnderTitle(given, announced);
  if (under !== undefined) {
    return {
      agentDid: under,
      replaced: true,
      note:
        `agent id ${quoted(given)} is not one this host announced. This decide is sent as ` +
        `${quoted(under)}, the announced id it starts with. Use ${quoted(under)} as the agent id.`,
    };
  }
  const listed = announced.slice(0, MAX_LISTED).map(plain).join(", ");
  const rest = announced.length - MAX_LISTED;
  return {
    agentDid: given,
    replaced: false,
    note:
      `agent id ${quoted(given)} is not a profile on this host or an id grokbot-artzain announce ` +
      `recorded here (those are: ${listed}${rest > 0 ? ` and ${rest} more` : ""}). The hosted service ` +
      "denies an agent id its account has not declared. Use your announced id. If this id is " +
      "the one meant, the person who runs this Bot lists it with grokbot-artzain announce.",
  };
}

/**
 * The ids this host announces: its profiles, then the names `announce`
 * recorded for this base URL and key that are not profiles.
 */
export function announcedAgentIds(input: {
  sandRoot: string;
  state: EnrollState | null;
  baseUrl: string;
  apiKey?: string;
}): string[] {
  const ids = listProfileAgentIds(input.sandRoot);
  if (input.apiKey) {
    for (const name of announcedNames(input.state, announceScope(input.baseUrl, input.apiKey))) {
      if (!ids.includes(name)) ids.push(name);
    }
  }
  return ids;
}

/**
 * `checkAgentId` against this host's profiles and state file. Never throws:
 * what cannot be read is "nothing to compare with", and the id is sent as
 * given.
 */
export async function agentIdForDecide(input: {
  given: string;
  env?: NodeJS.ProcessEnv;
  apiKey?: string;
  baseUrl: string;
  /** With it, an announce 0.1.11 or earlier recorded (a hash, no name) counts. */
  instance?: string;
}): Promise<AgentIdCheck> {
  const asGiven: AgentIdCheck = { agentDid: input.given, replaced: false };
  try {
    const state = input.apiKey ? await readEnrollState() : null;
    const announced = announcedAgentIds({
      sandRoot: resolveSandRoot(input.env ?? process.env),
      state,
      baseUrl: input.baseUrl,
      apiKey: input.apiKey,
    });
    if (announced.includes(input.given)) return asGiven;
    if (
      input.apiKey &&
      input.instance &&
      state?.announces[announceStateKey(input.baseUrl, input.apiKey, input.instance, input.given)]
    ) {
      return asGiven;
    }
    return checkAgentId(input.given, announced);
  } catch {
    return asGiven;
  }
}
