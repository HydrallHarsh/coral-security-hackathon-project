/** HarborGuard personality — loading quips, easter eggs, and risk banter. */

export type InvestigationMode = "dep" | "policy" | "secrets" | "release" | "general";

export const MODE_META: Record<
  InvestigationMode,
  { label: string; emoji: string; color: string }
> = {
  dep: { label: "Dependency Risk", emoji: "📦", color: "#f5b731" },
  policy: { label: "Policy Violation", emoji: "📋", color: "#3dd68c" },
  secrets: { label: "Secrets Exposure", emoji: "🔑", color: "#a78bfa" },
  release: { label: "Release Safety", emoji: "🚀", color: "#60a5fa" },
  general: { label: "Investigation", emoji: "🔍", color: "#e8693f" },
};

/** Stable default for SSR — never use pickRandom() as initial React state. */
export const DEFAULT_LOADING_QUIP =
  "Connecting to intelligence sources…";

export const LOADING_QUIPS = [
  "Convincing npm to tell the truth…",
  "Asking lodash if it's feeling okay…",
  "Checking if axios is still sending thoughts and prayers…",
  "Politely interrogating package-lock.json…",
  "Cross-referencing CVEs like it's a crossword puzzle…",
  "Scanning for secrets like a raccoon in a dumpster…",
  "Reading org policies so you don't have to…",
  "Making Dependabot jealous…",
  "Running queries faster than your CI pipeline (probably)…",
  "Correlating evidence chains — no duct tape involved…",
  "Teaching Coral what 'ship it' really means…",
  "Checking if .env is a template or a cry for help…",
  "Calculating risk score — not your credit score…",
  "Waiting for GitHub code search to wake up from its nap…",
  "HarborGuard never sleeps. Unlike your on-call rotation.",
];

export const PIPELINE_QUIPS = [
  "Initializing investigation…",
  "Warming up Coral engines…",
  "Discovering what tools actually work today…",
  "Planning the attack — the defensive kind…",
  "Fetching manifest — hope it's not a monorepo maze…",
];

export const DEEP_SCAN_QUIPS = [
  "Deep scan mode — grab a coffee; we're doing archaeology on your lockfile.",
  "Still here? Good. So is every transitive dependency we could find.",
  "This isn't slow — it's thorough. Your future on-call will thank you.",
  "We've gone full Indiana Jones on your package tree. No artifact left behind.",
  "Query #{n} and counting — the harbor doesn't do shallow dives.",
  "If this were a podcast, we'd be on episode 12 of 'Who Hurt Your Dependencies?'",
  "Somewhere, a CVE database just got another workout. You're welcome.",
  "Deep scan: because 'we only use two packages' is always a lie.",
  "Still scanning. Your node_modules folder sends its regards.",
  "At this depth we start finding packages you forgot you had.",
  "Coffee break recommended. Snack optional. Regret never.",
  "We're not stuck — we're being aggressively comprehensive.",
  "Every package gets a background check. Every. Single. One.",
  "This is the security equivalent of reading the entire terms of service.",
  "Halfway through your dependency graph. The other half is judging the first half.",
  "OSV, GitHub, policies — we're collecting receipts like it's Black Friday.",
  "Deep scan motto: trust, but verify… then verify again.",
  "Your lockfile has layers. We're peeling them like an onion. Might cry.",
  "If you're still watching this spinner, you're our kind of paranoid.",
  "Almost done. (Famous last words of every thorough security scan.)",
];

export const MODE_LOADING_QUIPS: Record<InvestigationMode, readonly string[]> = {
  dep: [
    "Dependency mode: every package is guilty until proven patched.",
    "Tracing the supply chain like it's a crime documentary.",
    "Checking if your upgrades fixed anything or just moved the CVEs around.",
  ],
  secrets: [
    "Secrets mode: hunting keys like they're Easter eggs (they shouldn't be).",
    "Scanning for .env files that weren't supposed to see daylight.",
    "If we find a live API key, we're telling you before Twitter does.",
  ],
  policy: [
    "Policy mode: reading the rulebook so your PR doesn't have to.",
    "Cross-checking changes against org policy — the fun kind of bureaucracy.",
    "Compliance isn't glamorous. This scan is still doing the work.",
  ],
  release: [
    "Release mode: answering 'can we ship?' with evidence, not vibes.",
    "Gatekeeping production — politely, with citations.",
    "Checking if production would survive this merge. Spoiler: we're thorough.",
  ],
  general: LOADING_QUIPS,
};

export type LoadingQuipContext = {
  mode?: InvestigationMode;
  queryCount: number;
  stepCount: number;
  latestQueryName?: string;
  latestProgress?: string;
  owner?: string;
  repo?: string;
};

function fillTemplate(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (_, key) => String(vars[key] ?? ""));
}

function repoLabel(owner?: string, repo?: string): string | null {
  if (!repo) return null;
  return owner ? `${owner}/${repo}` : repo;
}

function parseQueryTarget(name: string): { kind: string; label: string } {
  const lower = name.toLowerCase();
  const parts = name.split(":").map((p) => p.trim()).filter(Boolean);

  if (lower.includes("osv") || lower.startsWith("osv_")) {
    const pkg = parts[1] ?? "a package";
    const ver = parts[2];
    return { kind: "osv", label: ver ? `${pkg}@${ver}` : pkg };
  }
  if (lower.includes("secret") || lower.includes("credential") || lower.includes(".env")) {
    return { kind: "secrets", label: parts.slice(1).join(":") || "the repo" };
  }
  if (lower.includes("policy") || lower.includes("notion") || lower.includes("slack")) {
    return { kind: "policy", label: parts[1] ?? "org policy" };
  }
  if (lower.includes("github") || lower.includes("code_search") || lower.includes("search")) {
    return { kind: "github", label: parts.slice(1).join(":") || "GitHub" };
  }
  if (lower.includes("manifest") || lower.includes("package")) {
    return { kind: "manifest", label: parts[1] ?? "manifest" };
  }
  return { kind: "generic", label: name.length > 48 ? `${name.slice(0, 45)}…` : name };
}

const QUERY_QUIP_TEMPLATES: Record<string, readonly string[]> = {
  osv: [
    "Asking OSV whether {label} has any regrets from 2019…",
    "CVE speed-dating for {label} — swipe left on critical.",
    "Running {label} through the vulnerability gauntlet.",
    "OSV lookup on {label}: hope it's patched, fear it's not.",
  ],
  secrets: [
    "Secret sweep: {label} is not a safe place to hide keys.",
    "Sniffing around {label} for credentials that escaped.",
    "If {label} contains a token, we're about to have words.",
  ],
  policy: [
    "Policy check on {label} — bureaucracy with benefits.",
    "Does {label} violate the rulebook? Finding out.",
  ],
  github: [
    "GitHub recon on {label} — code search never sleeps.",
    "Digging through {label} like a very polite archaeologist.",
  ],
  manifest: [
    "Reading {label} — the Rosetta Stone of your dependencies.",
    "Manifest archaeology: {label} tells all (eventually).",
  ],
  generic: [
    "Running {label} — Coral is on the case.",
    "Query in flight: {label}",
  ],
};

const PROGRESS_ECHO_QUIPS: Array<{ match: RegExp; quips: readonly string[] }> = [
  {
    match: /starting investigation/i,
    quips: ["Investigation engaged. Seatbelts optional, evidence mandatory."],
  },
  {
    match: /discovering capabilities/i,
    quips: [
      "Rousing the integrations from their nap…",
      "Checking which tools are awake today — it's always a surprise.",
    ],
  },
  {
    match: /discovered \d+ available tools/i,
    quips: ["Toolkit assembled. Now the real questions begin."],
  },
  {
    match: /planning investigation/i,
    quips: ["Drawing the battle plan — strictly defensive, we promise."],
  },
  {
    match: /extracting manifest/i,
    quips: [
      "Manifest extraction in progress — pray it's not a monorepo labyrinth.",
      "Finding package.json (or twelve). Hold tight.",
    ],
  },
  {
    match: /deep scanning \d+ package/i,
    quips: [
      "Deep scan engaged — every target gets the full treatment.",
      "Package targets acquired. Nobody leaves without a CVE check.",
    ],
  },
  {
    match: /dynamic investigation loop/i,
    quips: [
      "Agent loop online — follow the evidence, not the vibes.",
      "Coral is thinking in public. Queries incoming.",
    ],
  },
  {
    match: /synthesizing findings/i,
    quips: [
      "Stitching findings into something your team can actually use…",
      "Almost there — turning chaos into a verdict.",
    ],
  },
];

function quipForProgress(latest?: string): string | null {
  if (!latest) return null;
  for (const { match, quips } of PROGRESS_ECHO_QUIPS) {
    if (match.test(latest)) return pickRandom(quips);
  }
  return null;
}

function quipForQuery(name?: string): string | null {
  if (!name) return null;
  const { kind, label } = parseQueryTarget(name);
  const pool = QUERY_QUIP_TEMPLATES[kind] ?? QUERY_QUIP_TEMPLATES.generic;
  return fillTemplate(pickRandom(pool), { label });
}

function quipForRepo(owner?: string, repo?: string): string | null {
  const label = repoLabel(owner, repo);
  if (!label) return null;
  return pickRandom([
    `Giving ${label} the full harbor inspection — no shortcuts.`,
    `${label} is getting more scrutiny than a production deploy on Friday.`,
    `Still working through ${label}. Patience beats postmortems.`,
    `Deep scan on ${label}: we're reading the fine print so you don't have to.`,
  ]);
}

export const RISK_QUIPS: Record<string, string[]> = {
  critical: [
    "Abort ship. Immediately. Like, yesterday.",
    "This repo needs a hug and a security audit.",
    "Production said 'absolutely not.'",
    "CVEs are having a party and you're not invited.",
  ],
  high: [
    "Not great, not terrible — mostly not great.",
    "Your dependencies are side-eyeing you.",
    "Deploy at your own peril (please don't).",
  ],
  medium: [
    "Some rough edges — worth a look before Friday deploy.",
    "Not clean, not catastrophic. Classic Tuesday.",
  ],
  low: [
    "Suspiciously quiet. Either clean or very good at hiding.",
    "Low risk detected. Don't let it go to your head.",
    "All clear — for now. Stay vigilant anyway.",
  ],
};

export const TAGLINE_ROTATION = [
  "Coral-powered investigation across GitHub, Slack, Notion, and vulnerability databases.",
  "Because 'it works on my machine' is not a security policy.",
  "Finding CVEs before your users find your postmortem.",
  "Your dependencies have secrets. We find those too.",
  "Ship with confidence — or at least with evidence.",
];

export const TITLE_EASTER_EGG_MESSAGES = [
  "🛡️ Achievement unlocked: Chief Vulnerability Officer",
  "⚓ HarborGuard has entered the chat.",
  "🐙 Coral says hi. It also says patch your deps.",
  "🔍 You've discovered the hidden harbor. No refunds.",
  "🏴‍☠️ Arr! That be a fine security posture, matey.",
  "🎣 Phishing for findings, not credentials.",
];

export const KONAMI_CODE = [
  "ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown",
  "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight",
  "KeyB", "KeyA",
];

export const KONAMI_MESSAGE = "🎮 Cheat code accepted. Unlimited investigations unlocked. (They were already unlimited.)";

export const DEMO_REPO = {
  owner: "HydrallHarsh",
  repo: "test-coral",
  org: "HydrallHarsh",
  label: "Sample: Coral Fleet API",
  desc: "Node service — try dependency, secrets, policy & release scans",
};

export const EMPTY_FINDINGS_QUIPS = [
  "Nothing here. Either you're secure or very lucky.",
  "Clean scan. Suspiciously clean…",
  "No findings. The harbor is calm.",
];

export function pickRandom<T>(items: readonly T[]): T {
  return items[Math.floor(Math.random() * items.length)];
}

export function detectMode(question: string): InvestigationMode {
  const q = question.toLowerCase();
  if (q.includes("secret") || q.includes("credential") || q.includes("token") || q.includes("leak")) {
    return "secrets";
  }
  if (q.includes("policy") || q.includes("compliance") || q.includes("violation")) {
    return "policy";
  }
  if (q.includes("release") || q.includes("deploy") || q.includes("production")) {
    return "release";
  }
  if (
    q.includes("dependency") || q.includes("package") || q.includes("cve") ||
    q.includes("vulnerability") || q.includes("upgrade")
  ) {
    return "dep";
  }
  return "general";
}

export function getRiskQuip(level: string | undefined): string {
  const key = (level ?? "low").toLowerCase();
  const pool = RISK_QUIPS[key] ?? RISK_QUIPS.low;
  return pickRandom(pool);
}

export function getLoadingQuip(ctx: LoadingQuipContext | number, stepCountLegacy?: number): string {
  const c: LoadingQuipContext =
    typeof ctx === "number"
      ? { queryCount: ctx, stepCount: stepCountLegacy ?? 0 }
      : ctx;

  const { queryCount, stepCount, mode = "general", latestQueryName, latestProgress, owner, repo } = c;

  // Early pipeline: echo backend progress when we have a fresh step message
  if (stepCount <= 4 && queryCount < 3) {
    const progress = quipForProgress(latestProgress);
    if (progress && Math.random() < 0.55) return progress;
  }

  // Mid/late scan: react to the latest query name when the feed is active
  if (queryCount >= 2 && latestQueryName && Math.random() < 0.42) {
    const q = quipForQuery(latestQueryName);
    if (q) return q;
  }

  if (queryCount > 15) {
    const deep = pickRandom(DEEP_SCAN_QUIPS);
    const withN = deep.includes("{n}")
      ? fillTemplate(deep, { n: queryCount })
      : deep;
    if (Math.random() < 0.28) {
      const repoQuip = quipForRepo(owner, repo);
      if (repoQuip) return repoQuip;
    }
    return withN;
  }

  if (queryCount > 8) {
    const modePool = MODE_LOADING_QUIPS[mode];
    if (modePool.length > 0 && Math.random() < 0.5) return pickRandom(modePool);
    return pickRandom(LOADING_QUIPS);
  }

  if (queryCount > 5 || stepCount > 3) return pickRandom(LOADING_QUIPS);
  return pickRandom(PIPELINE_QUIPS);
}

export function getCompletionQuip(riskLevel: string | undefined, findingCount: number): string {
  if (findingCount === 0) return pickRandom(EMPTY_FINDINGS_QUIPS);
  return getRiskQuip(riskLevel);
}
