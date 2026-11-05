/**
 * Which invocations ask for a decision, and the target each one names.
 * A GET, a read-only gh or aws call, and `rm -rf` under /tmp or /workspace
 * are not in that set. The target is `shell:host/<id>`.
 */

import { posix } from "node:path";

export interface ShimContext {
  cwd: string;
  env: NodeJS.ProcessEnv;
  home: string;
}

/** Absent `target` means this invocation runs with no decision. */
export interface ShimPlan {
  target?: string;
}

const CURL_VALUE = new Set(["X", "d", "F", "T", "H", "o", "O", "u", "A", "e", "b", "c", "x", "m", "y", "K", "E", "Q", "C", "D", "r", "z", "t", "w", ":"]);
const CURL_DATA = new Set(["data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "form", "form-string", "upload-file", "json"]);

const SSH_VALUE = new Set(["p", "i", "o", "l", "J", "L", "R", "D", "W", "b", "c", "F", "S", "w", "E", "B", "I", "m", "O", "Q"]);
const GIT_VALUE = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--exec-path"]);
const PUSH_VALUE = new Set(["-o", "--push-option", "--repo", "--receive-pack", "--exec", "--signed"]);

const GH_WRITE = new Set([
  "pr create", "pr merge", "pr close", "pr comment", "pr edit", "pr review", "pr ready", "pr reopen", "pr lock", "pr unlock",
  "issue create", "issue close", "issue comment", "issue edit", "issue delete", "issue reopen", "issue lock", "issue transfer",
  "release create", "release delete", "release upload", "release edit",
  "repo create", "repo delete", "repo edit", "repo archive", "repo unarchive", "repo fork", "repo rename", "repo sync",
  "gist create", "gist delete", "gist edit",
  "workflow run", "workflow enable", "workflow disable",
  "secret set", "secret delete",
  "variable set", "variable delete",
  "label create", "label delete", "label edit",
  "cache delete",
  "ssh-key add", "ssh-key delete",
  "gpg-key add", "gpg-key delete",
  "run cancel", "run rerun", "run delete",
  "alias set", "alias delete",
  "auth login", "auth logout", "auth refresh", "auth setup-git",
  "codespace create", "codespace delete", "codespace edit", "codespace stop", "codespace rebuild",
  "extension install", "extension upgrade", "extension remove",
]);

const GH_READ = new Set([
  "pr view", "pr status", "pr list", "pr checks", "pr diff",
  "issue view", "issue list", "issue status",
  "release view", "release list", "release download",
  "repo view", "repo list", "repo clone",
  "run view", "run list", "run watch",
  "workflow list", "workflow view",
  "secret list", "variable list", "label list",
  "auth status", "search", "status", "config get", "browse",
]);

const AWS_READ = /^(get-|list-|describe-|head-|lookup-|search-|batch-get-|wait$|help$)/;
const S3_READ = new Set(["ls", "presign"]);
const S3_WRITE = new Set(["cp", "mv", "rm", "sync", "mb", "rb"]);

function hostOf(raw: string): string {
  const text = raw.trim();
  const ssh = /^[^@/\s]+@([^:\s]+):/.exec(text);
  if (ssh && !text.includes("://")) return ssh[1] ?? text;
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`;
    const host = new URL(withScheme).hostname;
    return host || text;
  } catch {
    return text.split("/")[0] ?? text;
  }
}

function target(id: string): string {
  const cleaned = id.replace(/^\/+/, "").replace(/\/+$/, "") || "unknown";
  return `shell:host/${cleaned}`;
}

export function planShim(command: string, args: string[], ctx: ShimContext): ShimPlan {
  switch (command) {
    case "curl":
      return planCurl(args);
    case "wget":
      return planWget(args);
    case "git":
      return planGit(args);
    case "gh":
      return planGh(args, ctx.env);
    case "npm":
      return planNpm(args);
    case "aws":
      return planAws(args);
    case "ssh":
      return planSsh(args);
    case "scp":
      return planScp(args);
    case "rm":
      return planRm(args, ctx);
    default:
      return {};
  }
}

function planCurl(args: string[]): ShimPlan {
  let method = "";
  let data = false;
  let get = false;
  const urls: string[] = [];
  const take = (name: string, value: string | undefined) => {
    if (name === "request" || name === "X") method = (value ?? "").toUpperCase();
    else if (CURL_DATA.has(name) || name === "d" || name === "F" || name === "T") data = true;
    else if (name === "url" && value) urls.push(value);
  };
  walkOptions(args, {
    valueShort: CURL_VALUE,
    valueLong: new Set(["request", "url", "header", "output", "user", "user-agent", "referer", "cookie", "cookie-jar", "proxy", "connect-timeout", "max-time", "data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "form", "form-string", "upload-file", "json", "config", "write-out"]),
    onLong(name, value) {
      if (name === "get") get = true;
      if (name === "head") method = method || "HEAD";
      take(name, value);
    },
    onShort(name, value) {
      if (name === "G") get = true;
      if (name === "I") method = method || "HEAD";
      take(name, value);
    },
    onPositional(word) {
      urls.push(word);
    },
  });
  const explicit = method && method !== "GET";
  const implied = data && !get && method !== "GET";
  if (!explicit && !implied) return {};
  return { target: target(hostOf(urls[0] ?? "unknown")) };
}

function planWget(args: string[]): ShimPlan {
  let method = "";
  let data = false;
  const urls: string[] = [];
  walkOptions(args, {
    valueShort: new Set(["O", "o", "P", "t", "T", "w", "Q", "i", "B", "e"]),
    valueLong: new Set(["method", "post-data", "post-file", "body-data", "body-file", "output-document", "directory-prefix", "header", "user", "password", "timeout"]),
    onLong(name, value) {
      if (name === "method") method = (value ?? "").toUpperCase();
      if (name === "post-data" || name === "post-file" || name === "body-data" || name === "body-file") data = true;
    },
    onShort() {
      /* wget short options here take a value and do not set the method */
    },
    onPositional(word) {
      urls.push(word);
    },
  });
  if (method === "GET" || (!method && !data)) return {};
  return { target: target(hostOf(urls[0] ?? "unknown")) };
}

function planGit(args: string[]): ShimPlan {
  const rest: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const word = args[i] ?? "";
    if (word === "--") {
      rest.push(...args.slice(i + 1));
      break;
    }
    const bare = word.split("=", 1)[0] ?? word;
    if (word.startsWith("-")) {
      if (!word.includes("=") && GIT_VALUE.has(bare)) i += 1;
      continue;
    }
    rest.push(word, ...args.slice(i + 1));
    break;
  }
  if (rest[0] !== "push") return {};
  let remote = "";
  const pushArgs = rest.slice(1);
  for (let i = 0; i < pushArgs.length; i += 1) {
    const word = pushArgs[i] ?? "";
    if (word === "--") {
      remote = positionalRemote(pushArgs.slice(i + 1)) || remote;
      break;
    }
    const bare = word.split("=", 1)[0] ?? word;
    if (word.startsWith("-")) {
      if (bare === "--repo") remote = word.includes("=") ? word.slice(word.indexOf("=") + 1) : (pushArgs[i + 1] ?? remote);
      if (!word.includes("=") && PUSH_VALUE.has(bare)) i += 1;
      continue;
    }
    if (!remote) remote = word;
  }
  return { target: target(hostOf(remote || "origin")) };
}

function positionalRemote(words: string[]): string {
  for (const word of words) {
    if (!word.startsWith("-")) return word;
  }
  return "";
}

function planGh(args: string[], env: NodeJS.ProcessEnv): ShimPlan {
  let repo = "";
  let hostname = env.GH_HOST || "github.com";
  let method = "";
  let input = false;
  const words: string[] = [];
  walkOptions(args, {
    valueShort: new Set(["R", "X", "f", "F", "H"]),
    valueLong: new Set(["repo", "hostname", "method", "input", "raw-field", "field", "header", "jq", "template"]),
    onLong(name, value) {
      if (name === "repo" && value) repo = value;
      if (name === "hostname" && value) hostname = value;
      if (name === "method" && value) method = value.toUpperCase();
      if (name === "input" || name === "raw-field" || name === "field") input = true;
    },
    onShort(name, value) {
      if (name === "R" && value) repo = value;
      if (name === "X" && value) method = value.toUpperCase();
      if (name === "f" || name === "F") input = true;
    },
    onPositional(word) {
      words.push(word);
    },
  });
  if (words.length === 0 || words[0] === "help") return {};
  const key = words.slice(0, 2).join(" ");
  const apiWrite = words[0] === "api" && (input || (method !== "" && method !== "GET"));
  const write = GH_WRITE.has(key) || apiWrite;
  const read = GH_READ.has(key) || (words[0] === "api" && !apiWrite) || words[0] === "help";
  if (read && !write) return {};
  if (!write && read) return {};
  const id = repo ? `${hostname}/${repo}` : hostname;
  return { target: target(id) };
}

function planNpm(args: string[]): ShimPlan {
  let registry = "";
  let publish = false;
  walkOptions(args, {
    valueShort: new Set(["C"]),
    valueLong: new Set(["registry", "prefix", "userconfig", "cache", "otp", "tag", "access"]),
    onLong(name, value) {
      if (name === "registry" && value) registry = value;
    },
    onShort() {
      /* -C takes a directory and does not publish */
    },
    onPositional(word) {
      if (word === "publish") publish = true;
    },
  });
  if (!publish) return {};
  return { target: target(registry ? hostOf(registry) : "registry.npmjs.org") };
}

function planAws(args: string[]): ShimPlan {
  const words: string[] = [];
  walkOptions(args, {
    valueShort: new Set(),
    valueLong: new Set(["profile", "region", "output", "endpoint-url", "cli-read-timeout", "cli-connect-timeout", "ca-bundle", "query"]),
    onLong() {
      /* global flags are not the operation */
    },
    onShort() {
      /* aws has no short global flags that change the operation */
    },
    onPositional(word) {
      words.push(word);
    },
  });
  const service = words[0] ?? "";
  const operation = words[1] ?? "";
  if (!service || service === "help" || operation === "help") return {};
  if (service === "s3") {
    if (S3_READ.has(operation)) return {};
    if (S3_WRITE.has(operation) || operation !== "") return { target: target("s3") };
    return {};
  }
  if (AWS_READ.test(operation)) return {};
  if (!operation) return {};
  return { target: target(service) };
}

function planSsh(args: string[]): ShimPlan {
  const words: string[] = [];
  walkOptions(args, {
    valueShort: SSH_VALUE,
    valueLong: new Set(["port", "identity", "option", "login", "jump", "config", "proxycommand"]),
    onLong() {
      /* the destination is a positional word */
    },
    onShort() {
      /* the destination is a positional word */
    },
    onPositional(word) {
      words.push(word);
    },
  });
  const dest = words[0] ?? "";
  if (!dest) return { target: target("unknown") };
  const at = dest.lastIndexOf("@");
  return { target: target(at >= 0 ? dest.slice(at + 1) : dest) };
}

function planScp(args: string[]): ShimPlan {
  const words: string[] = [];
  walkOptions(args, {
    valueShort: new Set(["P", "i", "o", "l", "F", "S", "c"]),
    valueLong: new Set(["port", "identity", "option"]),
    onLong() {
      /* the remote spec is positional */
    },
    onShort() {
      /* the remote spec is positional */
    },
    onPositional(word) {
      words.push(word);
    },
  });
  for (const word of words) {
    const at = word.lastIndexOf("@");
    const colon = word.indexOf(":", at + 1);
    if (colon > 1) {
      const host = word.slice(at + 1, colon);
      if (host) return { target: target(host) };
    }
  }
  return { target: target("unknown") };
}

function planRm(args: string[], ctx: ShimContext): ShimPlan {
  let recursive = false;
  let force = false;
  const paths: string[] = [];
  const shorts = (cluster: string) => {
    if ([...cluster].some((ch) => ch === "r" || ch === "R")) recursive = true;
    if (cluster.includes("f")) force = true;
  };
  walkOptions(args, {
    valueShort: new Set(),
    valueLong: new Set(),
    onLong(name) {
      if (name === "recursive") recursive = true;
      if (name === "force") force = true;
    },
    onShort(name) {
      shorts(name);
    },
    onPositional(word) {
      paths.push(word);
    },
  });
  if (!recursive || !force) return {};
  for (const item of paths) {
    const resolved = resolveRmPath(item, ctx);
    if (!underSafeRoot(resolved)) return { target: target(resolved) };
  }
  return {};
}

function resolveRmPath(item: string, ctx: ShimContext): string {
  let path = item;
  if (path === "~" || path.startsWith("~/")) {
    path = `${ctx.home.replace(/\\/g, "/")}${path.slice(1)}`;
  }
  if (!path.startsWith("/")) path = `${ctx.cwd.replace(/\\/g, "/").replace(/\/+$/, "")}/${path}`;
  const norm = posix.normalize(path);
  return norm.startsWith("/") ? norm : `/${norm}`;
}

function underSafeRoot(path: string): boolean {
  return path === "/tmp" || path.startsWith("/tmp/") || path === "/workspace" || path.startsWith("/workspace/");
}

interface Walker {
  valueShort: Set<string>;
  valueLong: Set<string>;
  onLong: (name: string, value: string | undefined) => void;
  onShort: (name: string, value: string | undefined) => void;
  onPositional: (word: string) => void;
}

function walkOptions(args: string[], walker: Walker): void {
  let i = 0;
  while (i < args.length) {
    const word = args[i] ?? "";
    i += 1;
    if (word === "--") {
      for (const rest of args.slice(i)) walker.onPositional(rest);
      return;
    }
    if (word.startsWith("--")) {
      const body = word.slice(2);
      const eq = body.indexOf("=");
      const name = eq >= 0 ? body.slice(0, eq) : body;
      const inline = eq >= 0 ? body.slice(eq + 1) : undefined;
      const takes = walker.valueLong.has(name);
      const value = inline ?? (takes ? args[i++] : undefined);
      walker.onLong(name, value);
      continue;
    }
    if (word.startsWith("-") && word.length > 1) {
      const cluster = word.slice(1);
      for (let c = 0; c < cluster.length; c += 1) {
        const name = cluster[c] ?? "";
        if (walker.valueShort.has(name)) {
          const inline = cluster.slice(c + 1);
          const value = inline || args[i++];
          walker.onShort(name, value);
          break;
        }
        walker.onShort(name, undefined);
      }
      continue;
    }
    walker.onPositional(word);
  }
}
