/**
 * Newline-delimited JSON-RPC for the MCP server. A message that does not
 * parse is a parse error, and the line itself is not kept: it can carry a
 * key.
 */

export interface RpcRequest {
  method: string;
  params?: unknown;
  id: string | number;
}

export interface RpcNotification {
  method: string;
  params?: unknown;
}

export type RpcMessage =
  | { kind: "request"; request: RpcRequest }
  | { kind: "notification"; notification: RpcNotification };

export interface RpcErrorBody {
  code: number;
  message: string;
}

export interface RpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: RpcErrorBody;
}

export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;

export function rpcResult(id: string | number, result: unknown): RpcResponse {
  return { jsonrpc: "2.0", id, result };
}

export function rpcError(id: string | number | null, code: number, message: string): RpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function idOf(value: unknown): string | number | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const id = (value as { id?: unknown }).id;
  if (typeof id === "string") return id;
  if (typeof id === "number" && Number.isFinite(id)) return id;
  return null;
}

/**
 * One JSON-RPC message. `ok: false` is a parse error or an invalid request.
 * The raw line is not returned with either.
 */
export function parseRpc(line: string):
  | { ok: true; message: RpcMessage }
  | { ok: false; id: string | number | null; code: number } {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return { ok: false, id: null, code: PARSE_ERROR };
  }
  const id = idOf(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, id, code: INVALID_REQUEST };
  }
  const row = value as { jsonrpc?: unknown; method?: unknown; params?: unknown; id?: unknown };
  if (row.jsonrpc !== "2.0" || typeof row.method !== "string" || row.method.length === 0) {
    return { ok: false, id, code: INVALID_REQUEST };
  }
  if ("id" in row) {
    if (id === null) return { ok: false, id: null, code: INVALID_REQUEST };
    return { ok: true, message: { kind: "request", request: { method: row.method, params: row.params, id } } };
  }
  return { ok: true, message: { kind: "notification", notification: { method: row.method, params: row.params } } };
}
