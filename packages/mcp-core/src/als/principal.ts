import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Who a request was admitted as, when a transport authenticated it with something stronger than "reached the
 * socket". Today only the HTTP transport's studio (GitHub-token) gate sets it, to `github:<numeric id>`.
 *
 * This is deliberately a SECOND store, separate from the per-tool-call `ToolRequestContext`: the transport knows
 * the principal before any MCP handling exists, while `ToolRequestContext` is created inside the SDK's
 * `tools/call` handler. The store holds one opaque identifier string and nothing else: never a token, an
 * assertion or a claim set. The audit middleware reads it and copies it onto the AuditEvent; when no transport
 * set it (stdio, flag off, shared-secret or Access-fronted requests) nothing is copied and the event is
 * byte-identical to what it was before this store existed.
 */
const principalStore = new AsyncLocalStorage<string>();

/** Run `fn` with `principal` visible to everything it awaits. A blank principal is a programming error. */
export function runWithPrincipal<T>(principal: string, fn: () => T): T {
  if (typeof principal !== 'string' || principal.trim() === '') {
    throw new TypeError('runWithPrincipal: principal must be a non-empty string');
  }
  return principalStore.run(principal, fn);
}

/** The principal the current request was admitted as, or `undefined` when none was established. */
export function tryGetPrincipal(): string | undefined {
  return principalStore.getStore();
}
