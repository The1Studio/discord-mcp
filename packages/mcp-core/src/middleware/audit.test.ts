import { context, trace } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from '@opentelemetry/sdk-trace-base';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runWithCtx } from '../als/context.js';
import { runWithPrincipal } from '../als/principal.js';
import type { AuditEvent } from '../audit/schema.js';
import type { AuditSink } from '../audit/sink.js';
import { auditMiddleware } from './audit.js';
import type { MiddlewareContext } from './compose.js';

class CapturingSink implements AuditSink {
  readonly events: AuditEvent[] = [];
  async emit(event: AuditEvent): Promise<void> {
    this.events.push(event);
  }
}

const mutatingTool = {
  name: 'messages_send',
  category: 'messages',
  idempotent: false,
};

const readonlyTool = {
  name: 'messages_read',
  category: 'messages',
  idempotent: true,
};

const idempotentWriteTool = {
  name: 'channels_modify',
  category: 'channels',
  idempotent: true,
};

function makeCtx(
  tool: { name: string; category: string; idempotent: boolean },
  args: unknown = { channel_id: '111', content: 'hi' },
): MiddlewareContext<unknown> {
  return {
    tool,
    args,
    meta: new Map([
      [
        'toolPiece',
        {
          annotations: {
            readOnlyHint: tool === readonlyTool,
          },
        },
      ],
    ]),
  };
}

const TEST_REQUEST_CTX = {
  requestId: 'req-test-1',
  toolName: 'messages_send',
  transport: 'stdio' as const,
  signal: new AbortController().signal,
};

describe('auditMiddleware - mutating tools', () => {
  it('emits AuditEvent with status=success when next() returns isError=false', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    const result = await runWithCtx(TEST_REQUEST_CTX, () =>
      mw.onCallTool!(makeCtx(mutatingTool), async () => ({ isError: false, content: [] })),
    );
    expect(result).toEqual({ isError: false, content: [] });
    expect(sink.events).toHaveLength(1);
    const ev = sink.events[0]!;
    expect(ev.status).toBe('success');
    expect(ev.tool).toBe('messages_send');
    expect(ev.category).toBe('messages');
    expect(ev.idempotent).toBe(false);
    expect(ev.transport).toBe('stdio');
    expect(ev.request_id).toBe('req-test-1');
    // Phase F: messages_send.content is in SENSITIVE_KEYS_BY_TOOL → redacted
    // with length-aware marker. channel_id passes through.
    expect(ev.args_redacted).toEqual({ channel_id: '111', content: '[REDACTED:2ch]' });
    expect(ev.result_code).toBeUndefined();
    expect(typeof ev.duration_ms).toBe('number');
    // ISO-8601 timestamp shape (loose check).
    expect(ev.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  it('emits AuditEvent with status=tool_error and extracts code from structuredContent', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithCtx(TEST_REQUEST_CTX, () =>
      mw.onCallTool!(makeCtx(mutatingTool), async () => ({
        isError: true,
        content: [],
        structuredContent: { code: 'discord_not_found' },
      })),
    );
    expect(sink.events).toHaveLength(1);
    const ev = sink.events[0]!;
    expect(ev.status).toBe('tool_error');
    expect(ev.result_code).toBe('discord_not_found');
  });

  it('emits AuditEvent with status=thrown + result_code=error.name and re-throws', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    const boom = new TypeError('boom');
    await expect(
      runWithCtx(TEST_REQUEST_CTX, () =>
        mw.onCallTool!(makeCtx(mutatingTool), async () => {
          throw boom;
        }),
      ),
    ).rejects.toBe(boom);
    expect(sink.events).toHaveLength(1);
    const ev = sink.events[0]!;
    expect(ev.status).toBe('thrown');
    expect(ev.result_code).toBe('TypeError');
  });

  it('redacts globally sensitive top-level keys via redactArgs (length-aware marker)', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithCtx(TEST_REQUEST_CTX, () =>
      mw.onCallTool!(
        makeCtx(mutatingTool, { channel_id: '111', token: 'secret-bot-token' }),
        async () => ({ isError: false, content: [] }),
      ),
    );
    expect(sink.events[0]?.args_redacted).toEqual({
      channel_id: '111',
      token: '[REDACTED:16ch]',
    });
  });
});

describe('auditMiddleware - principal', () => {
  const ok = async () => ({ isError: false, content: [] });
  const stable = (event: AuditEvent) => {
    const { timestamp: _t, duration_ms: _d, ...rest } = event;
    return rest;
  };

  it('records the principal the transport established, for success, tool_error and thrown alike', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithPrincipal('github:1001', () =>
      runWithCtx(TEST_REQUEST_CTX, async () => {
        await mw.onCallTool!(makeCtx(mutatingTool), ok);
        await mw.onCallTool!(makeCtx(mutatingTool), async () => ({
          isError: true,
          content: [],
          structuredContent: { code: 'discord_not_found' },
        }));
        await expect(
          mw.onCallTool!(makeCtx(mutatingTool), async () => {
            throw new TypeError('boom');
          }),
        ).rejects.toThrow('boom');
      }),
    );
    expect(sink.events.map((e) => [e.status, e.principal])).toEqual([
      ['success', 'github:1001'],
      ['tool_error', 'github:1001'],
      ['thrown', 'github:1001'],
    ]);
  });

  it('every inner call of one request carries the principal (the mcp_pipeline shape: several calls, one request)', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithPrincipal('github:1002', () =>
      runWithCtx(TEST_REQUEST_CTX, async () => {
        for (let i = 0; i < 3; i += 1) await mw.onCallTool!(makeCtx(mutatingTool), ok);
      }),
    );
    expect(sink.events.map((e) => e.principal)).toEqual(Array(3).fill('github:1002'));
  });

  it('without a principal the field is ABSENT (not undefined, not empty) and the event keys are exactly the legacy set', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithCtx(TEST_REQUEST_CTX, () => mw.onCallTool!(makeCtx(mutatingTool), ok));
    const ev = sink.events[0]!;
    expect(Object.hasOwn(ev, 'principal')).toBe(false);
    expect('principal' in JSON.parse(JSON.stringify(ev))).toBe(false);
    // Golden: the serialised key set an audit record had before the field existed (no active span here).
    expect(Object.keys(ev).sort()).toEqual(
      [
        'args_redacted',
        'category',
        'duration_ms',
        'idempotent',
        'request_id',
        'status',
        'timestamp',
        'tool',
        'transport',
      ].sort(),
    );
  });

  it('the principal is the ONLY difference an admitted request makes to the record', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithCtx(TEST_REQUEST_CTX, () => mw.onCallTool!(makeCtx(mutatingTool), ok));
    await runWithPrincipal('github:1001', () =>
      runWithCtx(TEST_REQUEST_CTX, () => mw.onCallTool!(makeCtx(mutatingTool), ok)),
    );
    const [without, withPrincipal] = sink.events.map(stable);
    expect(withPrincipal).toEqual({ ...without, principal: 'github:1001' });
  });

  it('is not recorded for a read-only call (nothing is audited, so nothing can leak)', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithPrincipal('github:1001', () =>
      runWithCtx(TEST_REQUEST_CTX, () => mw.onCallTool!(makeCtx(readonlyTool), ok)),
    );
    expect(sink.events).toHaveLength(0);
  });
});

describe('auditMiddleware - read-only versus idempotent writes', () => {
  it('does NOT emit for explicitly read-only tools', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithCtx(TEST_REQUEST_CTX, () =>
      mw.onCallTool!(makeCtx(readonlyTool), async () => ({ isError: false, content: [] })),
    );
    expect(sink.events).toHaveLength(0);
  });

  it('does NOT emit for read-only tools even when next() throws', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await expect(
      runWithCtx(TEST_REQUEST_CTX, () =>
        mw.onCallTool!(makeCtx(readonlyTool), async () => {
          throw new Error('readonly boom');
        }),
      ),
    ).rejects.toThrow('readonly boom');
    expect(sink.events).toHaveLength(0);
  });

  it('emits for an idempotent write because it still changes Discord', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithCtx(TEST_REQUEST_CTX, () =>
      mw.onCallTool!(makeCtx(idempotentWriteTool), async () => ({ isError: false, content: [] })),
    );
    expect(sink.events).toHaveLength(1);
    expect(sink.events[0]).toMatchObject({ tool: 'channels_modify', idempotent: true });
  });
});

describe('auditMiddleware - trace correlation', () => {
  let spanExporter: InMemorySpanExporter;
  let tracerProvider: BasicTracerProvider;
  let ctxManager: AsyncLocalStorageContextManager;

  beforeEach(() => {
    spanExporter = new InMemorySpanExporter();
    tracerProvider = new BasicTracerProvider({
      spanProcessors: [new SimpleSpanProcessor(spanExporter)],
    });
    trace.setGlobalTracerProvider(tracerProvider);
    // Without a context manager, context.with() is a no-op and
    // trace.getActiveSpan() returns undefined inside the callback -
    // matching what NodeSDK installs at runtime.
    ctxManager = new AsyncLocalStorageContextManager();
    ctxManager.enable();
    context.setGlobalContextManager(ctxManager);
  });

  afterEach(async () => {
    context.disable();
    trace.disable();
    ctxManager.disable();
    await tracerProvider.shutdown();
  });

  it('captures trace_id/span_id when an active span exists', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    const tracer = trace.getTracer('test');
    const span = tracer.startSpan('parent');
    const otelCtx = trace.setSpan(context.active(), span);
    await context.with(otelCtx, () =>
      runWithCtx(TEST_REQUEST_CTX, () =>
        mw.onCallTool!(makeCtx(mutatingTool), async () => ({ isError: false, content: [] })),
      ),
    );
    span.end();

    const ev = sink.events[0]!;
    expect(ev.trace_id).toBeDefined();
    expect(ev.trace_id).toMatch(/^[0-9a-f]{32}$/);
    expect(ev.span_id).toBeDefined();
    expect(ev.span_id).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('auditMiddleware - no active span', () => {
  beforeEach(() => {
    trace.disable();
  });

  it('leaves trace_id and span_id undefined (NOT empty string) when no span is active', async () => {
    const sink = new CapturingSink();
    const mw = auditMiddleware(sink);
    await runWithCtx(TEST_REQUEST_CTX, () =>
      mw.onCallTool!(makeCtx(mutatingTool), async () => ({ isError: false, content: [] })),
    );
    const ev = sink.events[0]!;
    expect(ev.trace_id).toBeUndefined();
    expect(ev.span_id).toBeUndefined();
    // Confirm absence rather than presence-with-empty-string.
    expect(Object.hasOwn(ev, 'trace_id')).toBe(false);
    expect(Object.hasOwn(ev, 'span_id')).toBe(false);
  });
});

describe('auditMiddleware - sink failure isolation', () => {
  it('does not break tool execution when a custom sink.emit throws', async () => {
    const writeSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const failingSink: AuditSink = {
      async emit() {
        throw new Error('sink failure');
      },
    };
    const mw = auditMiddleware(failingSink);
    await expect(
      runWithCtx(TEST_REQUEST_CTX, () =>
        mw.onCallTool!(makeCtx(mutatingTool), async () => ({ isError: false, content: [] })),
      ),
    ).resolves.toMatchObject({ isError: false });
    expect(writeSpy).toHaveBeenCalledTimes(1);
    writeSpy.mockRestore();
  });
});
