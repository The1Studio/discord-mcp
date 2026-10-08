import { server } from '@discord-mcp/server-mocks';
import { REST } from '@discordjs/rest';
import { container } from '@sapphire/pieces';
import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { resolveToolAccessRequirement } from '../../access/requirements.js';
import messagesSend from './send.js';
import '../../container.js';

const DISCORD_API = 'https://discord.com/api/v10';
const CHANNEL = '112233445566778899';

function useRest(): void {
  container.rest = new REST({ version: '10', makeRequest: fetch }).setToken(
    'fake.test.token-abcdefghijklmnopqrstuvwxyz',
  );
}

function sendTool() {
  return new messagesSend(
    { name: 'messages_send', path: 'memory', root: 'memory', store: null as never },
    { name: 'messages_send', enabled: true },
  );
}

function signal() {
  return { signal: new AbortController().signal };
}

describe('messages_send tool', () => {
  it('returns dualResult with message_id, jump_url, timestamp on success', async () => {
    // Use global fetch so msw can intercept (undici bypasses msw's ClientRequest/fetch interceptors)
    container.rest = new REST({ version: '10', makeRequest: fetch }).setToken(
      'fake.test.token-abcdefghijklmnopqrstuvwxyz',
    );

    const ToolCls = messagesSend;
    const instance = new ToolCls(
      { name: 'messages_send', path: 'memory', root: 'memory', store: null as never },
      { name: 'messages_send', enabled: true },
    );

    const result = await instance.run(
      { channel_id: '112233445566778899', content: 'hello world' },
      { signal: new AbortController().signal },
    );

    expect(result).toMatchObject({
      isError: false,
      structuredContent: {
        message_id: '999000999000999000',
        channel_id: '112233445566778899',
        timestamp: '2026-04-28T12:00:00.000000+00:00',
      },
    });
    const data = (result as { structuredContent: { jump_url: string } }).structuredContent;
    expect(data.jump_url).toMatch(
      /^https:\/\/discord\.com\/channels\/999000999000999000\/112233445566778899\/999000999000999000$/,
    );
  });

  it('rejects empty-string content via zod', async () => {
    const instance = new messagesSend(
      { name: 'messages_send', path: 'memory', root: 'memory', store: null as never },
      { name: 'messages_send', enabled: true },
    );
    const { z } = await import('zod');
    const parsed = z.object(instance.inputSchema).safeParse({ channel_id: CHANNEL, content: '' });
    expect(parsed.success).toBe(false);
  });

  it('rejects a message with neither content nor attachments before calling Discord', async () => {
    useRest();
    let called = false;
    server.use(
      http.post(`${DISCORD_API}/channels/:channelId/messages`, () => {
        called = true;
        return HttpResponse.json({});
      }),
    );
    await expect(sendTool().run({ channel_id: CHANNEL }, signal())).rejects.toMatchObject({
      code: 'VALIDATION_FAILED',
    });
    expect(called).toBe(false);
  });

  it('references pre-uploaded files by uploaded_filename and allows no content', async () => {
    useRest();
    let sentBody: Record<string, unknown> | undefined;
    server.use(
      http.post(`${DISCORD_API}/channels/:channelId/messages`, async ({ params, request }) => {
        sentBody = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          id: '999000999000999001',
          channel_id: params.channelId,
          guild_id: '999000999000999000',
          content: '',
          timestamp: '2026-09-27T12:00:00.000000+00:00',
        });
      }),
    );
    const r = await sendTool().run(
      {
        channel_id: CHANNEL,
        attachments: [
          {
            id: 0,
            filename: 'strip.png',
            uploaded_filename: 'uuid-a/strip.png',
            description: 'three frames',
          },
        ],
      },
      signal(),
    );
    expect(r).toMatchObject({ isError: false });
    expect(sentBody).toEqual({
      tts: false,
      attachments: [
        {
          id: '0',
          filename: 'strip.png',
          uploaded_filename: 'uuid-a/strip.png',
          description: 'three frames',
        },
      ],
    });
  });

  it('names ATTACH_FILES when Discord rejects an attachment message with 50013', async () => {
    useRest();
    server.use(
      http.post(`${DISCORD_API}/channels/:channelId/messages`, () =>
        HttpResponse.json({ code: 50013, message: 'Missing Permissions' }, { status: 403 }),
      ),
    );
    await expect(
      sendTool().run(
        {
          channel_id: CHANNEL,
          content: 'see file',
          attachments: [{ id: '0', filename: 'a.png', uploaded_filename: 'u/a.png' }],
        },
        signal(),
      ),
    ).rejects.toMatchObject({ code: 'DISCORD_PERMISSION_DENIED', missing: ['ATTACH_FILES'] });
  });

  it('requires ATTACH_FILES only when the payload carries attachments', () => {
    expect(
      resolveToolAccessRequirement('messages_send', { channel_id: CHANNEL, content: 'hi' })
        ?.permissions,
    ).toEqual(['VIEW_CHANNEL', 'SEND_MESSAGES']);
    expect(
      resolveToolAccessRequirement('messages_send', {
        channel_id: CHANNEL,
        attachments: [{ id: '0', filename: 'a.png', uploaded_filename: 'u/a.png' }],
      })?.permissions,
    ).toEqual(['VIEW_CHANNEL', 'SEND_MESSAGES', 'ATTACH_FILES']);
  });
});
