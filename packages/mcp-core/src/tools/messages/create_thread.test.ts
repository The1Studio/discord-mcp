import { server } from '@discord-mcp/server-mocks';
import { REST } from '@discordjs/rest';
import { container } from '@sapphire/pieces';
import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import messagesCreateThread from './create_thread.js';
import '../../container.js';

const DISCORD_API = 'https://discord.com/api/v10';

describe('messages_create_thread', () => {
  it('POSTs to threads endpoint and returns thread_id', async () => {
    container.rest = new REST({ version: '10', makeRequest: fetch }).setToken('fake-token-aaaaaa');
    server.use(
      http.post(
        `${DISCORD_API}/channels/:channelId/messages/:messageId/threads`,
        async ({ params }) =>
          HttpResponse.json({
            id: '999000999000999111',
            name: 'Discussion',
            parent_id: params.channelId,
            type: 11,
          }),
      ),
    );
    const T = messagesCreateThread;
    const t = new T(
      { name: 'messages_create_thread', path: 'inline', root: 'inline', store: null as never },
      { name: 'messages_create_thread', enabled: true },
    );
    const r = (await t.run(
      {
        channel_id: '111122223333444401',
        message_id: '999000999000999000',
        name: 'Discussion',
        auto_archive_duration: 1440,
      },
      { signal: new AbortController().signal },
    )) as {
      isError: boolean;
      structuredContent: { thread_id: string; name: string };
    };
    expect(r.isError).toBe(false);
    expect(r.structuredContent.thread_id).toBe('999000999000999111');
    expect(r.structuredContent.name).toBe('Discussion');
  });

  const makeTool = () =>
    new messagesCreateThread(
      { name: 'messages_create_thread', path: 'inline', root: 'inline', store: null as never },
      { name: 'messages_create_thread', enabled: true },
    );
  const ctx = () => ({ signal: new AbortController().signal });

  it('without message_id POSTs to /channels/{id}/threads as a public thread', async () => {
    container.rest = new REST({ version: '10', makeRequest: fetch }).setToken('fake-token-aaaaaa');
    let body: Record<string, unknown> | undefined;
    server.use(
      http.post(`${DISCORD_API}/channels/:channelId/threads`, async ({ params, request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          id: '999000999000999222',
          name: 'Standalone',
          parent_id: params.channelId,
          type: 11,
        });
      }),
    );
    const r = (await makeTool().run(
      { channel_id: '111122223333444401', name: 'Standalone', auto_archive_duration: 1440 },
      ctx(),
    )) as { isError: boolean; structuredContent: { thread_id: string; parent_id: string } };
    expect(r.isError).toBe(false);
    expect(r.structuredContent.thread_id).toBe('999000999000999222');
    expect(r.structuredContent.parent_id).toBe('111122223333444401');
    expect(body).toEqual({ name: 'Standalone', auto_archive_duration: 1440, type: 11 });
  });

  it('standalone private thread forwards type 12 and invitable', async () => {
    container.rest = new REST({ version: '10', makeRequest: fetch }).setToken('fake-token-aaaaaa');
    let body: Record<string, unknown> | undefined;
    server.use(
      http.post(`${DISCORD_API}/channels/:channelId/threads`, async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ id: '999000999000999333', name: 'Priv', type: 12 });
      }),
    );
    const r = (await makeTool().run(
      { channel_id: '111122223333444401', name: 'Priv', type: 12, invitable: false },
      ctx(),
    )) as { isError: boolean };
    expect(r.isError).toBe(false);
    expect(body).toMatchObject({ type: 12, invitable: false });
  });

  it('rejects standalone-only options on an anchored call', async () => {
    await expect(
      makeTool().run(
        { channel_id: '111122223333444401', message_id: '999000999000999000', name: 'x', type: 12 },
        ctx(),
      ),
    ).rejects.toThrow('Input validation failed');
  });
});
