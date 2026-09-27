import { server } from '@discord-mcp/server-mocks';
import { REST } from '@discordjs/rest';
import { container } from '@sapphire/pieces';
import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { assessComponentsV2Payload } from '../../middleware/payload-confirmation.js';
import componentsV2Send from './send.js';
import '../../container.js';

describe('components_v2_send', () => {
  it('sets IS_COMPONENTS_V2 flag and returns message_id', async () => {
    container.rest = new REST({ version: '10', makeRequest: fetch }).setToken(
      'fake-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );
    const T = componentsV2Send;
    const t = new T(
      { name: 'components_v2_send', path: 'inline', root: 'inline', store: null as never },
      { name: 'components_v2_send', enabled: true },
    );
    const r = (await t.run(
      {
        channel_id: '112233445566778899',
        components: [{ type: 10, content: 'hi from V2' }],
      },
      { signal: new AbortController().signal },
    )) as {
      isError: boolean;
      structuredContent: {
        message_id: string;
        channel_id: string;
        component_count: number;
        jump_url: string;
      };
    };
    expect(r.isError).toBe(false);
    expect(r.structuredContent.message_id).toBe('999000999000999000');
    expect(r.structuredContent.component_count).toBe(1);
    expect(r.structuredContent.jump_url).toBe(
      'https://discord.com/channels/999000999000999000/112233445566778899/999000999000999000',
    );
  });

  it('rejects invalid layout offline (does not call Discord)', async () => {
    container.rest = new REST({ version: '10', makeRequest: fetch }).setToken('fake');
    const T = componentsV2Send;
    const t = new T(
      { name: 'components_v2_send', path: 'inline', root: 'inline', store: null as never },
      { name: 'components_v2_send', enabled: true },
    );
    // Container nested in Container is invalid
    await expect(
      t.run(
        {
          channel_id: '112233445566778899',
          components: [
            { type: 17, components: [{ type: 17, components: [{ type: 10, content: 'inner' }] }] },
          ],
        },
        { signal: new AbortController().signal },
      ),
    ).rejects.toThrow();
  });

  it('sends uploaded files alongside a MediaGallery that shows them via attachment://', async () => {
    container.rest = new REST({ version: '10', makeRequest: fetch }).setToken(
      'fake-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );
    let sentBody: Record<string, unknown> | undefined;
    server.use(
      http.post(
        'https://discord.com/api/v10/channels/:channelId/messages',
        async ({ params, request }) => {
          sentBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            id: '999000999000999002',
            channel_id: params.channelId,
            guild_id: '999000999000999000',
            flags: 1 << 15,
          });
        },
      ),
    );
    const components = [
      { type: 12, items: [{ media: { url: 'attachment://strip.png' }, description: 'frames' }] },
    ];
    const T = componentsV2Send;
    const t = new T(
      { name: 'components_v2_send', path: 'inline', root: 'inline', store: null as never },
      { name: 'components_v2_send', enabled: true },
    );
    const r = (await t.run(
      {
        channel_id: '112233445566778899',
        components,
        attachments: [{ id: '0', filename: 'strip.png', uploaded_filename: 'uuid-a/strip.png' }],
      },
      { signal: new AbortController().signal },
    )) as { isError: boolean };
    expect(r.isError).toBe(false);
    expect(sentBody).toEqual({
      flags: 1 << 15,
      components,
      attachments: [{ id: '0', filename: 'strip.png', uploaded_filename: 'uuid-a/strip.png' }],
    });
  });

  it('flags attachments in the payload review a human approves', () => {
    const flags = assessComponentsV2Payload('components_v2_send', {
      components: [{ type: 10, content: 'x' }],
      attachments: [{ id: '0', filename: 'a.png', uploaded_filename: 'u/a.png' }],
    }).riskFlags;
    expect(flags).toContain('attachments');
    expect(
      assessComponentsV2Payload('components_v2_send', { components: [{ type: 10, content: 'x' }] })
        .riskFlags,
    ).not.toContain('attachments');
  });
});
