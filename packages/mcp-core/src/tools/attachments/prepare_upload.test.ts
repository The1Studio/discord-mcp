import { server } from '@discord-mcp/server-mocks';
import { REST } from '@discordjs/rest';
import { container } from '@sapphire/pieces';
import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { getToolAccessRequirement } from '../../access/requirements.js';
import attachmentsPrepareUpload from './prepare_upload.js';
import '../../container.js';

const DISCORD_API = 'https://discord.com/api/v10';
const CHANNEL = '112233445566778899';

function tool() {
  container.rest = new REST({ version: '10', makeRequest: fetch }).setToken('fake-token-aaaaaa');
  const T = attachmentsPrepareUpload;
  return new T(
    { name: 'attachments_prepare_upload', path: 'inline', root: 'inline', store: null as never },
    { name: 'attachments_prepare_upload', enabled: true },
  );
}

describe('attachments_prepare_upload', () => {
  it('POSTs /channels/:id/attachments with indexed files and returns upload targets', async () => {
    let sentBody: unknown;
    server.use(
      http.post(`${DISCORD_API}/channels/:channelId/attachments`, async ({ request }) => {
        sentBody = await request.json();
        return HttpResponse.json({
          attachments: [
            {
              id: 0,
              upload_url: 'https://discord-attachments-uploads-prd.storage.googleapis.com/a?sig=1',
              upload_filename: 'uuid-a/strip.png',
            },
            {
              id: 1,
              upload_url: 'https://discord-attachments-uploads-prd.storage.googleapis.com/b?sig=2',
              upload_filename: 'uuid-b/run.gif',
            },
          ],
        });
      }),
    );

    const r = (await tool().run(
      {
        channel_id: CHANNEL,
        files: [
          { filename: 'strip.png', file_size: 55616 },
          { filename: 'run.gif', file_size: 54157 },
        ],
      },
      { signal: new AbortController().signal },
    )) as {
      isError: boolean;
      structuredContent: {
        attachments: {
          id: string;
          filename: string;
          upload_url: string;
          upload_filename: string;
        }[];
      };
    };

    expect(sentBody).toEqual({
      files: [
        { id: '0', filename: 'strip.png', file_size: 55616 },
        { id: '1', filename: 'run.gif', file_size: 54157 },
      ],
    });
    expect(r.isError).toBe(false);
    expect(r.structuredContent.attachments).toEqual([
      {
        id: '0',
        filename: 'strip.png',
        upload_url: 'https://discord-attachments-uploads-prd.storage.googleapis.com/a?sig=1',
        upload_filename: 'uuid-a/strip.png',
      },
      {
        id: '1',
        filename: 'run.gif',
        upload_url: 'https://discord-attachments-uploads-prd.storage.googleapis.com/b?sig=2',
        upload_filename: 'uuid-b/run.gif',
      },
    ]);
  });

  it('names ATTACH_FILES when Discord answers Missing Permissions (50013)', async () => {
    server.use(
      http.post(`${DISCORD_API}/channels/:channelId/attachments`, () =>
        HttpResponse.json({ code: 50013, message: 'Missing Permissions' }, { status: 403 }),
      ),
    );

    await expect(
      tool().run(
        { channel_id: CHANNEL, files: [{ filename: 'a.png', file_size: 10 }] },
        { signal: new AbortController().signal },
      ),
    ).rejects.toMatchObject({
      code: 'DISCORD_PERMISSION_DENIED',
      missing: ['ATTACH_FILES'],
    });
  });

  it('declares Attach Files in its channel access contract', () => {
    expect(getToolAccessRequirement('attachments_prepare_upload').requirement).toMatchObject({
      scope: 'channel',
      permissions: ['VIEW_CHANNEL', 'SEND_MESSAGES', 'ATTACH_FILES'],
    });
  });
});
