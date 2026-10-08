import { container } from '@sapphire/pieces';
import { z } from 'zod';
import { rethrowAttachFilesDenied } from '../_lib/attachments.js';
import { defineTool } from '../_lib/defineTool.js';
import { dualResult } from '../_lib/response.js';
import { ChannelId } from '../_lib/snowflake.js';

/** Discord's per-file ceiling for bot uploads without a boosted guild tier. */
const MAX_FILE_BYTES = 500 * 1024 * 1024;

interface PreparedAttachment {
  id: number | string;
  upload_url: string;
  upload_filename: string;
}

export default defineTool({
  name: 'attachments_prepare_upload',
  category: 'attachments',
  description: [
    '**Purpose**: Get one-time upload URLs so a LOCAL file can be attached to a Discord message without passing its bytes through this server.',
    '',
    '**Flow** (3 steps):',
    '1. Call this tool with each file name and exact byte size.',
    "2. For each returned item, upload the raw bytes yourself: `curl -sS -X PUT -H 'Content-Type: application/octet-stream' --data-binary @<file> '<upload_url>'` and expect HTTP 200. The URL needs no bot token and expires quickly.",
    '3. Call `messages_send` (or `components_v2_send`) with `attachments:[{id, filename, uploaded_filename}]`, using `uploaded_filename` = the returned `upload_filename`. Components can show the file as `attachment://<filename>`.',
    '',
    '**Needs**: Attach Files + Send Messages in the target channel/thread.',
    '',
    '**Example**: `{channel_id:"112233445566778899", files:[{filename:"shot.png", file_size:55616}]}`',
    '',
    '**Returns**: `{attachments:[{id, filename, upload_url, upload_filename}], expires_hint}`.',
  ].join('\n'),
  inputSchema: {
    channel_id: ChannelId.describe('Channel or thread the files will be posted to'),
    files: z
      .array(
        z.object({
          filename: z.string().min(1).max(1024).describe('File name, including extension'),
          file_size: z
            .number()
            .int()
            .positive()
            .max(MAX_FILE_BYTES)
            .describe('Exact size in bytes of the file you will PUT'),
        }),
      )
      .min(1)
      .max(10)
      .describe('1-10 files to upload'),
  },
  outputSchema: {
    attachments: z.array(
      z.object({
        id: z.string(),
        filename: z.string(),
        upload_url: z.string().url(),
        upload_filename: z.string(),
      }),
    ),
    expires_hint: z.string(),
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
  handler: async (args) => {
    const files = args.files.map((f, index) => ({
      id: String(index),
      filename: f.filename,
      file_size: f.file_size,
    }));
    let prepared: { attachments: PreparedAttachment[] };
    try {
      prepared = (await container.rest.post(`/channels/${args.channel_id}/attachments`, {
        body: { files },
      })) as { attachments: PreparedAttachment[] };
    } catch (error) {
      rethrowAttachFilesDenied(error, args.channel_id);
    }

    const attachments = prepared.attachments.map((a) => {
      const id = String(a.id);
      const requested = files.find((f) => f.id === id);
      return {
        id,
        filename: requested?.filename ?? a.upload_filename,
        upload_url: a.upload_url,
        upload_filename: a.upload_filename,
      };
    });

    return dualResult({
      text:
        `Prepared ${attachments.length} upload URL(s) for <#${args.channel_id}>. ` +
        'PUT each file to its upload_url, then send with attachments:[{id, filename, uploaded_filename}].',
      data: {
        attachments,
        expires_hint: 'Upload URLs are single-use and short-lived; PUT the bytes right away.',
      },
    });
  },
});
