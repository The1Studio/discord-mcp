import { DiscordAPIError } from '@discordjs/rest';
import { z } from 'zod';
import { DiscordPermissionError } from '../../errors/client.js';

/** Discord JSON error code "Missing Permissions". */
const MISSING_PERMISSIONS = 50013;

/**
 * A file already PUT to a Discord upload URL from `attachments_prepare_upload`.
 * The message body references it by `uploaded_filename`; no bytes pass through
 * this server.
 */
export const UploadedAttachment = z.object({
  id: z
    .union([z.string(), z.number().int().nonnegative()])
    .describe('The id returned by attachments_prepare_upload for this file'),
  filename: z
    .string()
    .min(1)
    .max(1024)
    .describe('Display filename; reference it as attachment://<filename> in components'),
  uploaded_filename: z
    .string()
    .min(1)
    .describe('The upload_filename returned by attachments_prepare_upload'),
  description: z.string().max(1024).optional().describe('Alt text for the attachment'),
});

export type UploadedAttachment = z.infer<typeof UploadedAttachment>;

export const UploadedAttachments = z
  .array(UploadedAttachment)
  .min(1)
  .max(10)
  .optional()
  .describe(
    'Files already uploaded via attachments_prepare_upload + an HTTP PUT of the bytes to each upload_url. ' +
      'Needs the Attach Files permission.',
  );

/** Build the Discord message-create `attachments` array. */
export function toMessageAttachments(
  attachments: readonly UploadedAttachment[],
): Record<string, unknown>[] {
  return attachments.map((a) => ({
    id: String(a.id),
    filename: a.filename,
    uploaded_filename: a.uploaded_filename,
    ...(a.description === undefined ? {} : { description: a.description }),
  }));
}

/**
 * Re-throw a Discord "Missing Permissions" rejection of an attachment request as
 * a structured permission error naming ATTACH_FILES. The runtime access
 * middleware blocks only in `enforce` mode, so without this an advisory-mode
 * deployment surfaces a generic 403 that never names the permission to grant.
 */
export function rethrowAttachFilesDenied(error: unknown, channelId: string): never {
  if (error instanceof DiscordAPIError && error.code === MISSING_PERMISSIONS) {
    const denied = new DiscordPermissionError(['ATTACH_FILES'], [], `channel ${channelId}`);
    denied.recoveryHint =
      'Grant the bot Attach Files (and Send Messages) in this channel or thread, then retry.';
    throw denied;
  }
  throw error;
}
