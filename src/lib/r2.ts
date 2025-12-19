// src/lib/r2.ts
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

// Check if all required R2 env vars are present
export function r2Enabled(): boolean {
  return !!(
    process.env.R2_ENDPOINT &&
    process.env.R2_BUCKET &&
    process.env.R2_ACCESS_KEY_ID &&
    process.env.R2_SECRET_ACCESS_KEY
  );
}

// Lazy-initialize S3 client
let _client: S3Client | null = null;
function getClient(): S3Client {
  if (!_client) {
    const endpoint = process.env.R2_ENDPOINT;
    const region = process.env.R2_REGION || "auto";
    const accessKeyId = process.env.R2_ACCESS_KEY_ID;
    const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;

    if (!endpoint || !accessKeyId || !secretAccessKey) {
      throw new Error("R2 credentials not configured");
    }

    _client = new S3Client({
      endpoint,
      region,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
      forcePathStyle: true,
    });
  }
  return _client;
}

// Upload object to R2
export async function r2PutObject(opts: {
  key: string;
  body: Buffer | Uint8Array | import("stream").Readable;
  contentType: string;
  contentLength?: number;
}): Promise<void> {
  const bucket = process.env.R2_BUCKET;
  if (!bucket) throw new Error("R2_BUCKET not set");

  const commandInput: any = {
    Bucket: bucket,
    Key: opts.key,
    Body: opts.body,
    ContentType: opts.contentType,
  };

  if (opts.contentLength !== undefined) {
    commandInput.ContentLength = opts.contentLength;
  }

  const command = new PutObjectCommand(commandInput);

  await getClient().send(command);
}

// Get signed URL for streaming/downloading from R2
export async function r2GetSignedUrl(opts: {
  key: string;
  expiresSeconds?: number;
  downloadName?: string;
  contentType?: string;
}): Promise<string> {
  const bucket = process.env.R2_BUCKET;
  if (!bucket) throw new Error("R2_BUCKET not set");

  const commandInput: any = {
    Bucket: bucket,
    Key: opts.key,
  };

  // Set Content-Disposition for download with custom filename
  if (opts.downloadName) {
    commandInput.ResponseContentDisposition = `attachment; filename="${opts.downloadName}"`;
  }

  // Override Content-Type if specified
  if (opts.contentType) {
    commandInput.ResponseContentType = opts.contentType;
  }

  const command = new GetObjectCommand(commandInput);
  const expiresIn = opts.expiresSeconds || 900; // Default 15 minutes

  return getSignedUrl(getClient(), command, { expiresIn });
}

// Delete object from R2
export async function r2DeleteObject(key: string): Promise<void> {
  const bucket = process.env.R2_BUCKET;
  if (!bucket) throw new Error("R2_BUCKET not set");

  const command = new DeleteObjectCommand({
    Bucket: bucket,
    Key: key,
  });

  await getClient().send(command);
}
