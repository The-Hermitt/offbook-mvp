// src/lib/r2.ts
// Cloudflare R2 storage using AWS SDK S3 client

import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import * as fs from "fs";
import { Readable } from "stream";

// Configuration from environment variables
const R2_ENDPOINT = process.env.R2_ENDPOINT;
const R2_REGION = process.env.R2_REGION || "auto";
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET = process.env.R2_BUCKET;

let s3Client: S3Client | null = null;

/**
 * Check if R2 is enabled and properly configured
 */
export function r2Enabled(): boolean {
  return Boolean(
    R2_ENDPOINT &&
    R2_ACCESS_KEY_ID &&
    R2_SECRET_ACCESS_KEY &&
    R2_BUCKET
  );
}

/**
 * Get or create the S3 client instance
 */
function getS3Client(): S3Client {
  if (!s3Client && r2Enabled()) {
    s3Client = new S3Client({
      endpoint: R2_ENDPOINT,
      region: R2_REGION,
      credentials: {
        accessKeyId: R2_ACCESS_KEY_ID!,
        secretAccessKey: R2_SECRET_ACCESS_KEY!,
      },
      forcePathStyle: true,
    });
  }

  if (!s3Client) {
    throw new Error("R2 is not enabled or configured");
  }

  return s3Client;
}

/**
 * Upload a file to R2
 * @param key - The R2 object key (path)
 * @param filePath - Local file path to upload
 * @param contentType - Optional MIME type
 */
export async function r2PutFile(
  key: string,
  filePath: string,
  contentType?: string
): Promise<void> {
  const client = getS3Client();
  const fileStream = fs.createReadStream(filePath);
  const stats = fs.statSync(filePath);

  const command = new PutObjectCommand({
    Bucket: R2_BUCKET!,
    Key: key,
    Body: fileStream,
    ContentType: contentType,
    ContentLength: stats.size,
  });

  await client.send(command);
  console.log(`[r2] Uploaded file to R2: ${key} (${stats.size} bytes)`);
}

/**
 * Get an object stream from R2 with optional range support
 * @param key - The R2 object key
 * @param rangeHeader - Optional range header (e.g., "bytes=0-1023")
 * @returns Object with stream and metadata
 */
export async function r2GetObjectStream(
  key: string,
  rangeHeader?: string
): Promise<{
  stream: NodeJS.ReadableStream;
  contentType?: string;
  contentLength?: number;
  contentRange?: string;
  statusCode: 200 | 206;
}> {
  const client = getS3Client();

  const command = new GetObjectCommand({
    Bucket: R2_BUCKET!,
    Key: key,
    Range: rangeHeader,
  });

  const response = await client.send(command);

  if (!response.Body) {
    throw new Error(`No body returned for key: ${key}`);
  }

  // Convert AWS SDK stream to Node.js readable stream
  const stream = response.Body as Readable;

  return {
    stream,
    contentType: response.ContentType,
    contentLength: response.ContentLength,
    contentRange: response.ContentRange,
    statusCode: rangeHeader && response.ContentRange ? 206 : 200,
  };
}

/**
 * Check if an object exists in R2 and get its metadata
 * @param key - The R2 object key
 * @returns Object with exists flag and metadata
 */
export async function r2Head(
  key: string
): Promise<{
  exists: boolean;
  contentLength?: number;
  contentType?: string;
}> {
  const client = getS3Client();

  try {
    const command = new HeadObjectCommand({
      Bucket: R2_BUCKET!,
      Key: key,
    });

    const response = await client.send(command);

    return {
      exists: true,
      contentLength: response.ContentLength,
      contentType: response.ContentType,
    };
  } catch (err: any) {
    // If the object doesn't exist, HeadObject throws a 404 error
    if (err.name === "NotFound" || err.$metadata?.httpStatusCode === 404) {
      return {
        exists: false,
      };
    }
    // Re-throw other errors
    throw err;
  }
}

/**
 * Delete an object from R2
 * @param key - The R2 object key
 */
export async function r2Delete(key: string): Promise<void> {
  const client = getS3Client();

  const command = new DeleteObjectCommand({
    Bucket: R2_BUCKET!,
    Key: key,
  });

  await client.send(command);
  console.log(`[r2] Deleted object from R2: ${key}`);
}
