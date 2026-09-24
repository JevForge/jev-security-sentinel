import { createHmac, randomBytes } from 'node:crypto';

function hmac(key: Buffer, data: Buffer | string): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

/**
 * Veracode HMAC-SHA-256 authorization header.
 * Data string: id, host, url path+query, method.
 * Signature chain: nonce → timestamp → vcode_request_version_1 → data.
 */
export function veracodeAuthorizationHeader(input: {
  apiId: string;
  apiKeyHex: string;
  url: string;
  method: string;
  nonce?: Buffer;
  timestamp?: string;
}): string {
  const parsed = new URL(input.url);
  const urlPath = `${parsed.pathname}${parsed.search}`;
  const data = `id=${input.apiId}&host=${parsed.hostname}&url=${urlPath}&method=${input.method.toUpperCase()}`;
  const key = Buffer.from(input.apiKeyHex, 'hex');
  if (key.length === 0) {
    throw new Error('VERACODE_API_KEY must be a hex string');
  }
  const nonce = input.nonce ?? randomBytes(16);
  const timestamp = input.timestamp ?? Date.now().toString();
  const signature = hmac(hmac(hmac(hmac(key, nonce), timestamp), 'vcode_request_version_1'), data);
  return `VERACODE-HMAC-SHA-256 id=${input.apiId},ts=${timestamp},nonce=${nonce.toString('hex')},sig=${signature.toString('hex')}`;
}
