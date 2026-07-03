// Public default. JULENNY_API_URL is the BARE base URL (e.g. https://julenny.net),
// with no /mcp and no /api suffix - this client appends /api/... itself.
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';

const DEFAULT_BASE_URL = 'https://julenny.net';

export class JulennyApiClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(apiKey: string, baseUrl?: string) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl || process.env.JULENNY_API_URL || DEFAULT_BASE_URL;
  }

  private async request(path: string, options: RequestInit = {}): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'x-api-key': this.apiKey,
      ...(options.headers as Record<string, string> || {}),
    };
    if (!headers['Content-Type'] && options.method && options.method !== 'GET') {
      headers['Content-Type'] = 'application/json';
    }
    return fetch(url, { ...options, headers });
  }

  async get(path: string) {
    const res = await this.request(path);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `API error ${res.status}`);
    }
    return res.json();
  }

  async post(path: string, body?: unknown) {
    const res = await this.request(path, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `API error ${res.status}`);
    }
    return res.json();
  }

  async patch(path: string, body?: unknown) {
    const res = await this.request(path, {
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `API error ${res.status}`);
    }
    return res.json();
  }

  async put(path: string, body?: unknown) {
    const res = await this.request(path, {
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `API error ${res.status}`);
    }
    return res.json();
  }

  // ---- pipeline (data/result/key-exchange) helpers ----
  // These move CIPHERTEXT and ENCRYPTED key material only. Never plaintext,
  // never key bytes in the clear, never the API key in a body/return.

  /**
   * POST multipart/form-data to a backend API path with x-api-key auth.
   * Do NOT set Content-Type manually: fetch derives the multipart boundary
   * from the FormData body. `extraHeaders` carries non-content headers
   * (e.g. x-jl-signature for release). Returns parsed JSON; throws on !ok.
   */
  async postMultipart(
    path: string,
    formData: FormData,
    extraHeaders: Record<string, string> = {},
  ) {
    const url = `${this.baseUrl}${path}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'x-api-key': this.apiKey,
        ...extraHeaders,
      },
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `API error ${res.status}`);
    }
    return res.json();
  }

  /**
   * GET a path with x-api-key auth and return the raw response body as a
   * Buffer. Used for result download (the result is still ciphertext).
   */
  async getBytes(path: string): Promise<Buffer> {
    const res = await this.request(path);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `API error ${res.status}`);
    }
    const ab = await res.arrayBuffer();
    return Buffer.from(ab);
  }

  /**
   * PUT bytes to an ABSOLUTE pre-signed URL with NO x-api-key (the URL is
   * already authorized). Used for signed-URL key-exchange uploads.
   */
  async putSignedUrl(
    absoluteUrl: string,
    body: Buffer,
    contentType = 'application/octet-stream',
  ): Promise<void> {
    const res = await fetch(absoluteUrl, {
      method: 'PUT',
      headers: { 'Content-Type': contentType },
      // Wrap in a Blob so it satisfies fetch's BodyInit typing. Copy into a
      // fresh Uint8Array first so the BlobPart is backed by a plain ArrayBuffer
      // (a raw Node Buffer's ArrayBufferLike backing is rejected by the typing).
      body: new Blob([new Uint8Array(body)]),
    });
    if (!res.ok) {
      throw new Error(`signed-URL PUT failed: HTTP ${res.status}`);
    }
  }

  /**
   * PUT a file to an ABSOLUTE pre-signed URL by STREAMING it from disk, so a
   * large dataset (e.g. the ~190MB decision-tree model bundle) is never held
   * fully in memory. Content-Length is set explicitly from the file size so the
   * signed URL still gets a fixed-length PUT (object storage rejects chunked
   * transfer here). Used for large-dataset uploads; small payloads that must be
   * signed still use putSignedUrl(buffer).
   */
  async putSignedUrlFromFile(
    absoluteUrl: string,
    filePath: string,
    contentType = 'application/octet-stream',
  ): Promise<void> {
    const { size } = await stat(filePath);
    const res = await fetch(absoluteUrl, {
      method: 'PUT',
      headers: { 'Content-Type': contentType, 'Content-Length': String(size) },
      body: createReadStream(filePath) as unknown as BodyInit,
      // Node/undici requires duplex:'half' when the body is a stream.
      duplex: 'half',
    } as RequestInit & { duplex: 'half' });
    if (!res.ok) {
      throw new Error(`signed-URL PUT failed: HTTP ${res.status}`);
    }
  }
}
