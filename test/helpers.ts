import { Client, type ClientOptions } from '../src/index.js';

export interface Call {
  method: string;
  url: URL;
  headers: Record<string, string>;
  body: string | undefined;
}

interface Reply {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
  error?: Error;
}

export class FakeApi {
  calls: Call[] = [];
  #replies = new Map<string, Reply[]>();

  on(method: string, path: string, ...replies: Reply[]): this {
    this.#replies.set(`${method} ${path}`, replies);
    return this;
  }

  fetch: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    this.calls.push({
      method: init?.method ?? 'GET',
      url,
      headers: { ...(init?.headers as Record<string, string>) },
      body: init?.body === undefined || init?.body === null ? undefined : String(init.body),
    });
    const queue = this.#replies.get(`${init?.method ?? 'GET'} ${url.pathname}`) ?? [
      { status: 404, body: { errors: [{ detail: 'not found' }] } },
    ];
    const reply = queue.length > 1 ? queue.shift()! : queue[0]!;
    if (reply.error) throw reply.error;
    const text = typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body ?? {});
    return new Response(text, { status: reply.status ?? 200, headers: reply.headers });
  };

  client(options: ClientOptions = {}): Client {
    const client = new Client({
      apiKey: 'sl_test_key',
      baseUrl: 'https://api.test/api/v1',
      fetch: this.fetch,
      ...options,
    });
    client.sleep = async () => {};
    return client;
  }
}

export const CHECK_BAD = {
  data: {
    ipAddress: '185.220.101.1',
    abuseConfidenceScore: 86,
    confidenceBand: 'High',
    totalReports: 41,
    numDistinctUsers: 6,
    isPublic: true,
    isWhitelisted: false,
    isTor: true,
    ipVersion: 4,
    categories: ['port-scan', 'brute-force'],
    categoryIds: [14, 18],
    countryCode: 'DE',
    asn: 60729,
    isp: 'Example',
    hostnames: [],
    link: 'https://isipsafe.com/ip/185.220.101.1',
    reports: [{ reportedAt: '2026-11-02T07:37:29Z', categories: ['ssh'], comment: 'x' }],
  },
};

export const CHECK_ALLOWLISTED = {
  data: {
    ipAddress: '8.8.8.8',
    abuseConfidenceScore: 100,
    confidenceBand: 'High',
    totalReports: 0,
    isWhitelisted: true,
  },
};
