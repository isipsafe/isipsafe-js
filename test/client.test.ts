import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  APIError,
  AuthenticationError,
  Client,
  NetworkError,
  RateLimitError,
  ValidationError,
  buildBulkCsv,
  isCidr,
  isIP,
} from '../src/index.js';
import { CHECK_ALLOWLISTED, CHECK_BAD, FakeApi } from './helpers.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('check', () => {
  it('parses the response and sends the key as a Bearer header', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', { body: CHECK_BAD });
    const result = await api.client().check('185.220.101.1', { maxAgeInDays: 90, verbose: true });

    expect(result.abuseConfidenceScore).toBe(86);
    expect(result.isTor).toBe(true);
    expect(result.reports?.[0]?.categories).toEqual(['ssh']);

    const call = api.calls[0]!;
    expect(Object.fromEntries(call.url.searchParams)).toEqual({
      ip: '185.220.101.1',
      maxAgeInDays: '90',
      verbose: 'true',
    });
    expect(call.headers.Authorization).toBe('Bearer sl_test_key');
    expect(call.headers['User-Agent']).toMatch(/^isipsafe-js\//);
    expect(call.url.searchParams.has('key')).toBe(false);
  });

  it('flags reported addresses at or above the threshold', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', { body: CHECK_BAD });
    const client = api.client();
    expect(await client.isMalicious('185.220.101.1')).toBe(true);
    expect(await client.isMalicious('185.220.101.1', 90)).toBe(false);
  });

  it('never flags allowlisted or unreported addresses', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', { body: CHECK_ALLOWLISTED });
    expect(await api.client().isMalicious('8.8.8.8')).toBe(false);
  });

  it('rejects invalid IPs without calling the API', async () => {
    const api = new FakeApi();
    await expect(api.client().check('999.1.1.1')).rejects.toThrow(TypeError);
    expect(api.calls).toHaveLength(0);
  });

  it('works without a key', async () => {
    vi.stubEnv('ISIPSAFE_API_KEY', '');
    vi.stubEnv('ISIPSAFE_KEY', '');
    const api = new FakeApi().on('GET', '/api/v1/check', { body: CHECK_BAD });
    await api.client({ apiKey: undefined }).check('185.220.101.1');
    expect(api.calls[0]!.headers.Authorization).toBeUndefined();
  });

  it('reads the key from the environment and never exposes it', async () => {
    vi.stubEnv('ISIPSAFE_API_KEY', '  sl_env_key ');
    const api = new FakeApi().on('GET', '/api/v1/check', { body: CHECK_BAD });
    const client = api.client({ apiKey: undefined });
    expect(client.hasApiKey).toBe(true);
    expect(JSON.stringify(client)).not.toContain('sl_env_key');
    await client.check('185.220.101.1');
    expect(api.calls[0]!.headers.Authorization).toBe('Bearer sl_env_key');
  });
});

describe('report', () => {
  it('sends JSON with normalised categories and timestamp', async () => {
    const api = new FakeApi().on('POST', '/api/v1/report', {
      body: {
        data: { ipAddress: '203.0.113.50', abuseConfidenceScore: 87, link: 'https://isipsafe.com/ip/203.0.113.50' },
      },
    });
    const result = await api.client().report({
      ip: '203.0.113.50',
      categories: 'ssh, brute-force,ssh',
      comment: 'sshd: 212 failed logins',
      timestamp: new Date('2026-11-02T07:00:00Z'),
    });
    expect(result).toEqual({
      ipAddress: '203.0.113.50',
      abuseConfidenceScore: 87,
      link: 'https://isipsafe.com/ip/203.0.113.50',
      duplicate: false,
    });
    const call = api.calls[0]!;
    expect(call.headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(call.body!)).toEqual({
      ip: '203.0.113.50',
      categories: ['ssh', 'brute-force'],
      comment: 'sshd: 212 failed logins',
      timestamp: '2026-11-02T07:00:00Z',
    });
  });

  it('accepts numeric IDs and CIDR networks, and truncates long comments', async () => {
    const api = new FakeApi().on('POST', '/api/v1/report', { body: { data: { ipAddress: '203.0.113.0/24' } } });
    await api.client().report({ ip: '203.0.113.0/24', categories: [22, 18], comment: 'x'.repeat(5000) });
    const body = JSON.parse(api.calls[0]!.body!);
    expect(body.categories).toEqual(['22', '18']);
    expect(body.comment).toHaveLength(1024);
  });

  it('treats a repeat within 15 minutes as a duplicate, not an error', async () => {
    const api = new FakeApi().on('POST', '/api/v1/report', { status: 429, body: { errors: [{ detail: 'again' }] } });
    const result = await api.client().report({ ip: '127.0.0.2', categories: 'ssh' });
    expect(result.duplicate).toBe(true);
  });

  it('needs a key and fails before any request', async () => {
    vi.stubEnv('ISIPSAFE_API_KEY', '');
    vi.stubEnv('ISIPSAFE_KEY', '');
    const api = new FakeApi();
    await expect(api.client({ apiKey: undefined }).report({ ip: '203.0.113.50', categories: 'ssh' })).rejects.toThrow(
      AuthenticationError,
    );
    expect(api.calls).toHaveLength(0);
  });

  it('validates categories', async () => {
    const client = new FakeApi().client();
    await expect(client.report({ ip: '203.0.113.50', categories: '' })).rejects.toThrow(TypeError);
    await expect(
      client.report({ ip: '203.0.113.50', categories: Array.from({ length: 13 }, (_, i) => i) }),
    ).rejects.toThrow(/at most 12/);
  });
});

describe('bulk report', () => {
  it('builds an escaped CSV', () => {
    expect(
      buildBulkCsv([
        { ip: '203.0.113.50', categories: ['ssh', 'brute-force'], comment: 'said "hi", twice' },
        { ip: '198.51.100.4', categories: 'port-scan', timestamp: '2026-11-02T07:00:00Z' },
      ]),
    ).toBe(
      'IP,Categories,ReportDate,Comment\n' +
        '203.0.113.50,"ssh,brute-force",,"said ""hi"", twice"\n' +
        '198.51.100.4,port-scan,2026-11-02T07:00:00Z,\n',
    );
  });

  it('uploads and parses the result without retrying', async () => {
    const api = new FakeApi().on('POST', '/api/v1/bulk-report', {
      body: { data: { savedReports: 1, invalidReports: [{ rowNumber: 3, input: '198.51.100.4', error: 'bad' }] } },
    });
    const result = await api.client().bulkReport([{ ip: '203.0.113.50', categories: 'ssh' }]);
    expect(result.savedReports).toBe(1);
    expect(result.invalidReports[0]).toEqual({ rowNumber: 3, input: '198.51.100.4', error: 'bad' });
    expect(api.calls[0]!.headers['Content-Type']).toBe('text/csv');

    const failing = new FakeApi().on('POST', '/api/v1/bulk-report', { status: 503, body: {} });
    await expect(failing.client().bulkReport([{ ip: '203.0.113.50', categories: 'ssh' }])).rejects.toThrow(APIError);
    expect(failing.calls).toHaveLength(1);
  });

  it('rejects empty uploads', () => {
    expect(() => buildBulkCsv([])).toThrow(/no reports/);
  });
});

describe('errors and retries', () => {
  it('maps 422 to ValidationError with the API detail', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', {
      status: 422,
      body: { errors: [{ detail: 'ip: that is not a valid IPv4 or IPv6 address', status: 422 }] },
    });
    const error = await api
      .client()
      .check('203.0.113.50')
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).status).toBe(422);
    expect((error as Error).message).toContain('not a valid');
  });

  it('maps 401 to AuthenticationError', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', { status: 401, body: { errors: [{ detail: 'bad key' }] } });
    await expect(api.client().check('203.0.113.50')).rejects.toThrow(AuthenticationError);
  });

  it('exposes Retry-After on rate limits', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', {
      status: 429,
      body: { errors: [{ detail: 'slow down' }] },
      headers: { 'Retry-After': '42' },
    });
    const error = await api
      .client()
      .check('203.0.113.50')
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RateLimitError);
    expect((error as RateLimitError).retryAfter).toBe(42);
  });

  it('retries lookups on 5xx', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', { status: 502, body: {} }, { body: CHECK_BAD });
    const result = await api.client().check('185.220.101.1');
    expect(result.abuseConfidenceScore).toBe(86);
    expect(api.calls).toHaveLength(2);
  });

  it('gives up after maxRetries', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', { status: 500, body: {} });
    await expect(api.client().check('185.220.101.1')).rejects.toThrow(APIError);
    expect(api.calls).toHaveLength(3);
  });

  it('wraps network failures in NetworkError', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check', { error: new TypeError('fetch failed') });
    await expect(api.client({ maxRetries: 1 }).check('185.220.101.1')).rejects.toThrow(NetworkError);
    expect(api.calls).toHaveLength(2);
  });

  it('times out slow requests', async () => {
    const slowFetch: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    const client = new Client({ baseUrl: 'https://api.test/api/v1', fetch: slowFetch, timeout: 20, maxRetries: 0 });
    await expect(client.check('185.220.101.1')).rejects.toThrow(/timed out after 20 ms/);
  });
});

describe('other endpoints', () => {
  it('reports() and allReports() paginate', async () => {
    const page = (n: number, last: number) => ({
      body: {
        data: {
          ipAddress: '185.220.101.1',
          total: 3,
          page: n,
          perPage: 100,
          lastPage: last,
          results: [{ reportedAt: `2026-11-0${n}T00:00:00Z`, categories: ['c2'], reporter: 'Automated feed' }],
        },
      },
    });
    const api = new FakeApi().on('GET', '/api/v1/reports', page(1, 2), page(2, 2));
    const all = [];
    for await (const report of api.client().allReports('185.220.101.1')) all.push(report);
    expect(all.map((r) => r.reportedAt)).toEqual(['2026-11-01T00:00:00Z', '2026-11-02T00:00:00Z']);
    expect(api.calls.map((c) => c.url.searchParams.get('page'))).toEqual(['1', '2']);
  });

  it('checkBlock validates the network', async () => {
    const api = new FakeApi().on('GET', '/api/v1/check-block', {
      body: {
        data: {
          networkAddress: '185.220.101.0',
          netmask: 28,
          reportedAddress: [{ ipAddress: '185.220.101.11', abuseConfidenceScore: 61, numReports: 27 }],
        },
      },
    });
    const net = await api.client().checkBlock('185.220.101.0/28');
    expect(net.reportedAddress[0]!.numReports).toBe(27);
    await expect(api.client().checkBlock('nope')).rejects.toThrow(TypeError);
  });

  it('blocklist() returns IPs and passes filters', async () => {
    const api = new FakeApi().on('GET', '/api/v1/blocklist', { body: '# isipsafe\n203.0.113.50\n\n198.51.100.4\n' });
    const ips = await api.client().blocklist({ confidenceMinimum: 90, exceptCountries: ['GB', 'IE'], ipVersion: 4 });
    expect(ips).toEqual(['203.0.113.50', '198.51.100.4']);
    const params = Object.fromEntries(api.calls[0]!.url.searchParams);
    expect(params).toEqual({ format: 'txt', confidenceMinimum: '90', exceptCountries: 'GB,IE', ipVersion: '4' });
    // @ts-expect-error invalid format on purpose
    await expect(api.client().blocklistRaw('exe')).rejects.toThrow(TypeError);
  });

  it('clearAddress uses DELETE', async () => {
    const api = new FakeApi().on('DELETE', '/api/v1/clear-address', { body: { data: { numReportsDeleted: 3 } } });
    expect(await api.client().clearAddress('203.0.113.50')).toEqual({ numReportsDeleted: 3 });
  });

  it('categories()', async () => {
    const api = new FakeApi().on('GET', '/api/v1/categories', {
      body: { data: [{ id: 22, slug: 'ssh', name: 'SSH', group: 'Authentication', description: 'd' }] },
    });
    expect(await api.client().categories()).toEqual([
      { id: 22, slug: 'ssh', name: 'SSH', group: 'Authentication', description: 'd' },
    ]);
  });
});

describe('ip helpers', () => {
  it.each(['1.2.3.4', '255.255.255.255', '::1', '2001:db8::7', '::ffff:192.0.2.1'])('%s is an IP', (ip) => {
    expect(isIP(ip)).toBe(true);
  });

  it.each(['', '1.2.3', '256.1.1.1', '01.2.3.4', 'abc', '2001:db8::7::1', '1.2.3.4/24', 'http://x'])(
    '%s is not an IP',
    (ip) => {
      expect(isIP(ip)).toBe(false);
    },
  );

  it('recognises CIDR', () => {
    expect(isCidr('203.0.113.0/24')).toBe(true);
    expect(isCidr('2001:db8::/48')).toBe(true);
    expect(isCidr('203.0.113.0/33')).toBe(false);
    expect(isCidr('203.0.113.0')).toBe(false);
  });
});
