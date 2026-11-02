import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { main } from '../src/cli.js';
import { CHECK_ALLOWLISTED, CHECK_BAD, FakeApi } from './helpers.js';

const BASE = ['--base-url', 'https://api.test/api/v1'];

function capture() {
  const io = { stdout: '', stderr: '' };
  return {
    io,
    sink: {
      out: (t: string) => {
        io.stdout += t;
      },
      err: (t: string) => {
        io.stderr += t;
      },
      readStdin: () => '',
    },
  };
}

let api: FakeApi;

beforeEach(() => {
  vi.stubEnv('ISIPSAFE_API_KEY', '');
  vi.stubEnv('ISIPSAFE_KEY', '');
  api = new FakeApi();
  vi.stubGlobal('fetch', api.fetch);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('cli', () => {
  it('prints a human summary for check', async () => {
    api.on('GET', '/api/v1/check', { body: CHECK_BAD });
    const { io, sink } = capture();
    expect(await main([...BASE, 'check', '185.220.101.1'], sink)).toBe(0);
    expect(io.stdout).toContain('MALICIOUS');
    expect(io.stdout).toContain('86/100');
    expect(io.stdout).toContain('Tor exit');
  });

  it('uses exit code 1 with --fail-if-malicious', async () => {
    api.on('GET', '/api/v1/check', { body: CHECK_BAD });
    expect(await main([...BASE, 'check', '185.220.101.1', '--fail-if-malicious'], capture().sink)).toBe(1);
    api.on('GET', '/api/v1/check', { body: CHECK_ALLOWLISTED });
    expect(await main([...BASE, 'check', '8.8.8.8', '--fail-if-malicious'], capture().sink)).toBe(0);
  });

  it('prints JSON with isMalicious', async () => {
    api.on('GET', '/api/v1/check', { body: CHECK_BAD });
    const { io, sink } = capture();
    await main([...BASE, 'check', '185.220.101.1', '--json'], sink);
    const data = JSON.parse(io.stdout);
    expect(data.abuseConfidenceScore).toBe(86);
    expect(data.isMalicious).toBe(true);
  });

  it('fails cleanly when reporting without a key', async () => {
    const { io, sink } = capture();
    expect(await main([...BASE, 'report', '203.0.113.50', '-c', 'ssh'], sink)).toBe(2);
    expect(io.stderr).toContain('API key');
    expect(api.calls).toHaveLength(0);
  });

  it('reports with a key', async () => {
    api.on('POST', '/api/v1/report', { body: { data: { ipAddress: '203.0.113.50', abuseConfidenceScore: 40 } } });
    const { io, sink } = capture();
    const code = await main(
      ['--api-key', 'sl_x', ...BASE, 'report', '203.0.113.50', '-c', 'ssh,brute-force', '-m', 'hi'],
      sink,
    );
    expect(code).toBe(0);
    expect(io.stdout).toContain('new score 40/100');
    expect(JSON.parse(api.calls[0]!.body!).categories).toEqual(['ssh', 'brute-force']);
  });

  it('uploads a CSV file', async () => {
    api.on('POST', '/api/v1/bulk-report', { body: { data: { savedReports: 2, invalidReports: [] } } });
    const dir = mkdtempSync(join(tmpdir(), 'isipsafe-'));
    const file = join(dir, 'reports.csv');
    writeFileSync(file, '203.0.113.50,ssh,,\n198.51.100.4,port-scan,,\n');
    const { io, sink } = capture();
    expect(await main(['--api-key', 'sl_x', ...BASE, 'bulk-report', file], sink)).toBe(0);
    expect(io.stdout).toContain('saved 2 reports');
    expect(api.calls[0]!.body).toBe(readFileSync(file, 'utf8'));
  });

  it('writes the blocklist to a file', async () => {
    api.on('GET', '/api/v1/blocklist', { body: '203.0.113.50\n' });
    const out = join(mkdtempSync(join(tmpdir(), 'isipsafe-')), 'list.txt');
    expect(
      await main(['--api-key', 'sl_x', ...BASE, 'blocklist', '--format', 'nginx', '-o', out], capture().sink),
    ).toBe(0);
    expect(readFileSync(out, 'utf8')).toBe('203.0.113.50\n');
    expect(api.calls[0]!.url.searchParams.get('format')).toBe('nginx');
  });

  it('rejects invalid input and unknown commands', async () => {
    const bad = capture();
    expect(await main([...BASE, 'check', '999.1.1.1'], bad.sink)).toBe(2);
    expect(bad.io.stderr).toContain('not a valid');
    const unknown = capture();
    expect(await main(['nope'], unknown.sink)).toBe(2);
  });

  it('prints help and version', async () => {
    const help = capture();
    expect(await main(['--help'], help.sink)).toBe(0);
    expect(help.io.stdout).toContain('Usage: isipsafe');
    const version = capture();
    expect(await main(['--version'], version.sink)).toBe(0);
    expect(version.io.stdout).toMatch(/^isipsafe \d+\.\d+\.\d+/);
  });
});
