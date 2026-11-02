import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as esm from '../dist/index.js';

const cjs = createRequire(import.meta.url)('../dist/index.cjs');

const fakeFetch = async (input) => {
  const url = new URL(String(input));
  assert.equal(url.pathname, '/api/v1/check');
  return new Response(
    JSON.stringify({ data: { ipAddress: url.searchParams.get('ip'), abuseConfidenceScore: 90, totalReports: 3 } }),
    { status: 200 },
  );
};

for (const [name, mod] of [
  ['esm', esm],
  ['cjs', cjs],
]) {
  const client = new mod.Client({ apiKey: 'sl_test', baseUrl: 'https://api.test/api/v1', fetch: fakeFetch });
  const result = await client.check('203.0.113.50');
  assert.equal(result.abuseConfidenceScore, 90, name);
  assert.equal(mod.isMalicious(result), true, name);
  assert.equal(mod.isIP('2001:db8::1'), true, name);
  console.log(`${name} ok on node ${process.version}`);
}
