# isipsafe

Official JavaScript and TypeScript client and command-line tool for [isIPsafe](https://isipsafe.com), the free IP reputation and abuse reporting service.

- **Check** whether an IP address is malicious before you trust it
- **Report** attackers from your logs, one at a time or 10,000 at once
- **Download the blocklist** in a firewall-ready format (nftables, ipset, nginx, apache, MikroTik, STIX and more)

No runtime dependencies. Works in Node.js 18+, Deno and Bun. ESM and CommonJS, with types.

```bash
npm install isipsafe
```

## Get an API key

Lookups work without a key (400 per day per address). Reporting, bulk uploads and the blocklist need a free key from [isipsafe.com/login](https://isipsafe.com/login). A key also raises the lookup limit to 10,000 per day.

```bash
export ISIPSAFE_API_KEY=sl_your_key_here
```

The client sends the key in an `Authorization` header, never in the URL. Keep it on the server; do not ship it to browsers.

## Usage

```ts
import { Client, isMalicious } from 'isipsafe';

const client = new Client(); // reads ISIPSAFE_API_KEY, or new Client({ apiKey: 'sl_...' })

const result = await client.check('185.220.101.1');
console.log(result.abuseConfidenceScore, result.totalReports, result.categories);

if (isMalicious(result)) {
  // score >= 75, has reports, not allowlisted
}

await client.report({
  ip: '203.0.113.50',
  categories: ['ssh', 'brute-force'],
  comment: 'sshd: 212 failed logins in 10 minutes',
});
```

CommonJS works too: `const { Client } = require('isipsafe');`

### Express middleware example

```ts
import express from 'express';
import { Client, isMalicious } from 'isipsafe';

const isipsafe = new Client({ timeout: 2000 });
const app = express();

app.post('/login', async (req, res, next) => {
  try {
    if (isMalicious(await isipsafe.check(req.ip!))) return res.status(403).send('Forbidden');
  } catch {
    // fail open: never lock users out because the lookup failed
  }
  next();
});
```

Cache results for a while (for example an LRU cache for 1 hour) so you do not call the API on every request.

### Report many addresses at once

```ts
const result = await client.bulkReport([
  { ip: '203.0.113.50', categories: ['ssh', 'brute-force'], comment: 'sshd' },
  { ip: '198.51.100.4', categories: 'port-scan', timestamp: new Date() },
]);
console.log(result.savedReports, result.invalidReports);
```

### Blocklist

```ts
const ips = await client.blocklist({ confidenceMinimum: 90, exceptCountries: ['GB'] });
const nft = await client.blocklistRaw('nftables');
```

### API

| Method                                                 | What it does                                               |
| ------------------------------------------------------ | ---------------------------------------------------------- |
| `check(ip, { maxAgeInDays, verbose })`                 | Score, report counts, location and network for one address |
| `isMalicious(ip, threshold = 75)`                      | Shortcut that resolves to `true` or `false`                |
| `report({ ip, categories, comment, timestamp })`       | Report an address or CIDR network                          |
| `bulkReport(rows)` / `bulkReportCsv(text)`             | Up to 10,000 reports in one request                        |
| `reports(ip, { page, perPage })` / `allReports(ip)`    | Reports filed against an address, newest first             |
| `checkBlock(network)`                                  | Reported addresses inside a network (up to /16 or /48)     |
| `blocklist(options)` / `blocklistRaw(format, options)` | The highest-confidence addresses                           |
| `clearAddress(ip)`                                     | Delete your own reports for an address                     |
| `categories()`                                         | All report categories and their slugs                      |

Options for `new Client()`: `apiKey`, `baseUrl`, `timeout` (ms, default 10000), `maxRetries` (default 2), `userAgent`, `fetch`.

### Errors

Every error extends `IsIPsafeError`.

| Error                 | When                                                        |
| --------------------- | ----------------------------------------------------------- |
| `AuthenticationError` | Missing or wrong API key (401)                              |
| `ValidationError`     | Invalid input, or an allowlisted address was reported (422) |
| `RateLimitError`      | Too many requests (429); see `.retryAfter`                  |
| `APIError`            | Any other error status; see `.status`                       |
| `NetworkError`        | The API could not be reached or timed out                   |

Invalid IP addresses and categories throw a `TypeError` before any request is made. Lookups are retried on network errors and 5xx responses. Reporting the same address twice within 15 minutes is not an error: `report()` resolves with `duplicate: true`.

## Command line

```console
$ npx isipsafe check 185.220.101.1
185.220.101.1  not flagged
  score       56/100 (Medium)
  reports     24 from 5 reporters
  categories  port-scan, hacking, vuln-scan, web-app-attack, c2
  network     DE AS60729 Stiftung Erneuerbare Freiheit
  flags       Tor exit
  details     https://isipsafe.com/ip/185.220.101.1

$ isipsafe report 203.0.113.50 -c ssh,brute-force -m "sshd: 212 failed logins"
$ isipsafe bulk-report reports.csv
$ isipsafe blocklist --format nftables --confidence-minimum 90 -o blocklist.nft
$ isipsafe check-block 185.220.101.0/24
$ isipsafe categories --json
```

`--fail-if-malicious` makes `check` exit with status `1` for malicious addresses, for use in shell scripts. Exit codes: `0` success, `1` malicious, `2` error.

## Links

- Official Usage Page: [isipsafe.com/integrations/nodejs](https://isipsafe.com/integrations/nodejs)
- Website: [isipsafe.com](https://isipsafe.com)
- API reference: [isipsafe.com/api](https://isipsafe.com/api)
- Python client: [isipsafe on PyPI](https://pypi.org/project/isipsafe/)

## Licence

The code in this repository is MIT licensed. Data returned by the isIPsafe API is covered by the [isIPsafe EULA](https://isipsafe.com/eula).
