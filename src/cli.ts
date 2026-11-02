import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { BLOCKLIST_FORMATS, Client, DEFAULT_BASE_URL, DEFAULT_MALICIOUS_THRESHOLD, isMalicious } from './client.js';
import { IsIPsafeError } from './errors.js';
import type { BlocklistFormat, CheckResult } from './types.js';
import { VERSION } from './version.js';

const EXIT_OK = 0;
const EXIT_MALICIOUS = 1;
const EXIT_ERROR = 2;

const HELP = `isipsafe ${VERSION} - check and report IP addresses with isIPsafe (https://isipsafe.com)

Usage: isipsafe <command> [options]

Commands:
  check <ip>             reputation of an IP address
      --max-age <days>   count reports from the last N days (1-365)
      --verbose          include the latest reports
      --threshold <n>    score at which an address counts as malicious (default ${DEFAULT_MALICIOUS_THRESHOLD})
      --fail-if-malicious  exit with status 1 when the address is malicious
  report <ip>            report an abusive IP address or network
      -c, --categories   comma separated, e.g. ssh,brute-force (required)
      -m, --comment      public comment, up to 1024 characters
      --timestamp        when it happened (RFC 3339), default now
  bulk-report <file>     upload a CSV (IP,Categories,ReportDate,Comment); - for stdin
  reports <ip>           list reports for an IP address (--page, --per-page, --max-age)
  check-block <cidr>     reported addresses inside a network (--max-age)
  blocklist              download the blocklist
      --format <f>       ${BLOCKLIST_FORMATS.join(', ')} (default txt)
      --confidence-minimum <n>  --limit <n>  --days <n>  --ip-version <4|6>
      --only-countries <CC,..>  --except-countries <CC,..>  -o, --output <file>
  clear <ip>             delete your own reports for an address
  categories             list report categories

Global options:
  --api-key <key>        API key (default: $ISIPSAFE_API_KEY)
  --timeout <seconds>    request timeout (default 10)
  --json                 print JSON
  -h, --help             show this help
  -v, --version          show the version

Exit codes: 0 success, 1 malicious (only with --fail-if-malicious), 2 error.
Reporting and the blocklist need a free API key: https://isipsafe.com/login
`;

interface Io {
  out: (text: string) => void;
  err: (text: string) => void;
  readStdin: () => string;
}

const defaultIo: Io = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
  readStdin: () => readFileSync(0, 'utf8'),
};

function describeCheck(result: CheckResult, threshold: number): string {
  const lines = [
    `${result.ipAddress}  ${isMalicious(result, threshold) ? 'MALICIOUS' : 'not flagged'}`,
    `  score       ${result.abuseConfidenceScore}/100 (${result.confidenceBand ?? 'n/a'})`,
    `  reports     ${result.totalReports} from ${result.numDistinctUsers} reporters`,
  ];
  if (result.lastReportedAt) lines.push(`  last seen   ${result.lastReportedAt}`);
  if (result.categories.length) lines.push(`  categories  ${result.categories.join(', ')}`);
  const network = [result.countryCode, result.asn ? `AS${result.asn}` : null, result.isp].filter(Boolean).join(' ');
  if (network) lines.push(`  network     ${network}`);
  const flags = [result.isTor ? 'Tor exit' : null, result.isWhitelisted ? 'allowlisted' : null].filter(Boolean);
  if (flags.length) lines.push(`  flags       ${flags.join(', ')}`);
  if (result.link) lines.push(`  details     ${result.link}`);
  return `${lines.join('\n')}\n`;
}

function int(value: string | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isInteger(n)) throw new TypeError(`--${name} must be a whole number`);
  return n;
}

function countries(value: string | undefined): string[] | undefined {
  if (!value) return undefined;
  return value
    .split(',')
    .map((c) => c.trim().toUpperCase())
    .filter(Boolean);
}

export async function main(argv: string[] = process.argv.slice(2), io: Io = defaultIo): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        'api-key': { type: 'string' },
        'base-url': { type: 'string' },
        timeout: { type: 'string' },
        json: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
        'max-age': { type: 'string' },
        verbose: { type: 'boolean' },
        threshold: { type: 'string' },
        'fail-if-malicious': { type: 'boolean' },
        categories: { type: 'string', short: 'c' },
        comment: { type: 'string', short: 'm' },
        timestamp: { type: 'string' },
        page: { type: 'string' },
        'per-page': { type: 'string' },
        format: { type: 'string' },
        'confidence-minimum': { type: 'string' },
        limit: { type: 'string' },
        days: { type: 'string' },
        'ip-version': { type: 'string' },
        'only-countries': { type: 'string' },
        'except-countries': { type: 'string' },
        output: { type: 'string', short: 'o' },
      },
    });
  } catch (error) {
    io.err(`isipsafe: ${(error as Error).message}\n`);
    return EXIT_ERROR;
  }
  const { values: opts, positionals } = parsed;
  if (opts.version) {
    io.out(`isipsafe ${VERSION}\n`);
    return EXIT_OK;
  }
  const [command, arg] = positionals;
  if (opts.help || !command) {
    io.out(HELP);
    return command || opts.help ? EXIT_OK : EXIT_ERROR;
  }

  const print = (value: unknown) => io.out(`${JSON.stringify(value, null, 2)}\n`);
  const need = (what: string): string => {
    if (!arg) throw new TypeError(`${command} needs ${what}`);
    return arg;
  };

  try {
    const timeoutSeconds = opts.timeout === undefined ? 10 : Number(opts.timeout);
    const client = new Client({
      apiKey: opts['api-key'],
      baseUrl: opts['base-url'] ?? DEFAULT_BASE_URL,
      timeout: Math.round(timeoutSeconds * 1000),
    });

    switch (command) {
      case 'check': {
        const threshold = int(opts.threshold, 'threshold') ?? DEFAULT_MALICIOUS_THRESHOLD;
        const result = await client.check(need('an IP address'), {
          maxAgeInDays: int(opts['max-age'], 'max-age'),
          verbose: opts.verbose,
        });
        if (opts.json) print({ ...result, isMalicious: isMalicious(result, threshold) });
        else {
          io.out(describeCheck(result, threshold));
          for (const r of result.reports ?? []) {
            io.out(`  - ${r.reportedAt}  ${r.categories.join(', ')}  ${r.comment ?? ''}`.trimEnd() + '\n');
          }
        }
        return opts['fail-if-malicious'] && isMalicious(result, threshold) ? EXIT_MALICIOUS : EXIT_OK;
      }
      case 'report': {
        if (!opts.categories) throw new TypeError('report needs --categories, e.g. -c ssh,brute-force');
        const result = await client.report({
          ip: need('an IP address'),
          categories: opts.categories,
          comment: opts.comment,
          timestamp: opts.timestamp,
        });
        if (opts.json) print(result);
        else if (result.duplicate) {
          io.out(`${result.ipAddress} was already reported by this account in the last 15 minutes\n`);
        } else {
          io.out(
            `reported ${result.ipAddress}, new score ${result.abuseConfidenceScore}/100  ${result.link ?? ''}`.trimEnd() +
              '\n',
          );
        }
        return EXIT_OK;
      }
      case 'bulk-report': {
        const file = need('a CSV file (or - for stdin)');
        const csv = file === '-' ? io.readStdin() : readFileSync(file, 'utf8');
        const result = await client.bulkReportCsv(csv);
        if (opts.json) print(result);
        else {
          io.out(`saved ${result.savedReports} reports, ${result.invalidReports.length} rejected\n`);
          for (const bad of result.invalidReports) io.err(`  row ${bad.rowNumber}: ${bad.input}: ${bad.error}\n`);
        }
        return EXIT_OK;
      }
      case 'reports': {
        const page = await client.reports(need('an IP address'), {
          maxAgeInDays: int(opts['max-age'], 'max-age'),
          page: int(opts.page, 'page'),
          perPage: int(opts['per-page'], 'per-page'),
        });
        if (opts.json) print(page);
        else {
          io.out(`${page.ipAddress}: ${page.total} reports (page ${page.page} of ${page.lastPage})\n`);
          for (const r of page.results) {
            io.out(`  ${r.reportedAt}  ${r.categories.join(', ')}  ${r.comment ?? ''}`.trimEnd() + '\n');
          }
        }
        return EXIT_OK;
      }
      case 'check-block': {
        const net = await client.checkBlock(need('a CIDR network'), { maxAgeInDays: int(opts['max-age'], 'max-age') });
        if (opts.json) print(net);
        else {
          io.out(`${net.networkAddress}/${net.netmask}: ${net.reportedAddress.length} reported addresses\n`);
          for (const a of net.reportedAddress) {
            io.out(
              `  ${a.ipAddress.padEnd(39)} score ${String(a.abuseConfidenceScore).padStart(3)}  ${a.numReports} reports\n`,
            );
          }
        }
        return EXIT_OK;
      }
      case 'blocklist': {
        const format = (opts.format ?? 'txt') as BlocklistFormat;
        const ipVersion = int(opts['ip-version'], 'ip-version');
        if (ipVersion !== undefined && ipVersion !== 4 && ipVersion !== 6)
          throw new TypeError('--ip-version must be 4 or 6');
        const text = await client.blocklistRaw(format, {
          confidenceMinimum: int(opts['confidence-minimum'], 'confidence-minimum'),
          limit: int(opts.limit, 'limit'),
          days: int(opts.days, 'days'),
          ipVersion,
          onlyCountries: countries(opts['only-countries']),
          exceptCountries: countries(opts['except-countries']),
        });
        if (opts.output) writeFileSync(opts.output, text);
        else io.out(text);
        return EXIT_OK;
      }
      case 'clear':
        print(await client.clearAddress(need('an IP address')));
        return EXIT_OK;
      case 'categories': {
        const cats = await client.categories();
        if (opts.json) print(cats);
        else for (const c of cats) io.out(`${c.slug.padEnd(22)} ${c.name}\n`);
        return EXIT_OK;
      }
      default:
        io.err(`isipsafe: unknown command '${command}'. Run isipsafe --help.\n`);
        return EXIT_ERROR;
    }
  } catch (error) {
    if (error instanceof IsIPsafeError || error instanceof TypeError || (error as NodeJS.ErrnoException).code) {
      io.err(`isipsafe: ${(error as Error).message}\n`);
      return EXIT_ERROR;
    }
    throw error;
  }
}
