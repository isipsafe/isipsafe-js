import {
  APIError,
  AuthenticationError,
  IsIPsafeError,
  NetworkError,
  RateLimitError,
  ValidationError,
} from './errors.js';
import { assertCidr, assertIP, assertIPOrCidr } from './ip.js';
import type {
  BlocklistFormat,
  BlocklistOptions,
  BulkReportResult,
  Categories,
  Category,
  CheckResult,
  NetworkResult,
  Report,
  ReportInput,
  ReportResult,
  ReportsPage,
} from './types.js';
import { VERSION } from './version.js';

export const DEFAULT_BASE_URL = 'https://isipsafe.com/api/v1';
export const DEFAULT_MALICIOUS_THRESHOLD = 75;
export const BLOCKLIST_FORMATS: readonly BlocklistFormat[] = [
  'json',
  'txt',
  'csv',
  'stix',
  'ipset',
  'nftables',
  'nginx',
  'apache',
  'mikrotik',
];

const MAX_CATEGORIES = 12;
const MAX_COMMENT_LENGTH = 1024;
const MAX_BULK_ROWS = 10000;

export interface ClientOptions {
  /** API key. Defaults to the ISIPSAFE_API_KEY environment variable when available. */
  apiKey?: string;
  baseUrl?: string;
  /** Request timeout in milliseconds. Default 10000. */
  timeout?: number;
  /** Retries for lookups on network errors and 5xx responses. Default 2. */
  maxRetries?: number;
  userAgent?: string;
  fetch?: typeof fetch;
}

type Query = Record<string, string | number | boolean | undefined | null>;

interface RequestOptions {
  query?: Query;
  body?: string;
  contentType?: string;
  requireKey?: boolean;
  retry?: boolean;
  accept?: string;
}

type Json = Record<string, unknown>;

function envApiKey(): string | undefined {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  const value = env?.ISIPSAFE_API_KEY?.trim() || env?.ISIPSAFE_KEY?.trim();
  return value || undefined;
}

function str(value: unknown): string | null {
  return value === undefined || value === null ? null : String(value);
}

function num(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function numOrNull(value: unknown): number | null {
  return value === undefined || value === null ? null : num(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

function numbers(value: unknown): number[] {
  return Array.isArray(value) ? value.map((v) => num(v)) : [];
}

function toReport(data: Json): Report {
  return {
    reportedAt: str(data.reportedAt),
    comment: str(data.comment),
    categories: strings(data.categories),
    categoryIds: numbers(data.categoryIds),
    reporter: str(data.reporter),
    reporterType: str(data.reporterType),
    reporterCountryCode: str(data.reporterCountryCode),
  };
}

function toCheckResult(data: Json): CheckResult {
  const result: CheckResult = {
    ipAddress: String(data.ipAddress ?? ''),
    abuseConfidenceScore: num(data.abuseConfidenceScore),
    confidenceBand: (str(data.confidenceBand) as CheckResult['confidenceBand']) ?? null,
    totalReports: num(data.totalReports),
    numDistinctUsers: num(data.numDistinctUsers),
    isPublic: data.isPublic !== false,
    isWhitelisted: data.isWhitelisted === true,
    isTor: data.isTor === true,
    ipVersion: data.ipVersion === 4 || data.ipVersion === 6 ? data.ipVersion : null,
    firstReportedAt: str(data.firstReportedAt),
    lastReportedAt: str(data.lastReportedAt),
    categories: strings(data.categories),
    categoryIds: numbers(data.categoryIds),
    countryCode: str(data.countryCode),
    countryName: str(data.countryName),
    region: str(data.region),
    city: str(data.city),
    asn: numOrNull(data.asn),
    isp: str(data.isp),
    domain: str(data.domain),
    usageType: str(data.usageType),
    hostnames: strings(data.hostnames),
    link: str(data.link),
  };
  if (Array.isArray(data.reports)) result.reports = (data.reports as Json[]).map(toReport);
  return result;
}

/**
 * True when the address has reports, is not allowlisted and its score reaches `threshold`.
 * Allowlisted addresses such as public DNS resolvers are never malicious.
 */
export function isMalicious(result: CheckResult, threshold = DEFAULT_MALICIOUS_THRESHOLD): boolean {
  if (result.isWhitelisted || result.totalReports === 0) return false;
  return result.abuseConfidenceScore >= threshold;
}

export function normalizeCategories(categories: Categories): string[] {
  const items =
    typeof categories === 'string' || typeof categories === 'number' ? String(categories).split(',') : categories;
  const result: string[] = [];
  for (const item of items) {
    const value = String(item).trim();
    if (value && !result.includes(value)) result.push(value);
  }
  if (result.length === 0) throw new TypeError("at least one category is required, e.g. 'ssh,brute-force'");
  if (result.length > MAX_CATEGORIES) {
    throw new TypeError(`at most ${MAX_CATEGORIES} categories per report, got ${result.length}`);
  }
  return result;
}

function formatTimestamp(value: string | Date | undefined): string | undefined {
  if (value === undefined || value === '') return undefined;
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new TypeError('timestamp is an invalid Date');
    return value.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }
  return String(value);
}

function csvField(value: string): string {
  const clean = value.replace(/[\r\n]+/g, ' ');
  return /[",]/.test(clean) ? `"${clean.replace(/"/g, '""')}"` : clean;
}

/** Builds the CSV body for a bulk upload (columns IP,Categories,ReportDate,Comment). */
export function buildBulkCsv(reports: Iterable<ReportInput>): string {
  const lines = ['IP,Categories,ReportDate,Comment'];
  let count = 0;
  for (const report of reports) {
    count += 1;
    if (count > MAX_BULK_ROWS) throw new TypeError(`at most ${MAX_BULK_ROWS} reports per bulk upload`);
    lines.push(
      [
        assertIPOrCidr(report.ip),
        normalizeCategories(report.categories).join(','),
        formatTimestamp(report.timestamp) ?? '',
        (report.comment ?? '').slice(0, MAX_COMMENT_LENGTH),
      ]
        .map(csvField)
        .join(','),
    );
  }
  if (count === 0) throw new TypeError('no reports to upload');
  return `${lines.join('\n')}\n`;
}

function errorDetail(body: unknown, fallback: string): string {
  if (body && typeof body === 'object') {
    const errors = (body as { errors?: unknown }).errors;
    if (Array.isArray(errors) && errors[0] && typeof errors[0] === 'object') {
      const detail = (errors[0] as { detail?: unknown }).detail;
      if (detail) return String(detail);
    }
    const detail = (body as { detail?: unknown }).detail;
    if (detail) return String(detail);
  }
  return fallback;
}

function parseJson(text: string): unknown {
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Client for the isIPsafe API (https://isipsafe.com/api). */
export class Client {
  readonly baseUrl: string;
  readonly timeout: number;
  readonly maxRetries: number;
  readonly userAgent: string;
  readonly #apiKey: string | undefined;
  readonly #fetch: typeof fetch;
  /** @internal */
  sleep: (ms: number) => Promise<void> = sleep;

  constructor(options: ClientOptions = {}) {
    const key = options.apiKey !== undefined ? options.apiKey.trim() : envApiKey();
    this.#apiKey = key || undefined;
    const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    if (!/^https?:\/\//.test(baseUrl)) throw new TypeError('baseUrl must start with https:// or http://');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.timeout = options.timeout ?? 10000;
    this.maxRetries = Math.max(0, Math.floor(options.maxRetries ?? 2));
    this.userAgent = options.userAgent ?? `isipsafe-js/${VERSION}`;
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== 'function') throw new IsIPsafeError('fetch is not available; pass options.fetch');
    this.#fetch = fetchImpl.bind(globalThis);
  }

  get hasApiKey(): boolean {
    return this.#apiKey !== undefined;
  }

  toJSON(): Record<string, unknown> {
    return { baseUrl: this.baseUrl, hasApiKey: this.hasApiKey };
  }

  /** Reputation of one address: score, report counts, location and network. */
  async check(ip: string, options: { maxAgeInDays?: number; verbose?: boolean } = {}): Promise<CheckResult> {
    const data = await this.#getJson('/check', {
      ip: assertIP(ip),
      maxAgeInDays: options.maxAgeInDays,
      verbose: options.verbose,
    });
    return toCheckResult(data as Json);
  }

  /** True when the address has reports and a score of at least `threshold` (default 75). */
  async isMalicious(ip: string, threshold = DEFAULT_MALICIOUS_THRESHOLD): Promise<boolean> {
    return isMalicious(await this.check(ip), threshold);
  }

  /**
   * Report an abusive address or CIDR network. A repeat within 15 minutes resolves with
   * `duplicate: true` instead of rejecting. The comment is public.
   */
  async report(input: ReportInput): Promise<ReportResult> {
    const ip = assertIPOrCidr(input.ip);
    const payload: Record<string, unknown> = { ip, categories: normalizeCategories(input.categories) };
    if (input.comment) payload.comment = input.comment.slice(0, MAX_COMMENT_LENGTH);
    const timestamp = formatTimestamp(input.timestamp);
    if (timestamp) payload.timestamp = timestamp;
    try {
      const text = await this.#request('POST', '/report', {
        body: JSON.stringify(payload),
        contentType: 'application/json',
        requireKey: true,
      });
      const data = this.#unwrap(text) as Json;
      return {
        ipAddress: String(data.ipAddress ?? ip),
        abuseConfidenceScore: numOrNull(data.abuseConfidenceScore),
        link: str(data.link),
        duplicate: false,
      };
    } catch (error) {
      if (error instanceof RateLimitError) {
        return { ipAddress: ip, abuseConfidenceScore: null, link: null, duplicate: true };
      }
      throw error;
    }
  }

  /** Upload up to 10,000 reports in one request. */
  async bulkReport(reports: Iterable<ReportInput>): Promise<BulkReportResult> {
    return this.bulkReportCsv(buildBulkCsv(reports));
  }

  /** Upload a CSV with columns IP,Categories,ReportDate,Comment as-is. */
  async bulkReportCsv(csv: string): Promise<BulkReportResult> {
    const text = await this.#request('POST', '/bulk-report', {
      body: csv,
      contentType: 'text/csv',
      requireKey: true,
      retry: false,
    });
    const data = this.#unwrap(text) as Json;
    const invalid = Array.isArray(data.invalidReports) ? (data.invalidReports as Json[]) : [];
    return {
      savedReports: num(data.savedReports),
      invalidReports: invalid.map((r) => ({
        rowNumber: numOrNull(r.rowNumber),
        input: str(r.input),
        error: String(r.error ?? ''),
      })),
    };
  }

  /** One page of reports for an address, newest first. */
  async reports(
    ip: string,
    options: { maxAgeInDays?: number; page?: number; perPage?: number } = {},
  ): Promise<ReportsPage> {
    const data = (await this.#getJson('/reports', {
      ip: assertIP(ip),
      maxAgeInDays: options.maxAgeInDays,
      page: options.page ?? 1,
      perPage: options.perPage ?? 25,
    })) as Json;
    return {
      ipAddress: String(data.ipAddress ?? ''),
      total: num(data.total),
      page: num(data.page, 1),
      perPage: num(data.perPage),
      lastPage: num(data.lastPage, 1),
      nextPageUrl: str(data.nextPageUrl),
      previousPageUrl: str(data.previousPageUrl),
      results: Array.isArray(data.results) ? (data.results as Json[]).map(toReport) : [],
    };
  }

  /** Every report for an address, fetching pages as needed. */
  async *allReports(ip: string, options: { maxAgeInDays?: number } = {}): AsyncGenerator<Report> {
    let page = 1;
    for (;;) {
      const result = await this.reports(ip, { ...options, page, perPage: 100 });
      yield* result.results;
      if (page >= result.lastPage || result.results.length === 0) return;
      page += 1;
    }
  }

  /** Reported addresses inside a network (IPv4 up to a /16, IPv6 up to a /48). */
  async checkBlock(network: string, options: { maxAgeInDays?: number } = {}): Promise<NetworkResult> {
    const data = (await this.#getJson('/check-block', {
      network: assertCidr(network),
      maxAgeInDays: options.maxAgeInDays,
    })) as Json;
    const reported = Array.isArray(data.reportedAddress) ? (data.reportedAddress as Json[]) : [];
    return {
      networkAddress: String(data.networkAddress ?? ''),
      netmask: num(data.netmask),
      minAddress: str(data.minAddress),
      maxAddress: str(data.maxAddress),
      numPossibleHosts: str(data.numPossibleHosts),
      asn: numOrNull(data.asn),
      isp: str(data.isp),
      countryCode: str(data.countryCode),
      reportedAddress: reported.map((r) => ({
        ipAddress: String(r.ipAddress ?? ''),
        abuseConfidenceScore: num(r.abuseConfidenceScore),
        numReports: num(r.numReports),
        mostRecentReport: str(r.mostRecentReport),
        countryCode: str(r.countryCode),
      })),
    };
  }

  /** The highest-confidence addresses as an array of strings. */
  async blocklist(options: BlocklistOptions = {}): Promise<string[]> {
    const text = await this.blocklistRaw('txt', options);
    return text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
  }

  /** The blocklist in a firewall-ready format. */
  async blocklistRaw(format: BlocklistFormat = 'txt', options: BlocklistOptions = {}): Promise<string> {
    if (!BLOCKLIST_FORMATS.includes(format)) {
      throw new TypeError(`format must be one of ${BLOCKLIST_FORMATS.join(', ')}`);
    }
    return this.#request('GET', '/blocklist', {
      query: {
        format,
        confidenceMinimum: options.confidenceMinimum,
        limit: options.limit,
        days: options.days,
        ipVersion: options.ipVersion,
        onlyCountries: options.onlyCountries?.join(','),
        exceptCountries: options.exceptCountries?.join(','),
      },
      requireKey: true,
      accept: '*/*',
    });
  }

  /** Delete every report this account filed against an address. */
  async clearAddress(ip: string): Promise<Record<string, unknown>> {
    const text = await this.#request('DELETE', '/clear-address', {
      query: { ip: assertIPOrCidr(ip) },
      requireKey: true,
    });
    const data = this.#unwrap(text);
    return data && typeof data === 'object' ? (data as Record<string, unknown>) : { result: data };
  }

  /** Every report category with its slug, name, group and numeric ID. */
  async categories(): Promise<Category[]> {
    const data = await this.#getJson('/categories');
    return (Array.isArray(data) ? (data as Json[]) : []).map((c) => ({
      id: num(c.id),
      slug: String(c.slug ?? ''),
      name: String(c.name ?? ''),
      group: str(c.group),
      description: str(c.description),
    }));
  }

  async #getJson(path: string, query?: Query): Promise<unknown> {
    return this.#unwrap(await this.#request('GET', path, { query }));
  }

  #unwrap(text: string): unknown {
    const parsed = parseJson(text);
    if (parsed && typeof parsed === 'object' && 'data' in parsed) return (parsed as { data: unknown }).data;
    if (parsed === undefined) throw new IsIPsafeError('the API returned a response that is not JSON');
    return parsed;
  }

  #url(path: string, query?: Query): string {
    const params = new URLSearchParams();
    for (const [name, value] of Object.entries(query ?? {})) {
      if (value === undefined || value === null || value === false || value === '') continue;
      params.append(name, value === true ? 'true' : String(value));
    }
    const qs = params.toString();
    return `${this.baseUrl}${path}${qs ? `?${qs}` : ''}`;
  }

  async #request(method: string, path: string, options: RequestOptions = {}): Promise<string> {
    if (options.requireKey && !this.#apiKey) {
      throw new AuthenticationError(
        'this endpoint needs an API key; get a free one at https://isipsafe.com/login and pass apiKey or set ISIPSAFE_API_KEY',
        401,
      );
    }
    const headers: Record<string, string> = {
      Accept: options.accept ?? 'application/json',
      'User-Agent': this.userAgent,
    };
    if (this.#apiKey) headers.Authorization = `Bearer ${this.#apiKey}`;
    if (options.contentType) headers['Content-Type'] = options.contentType;
    const url = this.#url(path, options.query);
    const attempts = 1 + (options.retry === false ? 0 : this.maxRetries);

    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const lastAttempt = attempt === attempts - 1;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);
      let response: Response;
      let text: string;
      try {
        response = await this.#fetch(url, { method, headers, body: options.body, signal: controller.signal });
        text = await response.text();
      } catch (error) {
        clearTimeout(timer);
        if (!lastAttempt) {
          await this.#backoff(attempt);
          continue;
        }
        const reason = controller.signal.aborted ? `timed out after ${this.timeout} ms` : String(error);
        throw new NetworkError(`could not reach ${this.baseUrl}: ${reason}`, error);
      }
      clearTimeout(timer);
      if (response.ok) return text;
      if (response.status >= 500 && !lastAttempt) {
        await this.#backoff(attempt);
        continue;
      }
      throw apiError(response.status, response.headers.get('Retry-After'), text);
    }
    throw new NetworkError(`could not reach ${this.baseUrl}`);
  }

  async #backoff(attempt: number): Promise<void> {
    await this.sleep(Math.min(500 * 2 ** attempt, 8000) + Math.random() * 250);
  }
}

function apiError(status: number, retryAfter: string | null, text: string): APIError {
  const body = parseJson(text);
  const message = errorDetail(body, `HTTP ${status}`);
  if (status === 401) return new AuthenticationError(message, status, body);
  if (status === 400 || status === 422) return new ValidationError(message, status, body);
  if (status === 429) {
    const seconds = retryAfter === null ? undefined : Number(retryAfter);
    return new RateLimitError(message, status, body, Number.isFinite(seconds) ? seconds : undefined);
  }
  return new APIError(message, status, body);
}
