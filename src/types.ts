export type ConfidenceBand = 'None' | 'Low' | 'Medium' | 'High';

export interface Report {
  reportedAt: string | null;
  comment: string | null;
  categories: string[];
  categoryIds: number[];
  reporter?: string | null;
  reporterType?: string | null;
  reporterCountryCode?: string | null;
}

export interface CheckResult {
  ipAddress: string;
  abuseConfidenceScore: number;
  confidenceBand: ConfidenceBand | null;
  totalReports: number;
  numDistinctUsers: number;
  isPublic: boolean;
  isWhitelisted: boolean;
  isTor: boolean;
  ipVersion: 4 | 6 | null;
  firstReportedAt: string | null;
  lastReportedAt: string | null;
  categories: string[];
  categoryIds: number[];
  countryCode: string | null;
  countryName: string | null;
  region: string | null;
  city: string | null;
  asn: number | null;
  isp: string | null;
  domain: string | null;
  usageType: string | null;
  hostnames: string[];
  link: string | null;
  reports?: Report[];
}

export interface ReportResult {
  ipAddress: string;
  abuseConfidenceScore: number | null;
  link: string | null;
  /** True when this account already reported the address in the last 15 minutes. */
  duplicate: boolean;
}

export interface InvalidReport {
  rowNumber: number | null;
  input: string | null;
  error: string;
}

export interface BulkReportResult {
  savedReports: number;
  invalidReports: InvalidReport[];
}

export interface ReportsPage {
  ipAddress: string;
  total: number;
  page: number;
  perPage: number;
  lastPage: number;
  nextPageUrl: string | null;
  previousPageUrl: string | null;
  results: Report[];
}

export interface ReportedAddress {
  ipAddress: string;
  abuseConfidenceScore: number;
  numReports: number;
  mostRecentReport: string | null;
  countryCode: string | null;
}

export interface NetworkResult {
  networkAddress: string;
  netmask: number;
  minAddress: string | null;
  maxAddress: string | null;
  numPossibleHosts: string | null;
  asn: number | null;
  isp: string | null;
  countryCode: string | null;
  reportedAddress: ReportedAddress[];
}

export interface Category {
  id: number;
  slug: string;
  name: string;
  group: string | null;
  description: string | null;
}

export type BlocklistFormat = 'json' | 'txt' | 'csv' | 'stix' | 'ipset' | 'nftables' | 'nginx' | 'apache' | 'mikrotik';

export interface BlocklistOptions {
  confidenceMinimum?: number;
  limit?: number;
  days?: number;
  ipVersion?: 4 | 6;
  onlyCountries?: string[];
  exceptCountries?: string[];
}

export type Categories = string | number | ReadonlyArray<string | number>;

export interface ReportInput {
  ip: string;
  categories: Categories;
  comment?: string;
  timestamp?: string | Date;
}
