// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { spawn } from 'child_process';
import { parseConfig } from '../config-parser.js';
import type {
  UrlHarvestAuthConfig,
  UrlHarvestConfig,
  UrlHarvestScopePolicy,
} from '../types/config.js';
import type { ActivityLogger } from '../types/activity-logger.js';

export type DiscoveryProfile = 'aggressive-broad';
export type AnalysisMode = 'url-first';

interface CrawlItem {
  url: string;
  depth: number;
}

interface HarvestOptions {
  maxPages: number;
  maxDepth: number;
  maxAssets: number;
  maxDiscoveredDomains: number;
  maxEndpointProbes: number;
  httpConcurrency: number;
  probeConcurrency: number;
  harvestTimeoutMinutes: number;
  autoClonePublicRepos: boolean;
  scopePolicy: UrlHarvestScopePolicy;
}

interface ReconCommandResult {
  command: string;
  args: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
  error?: string;
}

interface EndpointProbeResult {
  url: string;
  method: 'HEAD' | 'GET';
  status: number;
  ok: boolean;
  elapsedMs: number;
  location?: string;
  allow?: string[];
  contentType?: string | null;
  error?: string;
}

type EndpointKind = 'seed' | 'crawl' | 'form' | 'api' | 'js';
type ProbeStatus = 'reachable' | 'blocked' | 'redirect' | 'error' | 'unknown';
type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type FindingCategory =
  | 'cors'
  | 'headers'
  | 'exposure'
  | 'redirect'
  | 'reflection'
  | 'http-methods'
  | 'authz';

interface SecurityFinding {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  confidence: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  url: string;
  method: string;
  evidence: string[];
  reproduction?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    note?: string;
  };
}

interface ReachabilityEntry {
  url: string;
  status: ProbeStatus;
  lastStatusCode: number;
  methodsObserved: string[];
  kinds: EndpointKind[];
  discoveredFrom: string[];
  hasQueryParams: boolean;
  riskTags: string[];
}

interface ReachabilityMap {
  generatedAt: string;
  target: {
    webUrl: string;
    hostname: string;
    rootDomain: string;
  };
  totals: {
    endpointCandidates: number;
    endpointProbed: number;
    reachable: number;
    blocked: number;
    redirects: number;
    errors: number;
    unknown: number;
  };
  coverage: {
    probeCoveragePercent: number;
    reachablePercent: number;
  };
  findingsBySeverity: Record<FindingSeverity, number>;
  attackSurfaceScore: number;
  topReachable: string[];
  entries: ReachabilityEntry[];
}

interface HarvestAuthProfile {
  enabled: boolean;
  headers: Record<string, string>;
  summary: {
    enabled: boolean;
    headerNames: string[];
    cookieNames: string[];
    hasBearerToken: boolean;
    hasBasicAuth: boolean;
  };
}

interface OpenApiExtractionSummary {
  generatedAt: string;
  sourcesChecked: number;
  docsParsed: number;
  endpointsAdded: number;
  docs: Array<{
    sourceUrl: string;
    title?: string;
    version?: string;
    pathCount: number;
    endpointCount: number;
  }>;
}

interface GraphqlIntrospectionSummary {
  generatedAt: string;
  candidatesChecked: number;
  introspectionEnabled: number;
  results: Array<{
    endpoint: string;
    status: number;
    success: boolean;
    schemaTypeCount?: number;
    error?: string;
  }>;
}

interface AuthDifferentialSummary {
  generatedAt: string;
  enabled: boolean;
  candidatesChecked: number;
  protectedCount: number;
  publicCount: number;
  suspectedBypassCount: number;
  inconclusiveCount: number;
  results: Array<{
    endpoint: string;
    authStatus: number;
    unauthStatus: number;
    classification: 'protected' | 'public' | 'suspected-bypass' | 'inconclusive';
  }>;
}

export interface SourceOrigin {
  kind: 'manual-git' | 'manual-local' | 'discovered-public-git';
  location: string;
  workspacePath: string;
  cloned: boolean;
  note?: string;
}

export interface UrlHarvesterInput {
  webUrl: string;
  sessionId: string;
  manualSource?: string;
  configPath?: string;
  discoveryProfile?: DiscoveryProfile;
  targetsRoot?: string;
}

export interface UrlHarvesterResult {
  analysisPath: string;
  sourceOrigins: string[];
  sourceOriginDetails: SourceOrigin[];
  manifestPath: string;
  sourceInventoryPath: string;
  harvestSummary: string;
}

interface WorkspacePaths {
  root: string;
  rawHttp: string;
  rawAssets: string;
  rawJs: string;
  rawSourcemaps: string;
  reconstructedSource: string;
  recon: string;
  repos: string;
  deliverables: string;
}

const DEFAULT_OPTIONS: HarvestOptions = Object.freeze({
  maxPages: 1500,
  maxDepth: 6,
  maxAssets: 5000,
  maxDiscoveredDomains: 75,
  maxEndpointProbes: 4000,
  httpConcurrency: 20,
  probeConcurrency: 12,
  harvestTimeoutMinutes: 30,
  autoClonePublicRepos: true,
  scopePolicy: 'broad-discovery',
});

const ACTIVE_CHECK_LIMITS = Object.freeze({
  maxCorsChecks: 250,
  maxMethodChecks: 120,
  maxRedirectChecks: 80,
  maxReflectionChecks: 60,
  maxSensitivePathChecks: 20,
  maxOpenApiDocs: 20,
  maxGraphqlChecks: 20,
  maxAuthDifferentialChecks: 200,
  maxReachabilityEntries: 4000,
  responseSnippetBytes: 32_768,
});

const DANGEROUS_METHODS = new Set(['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']);

function toSafeInt(
  value: number | string | undefined,
  fallback: number,
  min: number,
  max: number
): number {
  const parsed = typeof value === 'string' ? Number(value) : value;
  if (typeof parsed !== 'number' || Number.isNaN(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

function toSafeBool(value: boolean | string | undefined, fallback: boolean): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
  }
  return fallback;
}

function resolveScopePolicy(value: string | undefined): UrlHarvestScopePolicy {
  if (value === 'same-origin' || value === 'first-party' || value === 'broad-discovery') {
    return value;
  }
  return DEFAULT_OPTIONS.scopePolicy;
}

function resolveHarvestOptions(overrides?: UrlHarvestConfig): HarvestOptions {
  if (!overrides) {
    return { ...DEFAULT_OPTIONS };
  }

  return {
    maxPages: toSafeInt(overrides.max_pages, DEFAULT_OPTIONS.maxPages, 1, 100_000),
    maxDepth: toSafeInt(overrides.max_depth, DEFAULT_OPTIONS.maxDepth, 0, 30),
    maxAssets: toSafeInt(overrides.max_assets, DEFAULT_OPTIONS.maxAssets, 0, 100_000),
    maxDiscoveredDomains: toSafeInt(
      overrides.max_discovered_domains,
      DEFAULT_OPTIONS.maxDiscoveredDomains,
      1,
      500
    ),
    maxEndpointProbes: toSafeInt(
      overrides.max_endpoint_probes,
      DEFAULT_OPTIONS.maxEndpointProbes,
      0,
      100_000
    ),
    httpConcurrency: toSafeInt(overrides.http_concurrency, DEFAULT_OPTIONS.httpConcurrency, 1, 200),
    probeConcurrency: toSafeInt(
      overrides.probe_concurrency,
      DEFAULT_OPTIONS.probeConcurrency,
      1,
      200
    ),
    harvestTimeoutMinutes: toSafeInt(
      overrides.harvest_timeout_minutes,
      DEFAULT_OPTIONS.harvestTimeoutMinutes,
      1,
      240
    ),
    autoClonePublicRepos: toSafeBool(
      overrides.auto_clone_public_repos,
      DEFAULT_OPTIONS.autoClonePublicRepos
    ),
    scopePolicy: resolveScopePolicy(typeof overrides.scope_policy === 'string'
      ? overrides.scope_policy
      : undefined),
  };
}

function hashText(value: string): string {
  return crypto.createHash('sha1').update(value).digest('hex');
}

function sanitizeSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/g, '_');
}

function normalizeUrl(rawUrl: string): string {
  const normalized = new URL(rawUrl);
  normalized.hash = '';
  return normalized.toString();
}

function toExtFromContentType(contentType: string | null, fallback: string): string {
  if (!contentType) return fallback;
  const normalized = contentType.toLowerCase();
  if (normalized.includes('text/html')) return 'html';
  if (normalized.includes('application/json')) return 'json';
  if (normalized.includes('javascript')) return 'js';
  if (normalized.includes('text/css')) return 'css';
  if (normalized.includes('xml')) return 'xml';
  if (normalized.includes('svg')) return 'svg';
  if (normalized.includes('plain')) return 'txt';
  return fallback;
}

function maybeUrl(base: string, candidate: string): string | null {
  if (!candidate) return null;
  const trimmed = candidate.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('javascript:') || trimmed.startsWith('data:') || trimmed.startsWith('mailto:')) {
    return null;
  }
  try {
    const resolved = new URL(trimmed, base);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
      return null;
    }
    resolved.hash = '';
    return resolved.toString();
  } catch {
    return null;
  }
}

function rootDomain(hostname: string): string {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length < 2) return hostname;
  return parts.slice(-2).join('.');
}

function isWithinScope(
  candidate: URL,
  targetHost: string,
  targetRootDomain: string,
  knownDomains: Set<string>,
  options: HarvestOptions
): boolean {
  if (options.scopePolicy === 'same-origin') {
    return candidate.hostname === targetHost;
  }

  if (options.scopePolicy === 'first-party') {
    return (
      candidate.hostname === targetHost ||
      candidate.hostname === targetRootDomain ||
      candidate.hostname.endsWith(`.${targetRootDomain}`)
    );
  }

  // broad-discovery
  if (knownDomains.has(candidate.hostname)) {
    return true;
  }

  return knownDomains.size < options.maxDiscoveredDomains;
}

function extractAttrUrls(html: string, baseUrl: string): string[] {
  const results: string[] = [];
  const attrRegex = /\b(?:href|src|action)\s*=\s*["']([^"']+)["']/gi;
  let match: RegExpExecArray | null = null;
  while ((match = attrRegex.exec(html)) !== null) {
    const parsed = maybeUrl(baseUrl, match[1] ?? '');
    if (parsed) {
      results.push(parsed);
    }
  }
  return results;
}

function extractFormEndpoints(html: string, baseUrl: string): string[] {
  const results: string[] = [];
  const formRegex = /<form[^>]*\baction\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let match: RegExpExecArray | null = null;
  while ((match = formRegex.exec(html)) !== null) {
    const endpoint = maybeUrl(baseUrl, match[1] ?? '');
    if (endpoint) {
      results.push(endpoint);
    }
  }
  return results;
}

function extractApiEndpointsFromText(text: string, baseUrl: string): string[] {
  const results = new Set<string>();

  // Absolute API URLs
  const absoluteRegex = /https?:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+\/api\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*/gi;
  let match: RegExpExecArray | null = null;
  while ((match = absoluteRegex.exec(text)) !== null) {
    const value = maybeUrl(baseUrl, match[0] ?? '');
    if (value) results.add(value);
  }

  // Relative /api paths
  const relativeRegex = /(^|["'`\s])\/api\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*/gi;
  while ((match = relativeRegex.exec(text)) !== null) {
    const segment = (match[0] ?? '').trim().replace(/^["'`]/, '');
    const value = maybeUrl(baseUrl, segment);
    if (value) results.add(value);
  }

  return Array.from(results);
}

function extractRepoLinks(text: string): string[] {
  const set = new Set<string>();
  const providerRegex =
    /https:\/\/(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?/gi;
  const genericGitRegex = /https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git/gi;

  let match: RegExpExecArray | null = null;
  while ((match = providerRegex.exec(text)) !== null) {
    if (match[0]) set.add(match[0].replace(/\/$/, ''));
  }
  while ((match = genericGitRegex.exec(text)) !== null) {
    if (match[0]) set.add(match[0].replace(/\/$/, ''));
  }

  return Array.from(set);
}

function isLikelyJsAsset(urlValue: string): boolean {
  try {
    const parsed = new URL(urlValue);
    const pathname = parsed.pathname.toLowerCase();
    return pathname.endsWith('.js') || pathname.endsWith('.mjs') || pathname.includes('/js/');
  } catch {
    return false;
  }
}

function isLikelyNavigablePage(urlValue: string): boolean {
  try {
    const parsed = new URL(urlValue);
    const pathname = parsed.pathname.toLowerCase();
    const blocked = [
      '.js', '.mjs', '.css', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg',
      '.ico', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.pdf', '.zip', '.tar',
      '.gz', '.mp4', '.mp3', '.wav', '.webm',
    ];
    return !blocked.some((ext) => pathname.endsWith(ext));
  } catch {
    return false;
  }
}

function normalizeRepoUrl(urlValue: string): string {
  const trimmed = urlValue.trim().replace(/\/$/, '');
  if (trimmed.endsWith('.git')) return trimmed;
  return `${trimmed}.git`;
}

function isAllowedGitUrl(urlValue: string): boolean {
  if (!urlValue.startsWith('https://')) {
    return false;
  }
  return /^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/.test(urlValue);
}

function isValidLocalRepoName(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
}

function isLikelyHostname(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith('.') || trimmed.endsWith('.')) return false;
  return /^[A-Za-z0-9.-]+$/.test(trimmed) && trimmed.includes('.');
}

function normalizeHeaderName(value: string): string {
  return value.trim().toLowerCase();
}

function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').trim();
}

function isSafeHeaderName(value: string): boolean {
  return /^[A-Za-z0-9-]+$/.test(value);
}

function isBlockedAuthHeader(value: string): boolean {
  const name = normalizeHeaderName(value);
  return (
    name === 'host' ||
    name === 'content-length' ||
    name === 'transfer-encoding' ||
    name === 'connection'
  );
}

function mergeHeaders(
  base: Record<string, string>,
  extra: Record<string, string> = {}
): Record<string, string> {
  const merged = new Map<string, string>();
  for (const [key, value] of Object.entries(base)) {
    const headerName = normalizeHeaderName(key);
    if (!headerName || !isSafeHeaderName(headerName)) continue;
    merged.set(headerName, value);
  }
  for (const [key, value] of Object.entries(extra)) {
    const headerName = normalizeHeaderName(key);
    if (!headerName || !isSafeHeaderName(headerName)) continue;
    merged.set(headerName, value);
  }
  return Object.fromEntries(merged.entries());
}

function buildHarvestAuthProfile(
  authConfig: UrlHarvestAuthConfig | undefined,
  logger: ActivityLogger
): HarvestAuthProfile {
  if (!authConfig) {
    return {
      enabled: false,
      headers: {},
      summary: {
        enabled: false,
        headerNames: [],
        cookieNames: [],
        hasBearerToken: false,
        hasBasicAuth: false,
      },
    };
  }

  const headers = new Map<string, string>();
  const headerNames = new Set<string>();
  const cookieNames: string[] = [];

  for (const [rawName, rawValue] of Object.entries(authConfig.headers ?? {})) {
    const headerName = normalizeHeaderName(rawName);
    const headerValue = sanitizeHeaderValue(rawValue ?? '');
    if (!headerName || !headerValue) continue;
    if (!isSafeHeaderName(headerName) || isBlockedAuthHeader(headerName)) continue;
    headers.set(headerName, headerValue);
    headerNames.add(headerName);
  }

  const cookiePairs: string[] = [];
  for (const [nameRaw, valueRaw] of Object.entries(authConfig.cookies ?? {})) {
    const name = sanitizeHeaderValue(nameRaw);
    const value = sanitizeHeaderValue(valueRaw ?? '');
    if (!name || !value) continue;
    if (!/^[A-Za-z0-9._-]+$/.test(name)) continue;
    cookiePairs.push(`${name}=${value}`);
    cookieNames.push(name);
  }
  if (cookiePairs.length > 0) {
    headers.set('cookie', cookiePairs.join('; '));
    headerNames.add('cookie');
  }

  const bearerToken = sanitizeHeaderValue(authConfig.bearer_token ?? '');
  const hasBearerToken = bearerToken.length > 0;
  const hasBasicAuth =
    typeof authConfig.basic_auth?.username === 'string' &&
    authConfig.basic_auth.username.length > 0 &&
    typeof authConfig.basic_auth?.password === 'string' &&
    authConfig.basic_auth.password.length > 0;

  if (hasBearerToken && hasBasicAuth) {
    logger.warn('url_harvest.auth has both bearer_token and basic_auth; bearer_token takes precedence');
  }

  if (hasBearerToken) {
    headers.set('authorization', `Bearer ${bearerToken}`);
    headerNames.add('authorization');
  } else if (hasBasicAuth) {
    const basicValue = Buffer.from(
      `${authConfig.basic_auth?.username ?? ''}:${authConfig.basic_auth?.password ?? ''}`,
      'utf8'
    ).toString('base64');
    headers.set('authorization', `Basic ${basicValue}`);
    headerNames.add('authorization');
  }

  const resolvedHeaders = Object.fromEntries(headers.entries());
  const enabled = Object.keys(resolvedHeaders).length > 0;

  return {
    enabled,
    headers: resolvedHeaders,
    summary: {
      enabled,
      headerNames: Array.from(headerNames).sort((a, b) => a.localeCompare(b)),
      cookieNames: Array.from(new Set(cookieNames)).sort((a, b) => a.localeCompare(b)),
      hasBearerToken,
      hasBasicAuth,
    },
  };
}

function toPercent(numerator: number, denominator: number): number {
  if (denominator <= 0) return 0;
  return Number(((numerator / denominator) * 100).toFixed(2));
}

function parseAllowHeader(value: string | null): string[] {
  if (!value) return [];
  const methods = value
    .split(',')
    .map((part) => part.trim().toUpperCase())
    .filter((part) => part.length > 0);
  return Array.from(new Set(methods));
}

function isFirstPartyUrl(urlValue: string, targetHost: string, targetRootDomain: string): boolean {
  try {
    const parsed = new URL(urlValue);
    return (
      parsed.hostname === targetHost ||
      parsed.hostname === targetRootDomain ||
      parsed.hostname.endsWith(`.${targetRootDomain}`)
    );
  } catch {
    return false;
  }
}

function extractQueryParamNames(urlValue: string): string[] {
  try {
    const parsed = new URL(urlValue);
    return Array.from(new Set(Array.from(parsed.searchParams.keys())));
  } catch {
    return [];
  }
}

function endpointRiskTags(urlValue: string): string[] {
  const tags = new Set<string>();
  try {
    const parsed = new URL(urlValue);
    const lowerPath = parsed.pathname.toLowerCase();
    const lowerParams = Array.from(parsed.searchParams.keys()).map((key) => key.toLowerCase());

    const keywordChecks: Array<[string, string]> = [
      ['auth', '/auth'],
      ['login', '/login'],
      ['admin', '/admin'],
      ['upload', '/upload'],
      ['api', '/api'],
      ['graphql', '/graphql'],
      ['debug', '/debug'],
      ['internal', '/internal'],
      ['config', '/config'],
      ['token', 'token'],
      ['redirect', 'redirect'],
      ['callback', 'callback'],
    ];

    for (const [tag, needle] of keywordChecks) {
      if (lowerPath.includes(needle) || lowerParams.some((param) => param.includes(needle))) {
        tags.add(tag);
      }
    }
  } catch {
    return [];
  }
  return Array.from(tags);
}

function classifyProbeStatus(statusCode: number): ProbeStatus {
  if (statusCode >= 200 && statusCode < 300) return 'reachable';
  if (statusCode >= 300 && statusCode < 400) return 'redirect';
  if (statusCode === 401 || statusCode === 403) return 'blocked';
  if (statusCode === 0 || statusCode >= 500) return 'error';
  return 'unknown';
}

function findingSeverityScore(severity: FindingSeverity): number {
  if (severity === 'critical') return 32;
  if (severity === 'high') return 20;
  if (severity === 'medium') return 10;
  if (severity === 'low') return 4;
  return 1;
}

function computeAttackSurfaceScore(
  findingsBySeverity: Record<FindingSeverity, number>,
  reachablePercent: number,
  probeCoveragePercent: number,
  totalRiskTagged: number
): number {
  const findingsScore =
    findingsBySeverity.critical * findingSeverityScore('critical') +
    findingsBySeverity.high * findingSeverityScore('high') +
    findingsBySeverity.medium * findingSeverityScore('medium') +
    findingsBySeverity.low * findingSeverityScore('low') +
    findingsBySeverity.info * findingSeverityScore('info');
  const reachScore = Math.min(30, Math.round(reachablePercent / 3.5));
  const coverageScore = Math.min(20, Math.round(probeCoveragePercent / 5));
  const riskTagScore = Math.min(15, totalRiskTagged);
  return Math.min(100, findingsScore + reachScore + coverageScore + riskTagScore);
}

function findingsToMarkdown(
  findings: SecurityFinding[],
  reachability: ReachabilityMap
): string {
  const lines: string[] = [];
  lines.push('# URL-First Security Findings');
  lines.push('');
  lines.push(`Generated: ${reachability.generatedAt}`);
  lines.push(`Target: ${reachability.target.webUrl}`);
  lines.push('');
  lines.push('## Coverage and Reach');
  lines.push(`- Endpoint candidates: ${reachability.totals.endpointCandidates}`);
  lines.push(`- Endpoints probed: ${reachability.totals.endpointProbed}`);
  lines.push(`- Reachable: ${reachability.totals.reachable}`);
  lines.push(`- Blocked (401/403): ${reachability.totals.blocked}`);
  lines.push(`- Redirecting: ${reachability.totals.redirects}`);
  lines.push(`- Error/timeout: ${reachability.totals.errors}`);
  lines.push(`- Probe coverage: ${reachability.coverage.probeCoveragePercent}%`);
  lines.push(`- Reachable ratio: ${reachability.coverage.reachablePercent}%`);
  lines.push(`- Attack surface score: ${reachability.attackSurfaceScore}/100`);
  lines.push('');
  lines.push('## Findings by Severity');
  lines.push(`- Critical: ${reachability.findingsBySeverity.critical}`);
  lines.push(`- High: ${reachability.findingsBySeverity.high}`);
  lines.push(`- Medium: ${reachability.findingsBySeverity.medium}`);
  lines.push(`- Low: ${reachability.findingsBySeverity.low}`);
  lines.push(`- Info: ${reachability.findingsBySeverity.info}`);
  lines.push('');
  if (findings.length === 0) {
    lines.push('## Findings');
    lines.push('No active security findings were confirmed by automated checks in this run.');
    return lines.join('\n');
  }
  lines.push('## Findings');
  for (const finding of findings) {
    lines.push('');
    lines.push(`### [${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push(`- Category: ${finding.category}`);
    lines.push(`- Confidence: ${finding.confidence}`);
    lines.push(`- URL: ${finding.url}`);
    lines.push(`- Method: ${finding.method}`);
    lines.push(`- Description: ${finding.description}`);
    lines.push('- Evidence:');
    for (const evidence of finding.evidence) {
      lines.push(`  - ${evidence}`);
    }
  }
  return lines.join('\n');
}

async function writeText(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content, 'utf8');
}

async function writeJson(filePath: string, data: unknown): Promise<void> {
  await writeText(filePath, JSON.stringify(data, null, 2));
}

async function runInBatches<T>(
  items: T[],
  batchSize: number,
  processor: (item: T) => Promise<void>
): Promise<void> {
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    await Promise.all(batch.map((item) => processor(item)));
  }
}

async function fetchWithTimeoutInit(
  targetUrl: string,
  timeoutMs: number,
  init?: {
    method?: string;
    redirect?: 'follow' | 'error' | 'manual';
    headers?: Record<string, string>;
    body?: string;
  }
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const headers = mergeHeaders(
    {
      'user-agent': 'Shannon-URL-Harvester/1.0',
      accept: '*/*',
    },
    init?.headers ?? {}
  );
  try {
    const requestInit: RequestInit = {
      redirect: init?.redirect ?? 'follow',
      signal: controller.signal,
      headers,
    };
    if (init?.method) {
      requestInit.method = init.method;
    }
    if (typeof init?.body === 'string') {
      requestInit.body = init.body;
    }
    return await fetch(targetUrl, requestInit);
  } finally {
    clearTimeout(timer);
  }
}

async function readResponseSnippet(response: Response, maxBytes: number): Promise<string> {
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length <= maxBytes) {
    return bytes.toString('utf8');
  }
  return bytes.subarray(0, maxBytes).toString('utf8');
}

async function runCommandCapture(
  command: string,
  args: string[],
  cwd: string,
  timeoutMs: number
): Promise<ReconCommandResult> {
  return await new Promise((resolve) => {
    const resolveFailure = (error: string) => {
      resolve({
        command,
        args,
        exitCode: null,
        stdout: '',
        stderr: '',
        error,
      });
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, {
        cwd,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      });
    } catch (error) {
      resolveFailure(error instanceof Error ? error.message : String(error));
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    const stdout = child.stdout;
    const stderr = child.stderr;
    if (!stdout || !stderr) {
      resolveFailure('Command output streams are unavailable');
      return;
    }

    stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
    stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({
        command,
        args,
        exitCode: null,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        error: error.message,
      });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        command,
        args,
        exitCode: code,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        ...(timedOut ? { error: 'Command timed out' } : {}),
      });
    });
  });
}

function createWorkspacePaths(root: string): WorkspacePaths {
  return {
    root,
    rawHttp: path.join(root, 'raw', 'http'),
    rawAssets: path.join(root, 'raw', 'assets'),
    rawJs: path.join(root, 'raw', 'js'),
    rawSourcemaps: path.join(root, 'raw', 'sourcemaps'),
    reconstructedSource: path.join(root, 'reconstructed', 'source'),
    recon: path.join(root, 'recon'),
    repos: path.join(root, 'repos'),
    deliverables: path.join(root, 'deliverables'),
  };
}

async function ensureWorkspaceLayout(paths: WorkspacePaths): Promise<void> {
  await Promise.all([
    fs.mkdir(paths.rawHttp, { recursive: true }),
    fs.mkdir(paths.rawAssets, { recursive: true }),
    fs.mkdir(paths.rawJs, { recursive: true }),
    fs.mkdir(paths.rawSourcemaps, { recursive: true }),
    fs.mkdir(paths.reconstructedSource, { recursive: true }),
    fs.mkdir(paths.recon, { recursive: true }),
    fs.mkdir(paths.repos, { recursive: true }),
    fs.mkdir(paths.deliverables, { recursive: true }),
  ]);
}

function safeReconstructedPath(rootDir: string, sourcePath: string): string {
  let cleaned = sourcePath
    .replace(/^webpack:\/\//, '')
    .replace(/^ng:\/\//, '')
    .replace(/^\/+/, '');
  cleaned = cleaned.replace(/[<>:"|?*]/g, '_');
  const resolved = path.resolve(rootDir, cleaned);
  const normalizedRoot = path.resolve(rootDir);
  if (!resolved.startsWith(normalizedRoot)) {
    return path.join(rootDir, `_escaped_${hashText(sourcePath)}.txt`);
  }
  return resolved;
}

async function cloneRepository(urlValue: string, destination: string): Promise<boolean> {
  await fs.rm(destination, { recursive: true, force: true });
  await fs.mkdir(path.dirname(destination), { recursive: true });
  const result = await runCommandCapture('git', ['clone', '--depth', '1', urlValue, destination], process.cwd(), 180000);
  return result.exitCode === 0;
}

async function copyLocalRepository(sourceRepoName: string, destination: string): Promise<boolean> {
  const sourcePath = path.join('/repos', sourceRepoName);
  try {
    const stat = await fs.stat(sourcePath);
    if (!stat.isDirectory()) {
      return false;
    }
  } catch {
    return false;
  }
  await fs.rm(destination, { recursive: true, force: true });
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.cp(sourcePath, destination, { recursive: true });
  return true;
}

export async function prepareUrlWorkspace(
  input: UrlHarvesterInput,
  logger: ActivityLogger
): Promise<UrlHarvesterResult> {
  const targetUrl = normalizeUrl(input.webUrl);
  const target = new URL(targetUrl);
  const targetHost = target.hostname;
  const targetRootDomain = rootDomain(targetHost);
  const startedAt = new Date().toISOString();

  const config = input.configPath ? await parseConfig(input.configPath).catch(() => null) : null;
  const options = resolveHarvestOptions(config?.url_harvest);
  const authProfile = buildHarvestAuthProfile(config?.url_harvest?.auth, logger);
  const targetsRoot = input.targetsRoot || '/targets';
  const analysisPath = path.join(targetsRoot, input.sessionId);
  const paths = createWorkspacePaths(analysisPath);

  logger.info('Preparing URL-first workspace', {
    sessionId: input.sessionId,
    analysisPath,
    profile: input.discoveryProfile || 'aggressive-broad',
    authEnabled: authProfile.summary.enabled,
    authHeaders: authProfile.summary.headerNames,
    authCookies: authProfile.summary.cookieNames,
  });

  function authHeadersForUrl(urlValue: string): Record<string, string> {
    if (!authProfile.enabled) return {};
    if (!isFirstPartyUrl(urlValue, targetHost, targetRootDomain)) {
      return {};
    }
    return authProfile.headers;
  }

  async function fetchTargetWithTimeout(urlValue: string, timeoutMs: number): Promise<Response> {
    return fetchWithTimeoutInit(urlValue, timeoutMs, {
      headers: authHeadersForUrl(urlValue),
    });
  }

  async function fetchTargetWithTimeoutInit(
    urlValue: string,
    timeoutMs: number,
    init?: {
      method?: string;
      redirect?: 'follow' | 'error' | 'manual';
      headers?: Record<string, string>;
      body?: string;
    }
  ): Promise<Response> {
    const mergedHeaders = mergeHeaders(authHeadersForUrl(urlValue), init?.headers ?? {});
    return fetchWithTimeoutInit(urlValue, timeoutMs, {
      ...init,
      headers: mergedHeaders,
    });
  }

  await fs.rm(analysisPath, { recursive: true, force: true });
  await ensureWorkspaceLayout(paths);

  const sourceOriginDetails: SourceOrigin[] = [];
  const sourceOrigins: string[] = [];

  const knownDomains = new Set<string>([targetHost]);
  const visitedPages = new Set<string>();
  const queuedPages = new Set<string>();
  const discoveredUrls = new Set<string>();
  const discoveredAssets = new Set<string>();
  const discoveredJs = new Set<string>();
  const discoveredEndpoints = new Set<string>();
  const endpointMetadata = new Map<
    string,
    {
      sources: Set<string>;
      kinds: Set<EndpointKind>;
      queryParams: Set<string>;
    }
  >();
  const discoveredRepos = new Set<string>();
  const sourcemapUrls = new Set<string>();
  let reconstructedFiles = 0;
  let downloadedAssets = 0;
  let downloadedJs = 0;
  let downloadedSourcemaps = 0;

  function registerEndpoint(endpointUrl: string, discoveredFrom: string, kind: EndpointKind): void {
    let normalized: string;
    try {
      normalized = normalizeUrl(endpointUrl);
    } catch {
      return;
    }
    discoveredEndpoints.add(normalized);
    const paramNames = extractQueryParamNames(normalized);
    const existing = endpointMetadata.get(normalized);
    if (existing) {
      existing.sources.add(discoveredFrom);
      existing.kinds.add(kind);
      for (const param of paramNames) {
        existing.queryParams.add(param);
      }
      return;
    }
    endpointMetadata.set(normalized, {
      sources: new Set<string>([discoveredFrom]),
      kinds: new Set<EndpointKind>([kind]),
      queryParams: new Set<string>(paramNames),
    });
  }

  registerEndpoint(targetUrl, targetUrl, 'seed');

  const crawlQueue: CrawlItem[] = [{ url: targetUrl, depth: 0 }];
  queuedPages.add(targetUrl);
  const harvestDeadline = Date.now() + options.harvestTimeoutMinutes * 60_000;

  function isTimedOut(): boolean {
    return Date.now() >= harvestDeadline;
  }

  async function storeHttpBody(
    baseDir: string,
    urlValue: string,
    contentType: string | null,
    body: string | Buffer
  ): Promise<void> {
    const parsed = new URL(urlValue);
    const extension = toExtFromContentType(contentType, 'txt');
    const filename = `${sanitizeSegment(parsed.hostname)}_${hashText(urlValue)}.${extension}`;
    const outputPath = path.join(baseDir, filename);
    await fs.writeFile(outputPath, body);
  }

  async function processSourcemap(
    jsUrl: string,
    jsContent: string
  ): Promise<void> {
    const mapMatch =
      jsContent.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s]+)/i) ||
      jsContent.match(/\/\*[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)\s*\*\//i);
    if (!mapMatch || !mapMatch[1]) {
      return;
    }

    const mapUrl = maybeUrl(jsUrl, mapMatch[1]);
    if (!mapUrl || sourcemapUrls.has(mapUrl)) {
      return;
    }
    sourcemapUrls.add(mapUrl);

    try {
      const response = await fetchTargetWithTimeout(mapUrl, 20000);
      const mapText = await response.text();
      await storeHttpBody(paths.rawSourcemaps, mapUrl, response.headers.get('content-type'), mapText);
      downloadedSourcemaps += 1;

      const parsed = JSON.parse(mapText) as {
        sources?: string[];
        sourcesContent?: Array<string | null>;
      };
      if (!Array.isArray(parsed.sources) || !Array.isArray(parsed.sourcesContent)) {
        return;
      }

      const limit = Math.min(parsed.sources.length, parsed.sourcesContent.length);
      for (let i = 0; i < limit; i++) {
        const sourcePath = parsed.sources[i];
        const sourceContent = parsed.sourcesContent[i];
        if (!sourcePath || typeof sourceContent !== 'string') {
          continue;
        }
        const outputPath = safeReconstructedPath(paths.reconstructedSource, sourcePath);
        await fs.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.writeFile(outputPath, sourceContent, 'utf8');
        reconstructedFiles += 1;
      }
    } catch (error) {
      logger.warn(`Failed to process sourcemap for ${jsUrl}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async function processPage(item: CrawlItem): Promise<void> {
    if (visitedPages.size >= options.maxPages) return;
    if (item.depth > options.maxDepth) return;
    if (isTimedOut()) return;

    if (visitedPages.has(item.url)) {
      return;
    }
    visitedPages.add(item.url);
    discoveredUrls.add(item.url);
    registerEndpoint(item.url, item.url, 'crawl');

    let response: Response;
    try {
      response = await fetchTargetWithTimeout(item.url, 20000);
    } catch (error) {
      logger.warn(`Page fetch failed: ${item.url} (${error instanceof Error ? error.message : String(error)})`);
      return;
    }

    const contentType = response.headers.get('content-type');
    const body = await response.text();
    await storeHttpBody(paths.rawHttp, item.url, contentType, body);

    const links = extractAttrUrls(body, item.url);
    const formEndpoints = extractFormEndpoints(body, item.url);
    const apiEndpoints = extractApiEndpointsFromText(body, item.url);
    const repoLinks = extractRepoLinks(body);

    for (const entry of formEndpoints) registerEndpoint(entry, item.url, 'form');
    for (const entry of apiEndpoints) registerEndpoint(entry, item.url, 'api');
    for (const entry of repoLinks) discoveredRepos.add(entry);

    for (const discovered of links) {
      discoveredUrls.add(discovered);
      if (isLikelyJsAsset(discovered)) {
        discoveredJs.add(discovered);
      } else {
        discoveredAssets.add(discovered);
      }

      let parsed: URL;
      try {
        parsed = new URL(discovered);
      } catch {
        continue;
      }
      if (!isWithinScope(parsed, targetHost, targetRootDomain, knownDomains, options)) {
        continue;
      }
      if (!knownDomains.has(parsed.hostname)) {
        knownDomains.add(parsed.hostname);
      }

      if (item.depth + 1 > options.maxDepth) {
        continue;
      }
      if (!isLikelyNavigablePage(discovered)) {
        continue;
      }
      if (!queuedPages.has(discovered) && !visitedPages.has(discovered)) {
        queuedPages.add(discovered);
        crawlQueue.push({ url: discovered, depth: item.depth + 1 });
      }
    }

    // Mine inline JS fragments for API endpoints and repo links.
    const scriptTagRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    let scriptMatch: RegExpExecArray | null = null;
    while ((scriptMatch = scriptTagRegex.exec(body)) !== null) {
      const inlineText = scriptMatch[1] ?? '';
      for (const endpoint of extractApiEndpointsFromText(inlineText, item.url)) {
        registerEndpoint(endpoint, item.url, 'api');
      }
      for (const repoLink of extractRepoLinks(inlineText)) {
        discoveredRepos.add(repoLink);
      }
    }
  }

  while (
    crawlQueue.length > 0 &&
    visitedPages.size < options.maxPages &&
    !isTimedOut()
  ) {
    const batch = crawlQueue.splice(0, options.httpConcurrency);
    await Promise.all(batch.map((item) => processPage(item)));
  }

  const allAssetCandidates = Array.from(new Set([
    ...Array.from(discoveredJs),
    ...Array.from(discoveredAssets).filter((asset) => !discoveredJs.has(asset)),
  ])).slice(0, options.maxAssets);

  async function processAsset(assetUrl: string): Promise<void> {
    if (isTimedOut()) return;
    try {
      const response = await fetchTargetWithTimeout(assetUrl, 20000);
      const contentType = response.headers.get('content-type');
      const isJs = isLikelyJsAsset(assetUrl) || (contentType || '').includes('javascript');
      if (isJs) {
        const jsContent = await response.text();
        await storeHttpBody(paths.rawJs, assetUrl, contentType, jsContent);
        downloadedJs += 1;
        for (const endpoint of extractApiEndpointsFromText(jsContent, assetUrl)) {
          registerEndpoint(endpoint, assetUrl, 'js');
        }
        for (const repoLink of extractRepoLinks(jsContent)) {
          discoveredRepos.add(repoLink);
        }
        await processSourcemap(assetUrl, jsContent);
      } else {
        const bytes = Buffer.from(await response.arrayBuffer());
        await storeHttpBody(paths.rawAssets, assetUrl, contentType, bytes);
        downloadedAssets += 1;
      }
    } catch (error) {
      logger.warn(`Asset fetch failed: ${assetUrl} (${error instanceof Error ? error.message : String(error)})`);
    }
  }

  for (let i = 0; i < allAssetCandidates.length && !isTimedOut(); i += options.httpConcurrency) {
    const batch = allAssetCandidates.slice(i, i + options.httpConcurrency);
    await Promise.all(batch.map((assetUrl) => processAsset(assetUrl)));
  }

  const openApiSummary: OpenApiExtractionSummary = {
    generatedAt: new Date().toISOString(),
    sourcesChecked: 0,
    docsParsed: 0,
    endpointsAdded: 0,
    docs: [],
  };

  const openApiCandidates = new Set<string>();
  const defaultOpenApiPaths = [
    '/openapi.json',
    '/swagger.json',
    '/v3/api-docs',
    '/v2/api-docs',
    '/api-docs',
  ];
  for (const relativePath of defaultOpenApiPaths) {
    try {
      const resolved = new URL(relativePath, `${target.protocol}//${target.host}`).toString();
      openApiCandidates.add(resolved);
    } catch {
      // Ignore malformed candidate paths.
    }
  }

  for (const endpoint of discoveredEndpoints) {
    try {
      const parsed = new URL(endpoint);
      const lowerPath = parsed.pathname.toLowerCase();
      if (
        lowerPath.includes('openapi') ||
        lowerPath.includes('swagger') ||
        lowerPath.includes('api-docs')
      ) {
        openApiCandidates.add(endpoint);
      }
    } catch {
      // Ignore malformed endpoint strings.
    }
  }

  const openApiCandidateList = Array.from(openApiCandidates)
    .filter((endpoint) => isFirstPartyUrl(endpoint, targetHost, targetRootDomain))
    .slice(0, ACTIVE_CHECK_LIMITS.maxOpenApiDocs);

  for (const docUrl of openApiCandidateList) {
    if (isTimedOut()) break;
    openApiSummary.sourcesChecked += 1;
    try {
      const response = await fetchTargetWithTimeoutInit(docUrl, 15000, {
        method: 'GET',
        redirect: 'follow',
        headers: {
          'User-Agent': 'Shannon-OpenAPI-Extractor/1.0',
        },
      });
      if (!response.ok) {
        continue;
      }
      const jsonText = await response.text();
      const parsed = JSON.parse(jsonText) as {
        openapi?: string;
        swagger?: string;
        info?: { title?: string; version?: string };
        paths?: Record<string, unknown>;
      };
      if (!parsed || typeof parsed !== 'object' || typeof parsed.paths !== 'object') {
        continue;
      }
      if (!parsed.openapi && !parsed.swagger) {
        continue;
      }
      const pathEntries = Object.entries(parsed.paths ?? {}).filter(([key]) => key.startsWith('/'));
      if (pathEntries.length === 0) {
        continue;
      }

      const beforeCount = discoveredEndpoints.size;
      let endpointCount = 0;
      for (const [rawPath] of pathEntries) {
        const sanitizedPath = rawPath.replace(/\{[^/}]+\}/g, '1');
        let resolvedPath: string;
        try {
          resolvedPath = new URL(sanitizedPath, docUrl).toString();
        } catch {
          continue;
        }
        registerEndpoint(resolvedPath, docUrl, 'api');
        endpointCount += 1;
      }
      const added = discoveredEndpoints.size - beforeCount;
      openApiSummary.docsParsed += 1;
      openApiSummary.endpointsAdded += Math.max(0, added);
      const docSummary: {
        sourceUrl: string;
        title?: string;
        version?: string;
        pathCount: number;
        endpointCount: number;
      } = {
        sourceUrl: docUrl,
        pathCount: pathEntries.length,
        endpointCount,
      };
      if (parsed.info?.title) {
        docSummary.title = parsed.info.title;
      }
      const docVersion = parsed.info?.version ?? parsed.openapi ?? parsed.swagger;
      if (docVersion) {
        docSummary.version = docVersion;
      }
      openApiSummary.docs.push({
        ...docSummary,
      });
    } catch {
      // Best-effort extraction.
    }
  }

  // Probe endpoints aggressively (bounded by maxEndpointProbes).
  const endpointProbeInputs = Array.from(discoveredEndpoints).slice(0, options.maxEndpointProbes);
  const endpointProbeResults: EndpointProbeResult[] = [];

  async function probeEndpoint(endpointUrl: string): Promise<void> {
    if (isTimedOut()) return;
    const start = Date.now();
    try {
      const headResponse = await fetchTargetWithTimeoutInit(endpointUrl, 15000, {
        method: 'HEAD',
        redirect: 'manual',
        headers: {
          'User-Agent': 'Shannon-Endpoint-Prober/1.0',
        },
      });
      const headAllow = parseAllowHeader(headResponse.headers.get('allow'));
      const headRecord: EndpointProbeResult = {
        url: endpointUrl,
        method: 'HEAD',
        status: headResponse.status,
        ok: headResponse.ok,
        elapsedMs: Date.now() - start,
        contentType: headResponse.headers.get('content-type'),
      };
      const headLocation = headResponse.headers.get('location');
      if (headLocation) {
        headRecord.location = headLocation;
      }
      if (headAllow.length > 0) {
        headRecord.allow = headAllow;
      }
      endpointProbeResults.push(headRecord);

      if (headResponse.status === 405 || headResponse.status === 501) {
        const getStart = Date.now();
        const getResponse = await fetchTargetWithTimeoutInit(endpointUrl, 15000, {
          method: 'GET',
          redirect: 'manual',
          headers: {
            'User-Agent': 'Shannon-Endpoint-Prober/1.0',
          },
        });
        const getAllow = parseAllowHeader(getResponse.headers.get('allow'));
        const getRecord: EndpointProbeResult = {
          url: endpointUrl,
          method: 'GET',
          status: getResponse.status,
          ok: getResponse.ok,
          elapsedMs: Date.now() - getStart,
          contentType: getResponse.headers.get('content-type'),
        };
        const getLocation = getResponse.headers.get('location');
        if (getLocation) {
          getRecord.location = getLocation;
        }
        if (getAllow.length > 0) {
          getRecord.allow = getAllow;
        }
        endpointProbeResults.push(getRecord);
      }
    } catch (error) {
      endpointProbeResults.push({
        url: endpointUrl,
        method: 'HEAD',
        status: 0,
        ok: false,
        elapsedMs: Date.now() - start,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const endpointProbeQueue = endpointProbeInputs;
  await runInBatches(endpointProbeQueue, options.probeConcurrency, probeEndpoint);
  await writeJson(path.join(paths.recon, 'endpoint-probes.json'), endpointProbeResults);

  // Recon command suite.
  const nmapResult = await runCommandCapture(
    'nmap',
    ['-Pn', '-T4', targetHost],
    paths.recon,
    120000
  );
  await writeJson(path.join(paths.recon, 'nmap.json'), nmapResult);

  const subfinderResult = await runCommandCapture(
    'subfinder',
    ['-d', targetRootDomain, '-silent'],
    paths.recon,
    120000
  );
  await writeJson(path.join(paths.recon, 'subfinder.json'), subfinderResult);
  if (subfinderResult.stdout) {
    const lines = subfinderResult.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    let capped = 0;
    for (const line of lines) {
      if (!isLikelyHostname(line)) continue;
      if (!knownDomains.has(line) && knownDomains.size >= options.maxDiscoveredDomains) {
        capped += 1;
        continue;
      }
      knownDomains.add(line);
      discoveredUrls.add(`https://${line}`);
    }
    if (capped > 0) {
      logger.info('Subfinder domain list was capped by maxDiscoveredDomains', {
        maxDiscoveredDomains: options.maxDiscoveredDomains,
        skipped: capped,
      });
    }
  }

  const whatwebResult = await runCommandCapture(
    'whatweb',
    [targetUrl],
    paths.recon,
    120000
  );
  await writeJson(path.join(paths.recon, 'whatweb.json'), whatwebResult);

  // Build endpoint reachability map from probe results and metadata.
  const endpointRollup = new Map<
    string,
    {
      status: ProbeStatus;
      lastStatusCode: number;
      methodsObserved: Set<string>;
      kinds: Set<EndpointKind>;
      discoveredFrom: Set<string>;
      hasQueryParams: boolean;
      riskTags: Set<string>;
    }
  >();

  for (const endpoint of endpointProbeInputs) {
    const metadata = endpointMetadata.get(endpoint);
    endpointRollup.set(endpoint, {
      status: 'unknown',
      lastStatusCode: 0,
      methodsObserved: new Set<string>(),
      kinds: new Set<EndpointKind>(metadata ? Array.from(metadata.kinds) : ['seed']),
      discoveredFrom: new Set<string>(metadata ? Array.from(metadata.sources) : [targetUrl]),
      hasQueryParams: metadata ? metadata.queryParams.size > 0 : extractQueryParamNames(endpoint).length > 0,
      riskTags: new Set<string>(endpointRiskTags(endpoint)),
    });
  }

  const probeStatusRank: Record<ProbeStatus, number> = {
    reachable: 5,
    blocked: 4,
    redirect: 3,
    error: 2,
    unknown: 1,
  };

  for (const probeResult of endpointProbeResults) {
    const metadata = endpointMetadata.get(probeResult.url);
    const current =
      endpointRollup.get(probeResult.url) ??
      {
        status: 'unknown' as ProbeStatus,
        lastStatusCode: 0,
        methodsObserved: new Set<string>(),
        kinds: new Set<EndpointKind>(metadata ? Array.from(metadata.kinds) : ['seed']),
        discoveredFrom: new Set<string>(metadata ? Array.from(metadata.sources) : [targetUrl]),
        hasQueryParams: metadata
          ? metadata.queryParams.size > 0
          : extractQueryParamNames(probeResult.url).length > 0,
        riskTags: new Set<string>(endpointRiskTags(probeResult.url)),
      };
    current.methodsObserved.add(probeResult.method);
    for (const allowMethod of probeResult.allow ?? []) {
      current.methodsObserved.add(allowMethod);
    }
    const nextStatus = classifyProbeStatus(probeResult.status);
    if (probeStatusRank[nextStatus] >= probeStatusRank[current.status]) {
      current.status = nextStatus;
      current.lastStatusCode = probeResult.status;
    }
    if (probeResult.status > 0 && current.lastStatusCode === 0) {
      current.lastStatusCode = probeResult.status;
    }
    endpointRollup.set(probeResult.url, current);
  }

  const securityFindings: SecurityFinding[] = [];
  const findingDedup = new Set<string>();
  const graphqlSummary: GraphqlIntrospectionSummary = {
    generatedAt: new Date().toISOString(),
    candidatesChecked: 0,
    introspectionEnabled: 0,
    results: [],
  };
  const authDifferentialSummary: AuthDifferentialSummary = {
    generatedAt: new Date().toISOString(),
    enabled: authProfile.summary.enabled,
    candidatesChecked: 0,
    protectedCount: 0,
    publicCount: 0,
    suspectedBypassCount: 0,
    inconclusiveCount: 0,
    results: [],
  };

  function addFinding(finding: Omit<SecurityFinding, 'id'>): void {
    const dedupKey = [
      finding.category,
      finding.severity,
      finding.url,
      finding.method,
      finding.title,
      finding.evidence.join('|'),
    ].join('::');
    if (findingDedup.has(dedupKey)) {
      return;
    }
    findingDedup.add(dedupKey);
    securityFindings.push({
      id: hashText(dedupKey).slice(0, 16),
      ...finding,
    });
  }

  if (openApiSummary.docsParsed > 0) {
    const firstOpenApiDoc = openApiSummary.docs[0];
    addFinding({
      category: 'exposure',
      severity: 'info',
      confidence: 'high',
      title: 'OpenAPI/Swagger documentation parsed',
      description:
        'Public API schema was discovered and parsed. Endpoint extraction has been expanded using this contract.',
      url: firstOpenApiDoc?.sourceUrl ?? targetUrl,
      method: 'GET',
      evidence: [
        `OpenAPI documents parsed: ${openApiSummary.docsParsed}`,
        `Additional endpoints added: ${openApiSummary.endpointsAdded}`,
      ],
    });
  }

  // Header posture checks on target URL.
  try {
    const targetResponse = await fetchTargetWithTimeoutInit(targetUrl, 15000, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'User-Agent': 'Shannon-Headers-Check/1.0',
      },
    });
    const missingHeaders: string[] = [];
    const headerExpectations: Array<{ name: string; condition: boolean }> = [
      { name: 'content-security-policy', condition: Boolean(targetResponse.headers.get('content-security-policy')) },
      { name: 'x-frame-options', condition: Boolean(targetResponse.headers.get('x-frame-options')) },
      { name: 'x-content-type-options', condition: Boolean(targetResponse.headers.get('x-content-type-options')) },
      { name: 'referrer-policy', condition: Boolean(targetResponse.headers.get('referrer-policy')) },
      { name: 'permissions-policy', condition: Boolean(targetResponse.headers.get('permissions-policy')) },
    ];
    if (target.protocol === 'https:') {
      headerExpectations.push({
        name: 'strict-transport-security',
        condition: Boolean(targetResponse.headers.get('strict-transport-security')),
      });
    }
    for (const expectation of headerExpectations) {
      if (!expectation.condition) {
        missingHeaders.push(expectation.name);
      }
    }
    if (missingHeaders.length > 0) {
      addFinding({
        category: 'headers',
        severity: missingHeaders.length >= 3 ? 'medium' : 'low',
        confidence: 'high',
        title: 'Missing recommended HTTP security headers',
        description:
          'The target response omits standard browser hardening headers. This increases exploitability for client-side attacks.',
        url: targetUrl,
        method: 'GET',
        evidence: [
          `Status: ${targetResponse.status}`,
          `Missing headers: ${missingHeaders.join(', ')}`,
        ],
        reproduction: {
          method: 'GET',
          url: targetUrl,
          headers: {
            'User-Agent': 'Shannon-Headers-Check/1.0',
          },
        },
      });
    }
    const csp = (targetResponse.headers.get('content-security-policy') ?? '').toLowerCase();
    if (csp.includes("'unsafe-inline'") && !csp.includes('nonce-') && !csp.includes('strict-dynamic')) {
      addFinding({
        category: 'headers',
        severity: 'low',
        confidence: 'medium',
        title: 'Potentially weak CSP configuration',
        description: 'CSP allows unsafe inline content without nonce or strict-dynamic protections.',
        url: targetUrl,
        method: 'GET',
        evidence: [`CSP: ${targetResponse.headers.get('content-security-policy')}`],
      });
    }
  } catch (error) {
    logger.warn(
      `Header posture check failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  // CORS checks against first-party endpoints.
  const corsProbeOrigin = 'https://attacker.shannon.invalid';
  const corsCandidates = endpointProbeInputs
    .filter((endpoint) => isFirstPartyUrl(endpoint, targetHost, targetRootDomain))
    .slice(0, ACTIVE_CHECK_LIMITS.maxCorsChecks);
  for (const endpoint of corsCandidates) {
    if (isTimedOut()) break;
    try {
      const response = await fetchTargetWithTimeoutInit(endpoint, 12000, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          Origin: corsProbeOrigin,
          'User-Agent': 'Shannon-CORS-Check/1.0',
        },
      });
      const acao = response.headers.get('access-control-allow-origin');
      if (!acao) continue;
      const acac = (response.headers.get('access-control-allow-credentials') ?? '').toLowerCase();
      if (
        (acao === '*' && acac === 'true') ||
        (acao === corsProbeOrigin && acac === 'true')
      ) {
        addFinding({
          category: 'cors',
          severity: 'high',
          confidence: 'high',
          title: 'CORS allows attacker origin with credentials',
          description:
            'Cross-origin requests appear to be accepted with credentials, enabling potential cross-site data exfiltration.',
          url: endpoint,
          method: 'GET',
          evidence: [
            `Status: ${response.status}`,
            `Access-Control-Allow-Origin: ${acao}`,
            `Access-Control-Allow-Credentials: ${acac || '(not set)'}`,
          ],
          reproduction: {
            method: 'GET',
            url: endpoint,
            headers: {
              Origin: corsProbeOrigin,
              'User-Agent': 'Shannon-CORS-Check/1.0',
            },
          },
        });
      } else if (acao === '*') {
        addFinding({
          category: 'cors',
          severity: 'low',
          confidence: 'medium',
          title: 'Wildcard CORS policy observed',
          description: 'Endpoint responds with Access-Control-Allow-Origin: *.',
          url: endpoint,
          method: 'GET',
          evidence: [
            `Status: ${response.status}`,
            `Access-Control-Allow-Origin: ${acao}`,
            `Access-Control-Allow-Credentials: ${acac || '(not set)'}`,
          ],
        });
      }
    } catch {
      // Best-effort check; ignore endpoint-level failures.
    }
  }

  // Sensitive path and exposure checks on target origin.
  const targetOrigin = `${target.protocol}//${target.host}`;
  const sensitivePaths = [
    '/.env',
    '/.git/config',
    '/.git/HEAD',
    '/backup.zip',
    '/swagger.json',
    '/openapi.json',
    '/v2/api-docs',
    '/graphql',
    '/actuator',
    '/actuator/env',
  ].slice(0, ACTIVE_CHECK_LIMITS.maxSensitivePathChecks);

  for (const relativePath of sensitivePaths) {
    if (isTimedOut()) break;
    const sensitiveUrl = new URL(relativePath, targetOrigin).toString();
    try {
      const response = await fetchTargetWithTimeoutInit(sensitiveUrl, 12000, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': 'Shannon-Exposure-Check/1.0',
        },
      });
      if (response.status < 200 || response.status >= 300) {
        continue;
      }
      const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
      const snippet = await readResponseSnippet(response, ACTIVE_CHECK_LIMITS.responseSnippetBytes);
      const snippetLower = snippet.toLowerCase();

      if (
        relativePath === '/.env' &&
        /(?:api|secret|token|password|key)\s*=/.test(snippetLower)
      ) {
        addFinding({
          category: 'exposure',
          severity: 'high',
          confidence: 'high',
          title: 'Potential sensitive .env file exposure',
          description: 'Environment configuration appears publicly accessible and contains secret-like keys.',
          url: sensitiveUrl,
          method: 'GET',
          evidence: [
            `Status: ${response.status}`,
            `Content-Type: ${contentType || '(unknown)'}`,
          ],
        });
      } else if (relativePath === '/.git/config' && /\[core\]/.test(snippetLower)) {
        addFinding({
          category: 'exposure',
          severity: 'high',
          confidence: 'high',
          title: 'Git repository config exposed over HTTP',
          description: 'Git metadata exposure can lead to source disclosure and secret recovery.',
          url: sensitiveUrl,
          method: 'GET',
          evidence: [
            `Status: ${response.status}`,
            'Response contains [core] git config signature',
          ],
        });
      } else if (relativePath === '/.git/HEAD' && /ref:\s*refs\//.test(snippetLower)) {
        addFinding({
          category: 'exposure',
          severity: 'high',
          confidence: 'high',
          title: 'Git HEAD file exposed over HTTP',
          description: 'Exposed git metadata often indicates recoverable repository history.',
          url: sensitiveUrl,
          method: 'GET',
          evidence: [
            `Status: ${response.status}`,
            'Response contains git HEAD reference',
          ],
        });
      } else if (
        (relativePath === '/swagger.json' ||
          relativePath === '/openapi.json' ||
          relativePath === '/v2/api-docs') &&
        (snippetLower.includes('"openapi"') || snippetLower.includes('"swagger"'))
      ) {
        addFinding({
          category: 'exposure',
          severity: 'medium',
          confidence: 'high',
          title: 'Public API documentation endpoint discovered',
          description:
            'OpenAPI/Swagger documentation appears reachable and can accelerate attack path discovery.',
          url: sensitiveUrl,
          method: 'GET',
          evidence: [`Status: ${response.status}`],
        });
      } else if (
        relativePath === '/actuator/env' &&
        (snippetLower.includes('propertysources') || snippetLower.includes('activeprofiles'))
      ) {
        addFinding({
          category: 'exposure',
          severity: 'high',
          confidence: 'high',
          title: 'Spring actuator environment data exposed',
          description: 'Actuator environment output may leak secrets and internal system configuration.',
          url: sensitiveUrl,
          method: 'GET',
          evidence: [`Status: ${response.status}`],
        });
      } else if (
        relativePath === '/backup.zip' &&
        (contentType.includes('zip') || response.headers.get('content-disposition')?.includes('.zip'))
      ) {
        addFinding({
          category: 'exposure',
          severity: 'medium',
          confidence: 'medium',
          title: 'Public backup archive endpoint exposed',
          description: 'A downloadable backup archive endpoint appears reachable.',
          url: sensitiveUrl,
          method: 'GET',
          evidence: [
            `Status: ${response.status}`,
            `Content-Type: ${contentType || '(unknown)'}`,
          ],
        });
      } else if (relativePath === '/graphql') {
        addFinding({
          category: 'exposure',
          severity: 'info',
          confidence: 'medium',
          title: 'GraphQL endpoint reachable',
          description:
            'GraphQL endpoint discovered. Validate authorization controls and introspection policy manually.',
          url: sensitiveUrl,
          method: 'GET',
          evidence: [`Status: ${response.status}`],
        });
      }
    } catch {
      // Best-effort check; ignore endpoint-level failures.
    }
  }

  // Open redirect validation on redirect-like parameters.
  const redirectParamNames = new Set([
    'next',
    'url',
    'redirect',
    'redirect_uri',
    'return',
    'returnurl',
    'continue',
    'dest',
    'destination',
    'callback',
  ]);
  const openRedirectCandidates = Array.from(endpointMetadata.entries())
    .filter(([endpoint, metadata]) => {
      if (!isFirstPartyUrl(endpoint, targetHost, targetRootDomain)) return false;
      const queryParams = Array.from(metadata.queryParams).map((param) => param.toLowerCase());
      if (queryParams.some((param) => redirectParamNames.has(param))) return true;
      const tags = endpointRiskTags(endpoint);
      return tags.includes('redirect') || tags.includes('callback');
    })
    .map(([endpoint]) => endpoint)
    .slice(0, ACTIVE_CHECK_LIMITS.maxRedirectChecks);
  if (openRedirectCandidates.length === 0) {
    openRedirectCandidates.push(targetUrl);
  }

  const redirectProbeValue = 'https://attacker.shannon.invalid/redirect-check';
  for (const endpoint of openRedirectCandidates) {
    if (isTimedOut()) break;
    let probeUrl: string;
    try {
      const parsed = new URL(endpoint);
      const existingParams = Array.from(parsed.searchParams.keys());
      let probeParam = existingParams.find((param) =>
        redirectParamNames.has(param.toLowerCase())
      );
      if (!probeParam) {
        probeParam = 'next';
      }
      parsed.searchParams.set(probeParam, redirectProbeValue);
      probeUrl = parsed.toString();
    } catch {
      continue;
    }

    try {
      const response = await fetchTargetWithTimeoutInit(probeUrl, 12000, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': 'Shannon-Redirect-Check/1.0',
        },
      });
      const location = response.headers.get('location') ?? '';
      if (
        response.status >= 300 &&
        response.status < 400 &&
        location.includes('attacker.shannon.invalid')
      ) {
        addFinding({
          category: 'redirect',
          severity: 'high',
          confidence: 'high',
          title: 'Potential open redirect confirmed',
          description:
            'Endpoint redirected to attacker-controlled URL when redirect parameter was supplied.',
          url: endpoint,
          method: 'GET',
          evidence: [
            `Probe URL: ${probeUrl}`,
            `Status: ${response.status}`,
            `Location: ${location}`,
          ],
          reproduction: {
            method: 'GET',
            url: probeUrl,
            headers: {
              'User-Agent': 'Shannon-Redirect-Check/1.0',
            },
          },
        });
      }
    } catch {
      // Best-effort check; ignore endpoint-level failures.
    }
  }

  // Reflection checks for potential XSS injection points.
  const reflectionCandidates = Array.from(endpointMetadata.entries())
    .filter(([endpoint, metadata]) => {
      if (!isFirstPartyUrl(endpoint, targetHost, targetRootDomain)) return false;
      return metadata.queryParams.size > 0;
    })
    .map(([endpoint]) => endpoint)
    .slice(0, ACTIVE_CHECK_LIMITS.maxReflectionChecks);

  for (const endpoint of reflectionCandidates) {
    if (isTimedOut()) break;
    let probeUrl: string;
    const reflectionToken = `shannon_reflect_${hashText(endpoint).slice(0, 12)}`;
    let probeParamName = 'q';
    try {
      const parsed = new URL(endpoint);
      const queryKeys = Array.from(parsed.searchParams.keys());
      if (queryKeys.length > 0) {
        probeParamName = queryKeys[0] ?? 'q';
      }
      parsed.searchParams.set(probeParamName, reflectionToken);
      probeUrl = parsed.toString();
    } catch {
      continue;
    }

    try {
      const response = await fetchTargetWithTimeoutInit(probeUrl, 12000, {
        method: 'GET',
        redirect: 'follow',
        headers: {
          'User-Agent': 'Shannon-Reflection-Check/1.0',
        },
      });
      const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
      if (
        !contentType.includes('html') &&
        !contentType.includes('json') &&
        !contentType.includes('javascript') &&
        !contentType.includes('text/')
      ) {
        continue;
      }
      const snippet = await readResponseSnippet(response, ACTIVE_CHECK_LIMITS.responseSnippetBytes);
      if (!snippet.includes(reflectionToken)) {
        continue;
      }
      addFinding({
        category: 'reflection',
        severity: contentType.includes('html') ? 'medium' : 'low',
        confidence: 'medium',
        title: 'Input reflection detected',
        description:
          'Injected token is reflected in server response. Manual context-aware validation is required to confirm XSS exploitability.',
        url: endpoint,
        method: 'GET',
        evidence: [
          `Probe URL: ${probeUrl}`,
          `Status: ${response.status}`,
          `Content-Type: ${contentType || '(unknown)'}`,
          `Reflected token: ${reflectionToken}`,
        ],
        reproduction: {
          method: 'GET',
          url: probeUrl,
          headers: {
            'User-Agent': 'Shannon-Reflection-Check/1.0',
          },
          note: `Check whether token "${reflectionToken}" is reflected in executable HTML/JS context.`,
        },
      });
    } catch {
      // Best-effort check; ignore endpoint-level failures.
    }
  }

  // OPTIONS/Allow method checks on first-party endpoints.
  const methodCandidates = Array.from(endpointRollup.entries())
    .map(([endpoint]) => endpoint)
    .filter((endpoint) => isFirstPartyUrl(endpoint, targetHost, targetRootDomain))
    .slice(0, ACTIVE_CHECK_LIMITS.maxMethodChecks);

  for (const endpoint of methodCandidates) {
    if (isTimedOut()) break;
    try {
      const response = await fetchTargetWithTimeoutInit(endpoint, 12000, {
        method: 'OPTIONS',
        redirect: 'manual',
        headers: {
          'User-Agent': 'Shannon-Method-Check/1.0',
        },
      });
      const allowMethods = parseAllowHeader(response.headers.get('allow'));
      if (allowMethods.length === 0) continue;
      const record = endpointRollup.get(endpoint);
      if (record) {
        for (const method of allowMethods) {
          record.methodsObserved.add(method);
        }
      }
      const dangerous = allowMethods.filter((method) => DANGEROUS_METHODS.has(method));
      if (dangerous.length === 0) continue;
      const severity: FindingSeverity =
        dangerous.includes('TRACE') || dangerous.includes('CONNECT') ? 'medium' : 'low';
      addFinding({
        category: 'http-methods',
        severity,
        confidence: 'medium',
        title: 'Potentially dangerous HTTP methods exposed',
        description:
          'Endpoint advertises potentially risky methods. Validate authorization and method-specific controls.',
        url: endpoint,
        method: 'OPTIONS',
        evidence: [
          `Status: ${response.status}`,
          `Allow: ${allowMethods.join(', ')}`,
        ],
      });
    } catch {
      // Best-effort check; ignore endpoint-level failures.
    }
  }

  // Auth differential checks: compare authenticated context vs unauthenticated access.
  if (authProfile.summary.enabled) {
    const authDiffCandidates = Array.from(endpointRollup.entries())
      .map(([endpoint]) => endpoint)
      .filter((endpoint) => isFirstPartyUrl(endpoint, targetHost, targetRootDomain))
      .slice(0, ACTIVE_CHECK_LIMITS.maxAuthDifferentialChecks);

    for (const endpoint of authDiffCandidates) {
      if (isTimedOut()) break;
      const rollupEntry = endpointRollup.get(endpoint);
      if (!rollupEntry) continue;
      authDifferentialSummary.candidatesChecked += 1;

      const authStatus = rollupEntry.lastStatusCode;
      let unauthStatus = 0;
      try {
        const unauthResponse = await fetchWithTimeoutInit(endpoint, 12000, {
          method: 'HEAD',
          redirect: 'manual',
          headers: {
            'User-Agent': 'Shannon-Auth-Diff-Check/1.0',
          },
        });
        unauthStatus = unauthResponse.status;
      } catch {
        unauthStatus = 0;
      }

      let classification: 'protected' | 'public' | 'suspected-bypass' | 'inconclusive' = 'inconclusive';
      const authReachable = authStatus >= 200 && authStatus < 300;
      const authBlocked = authStatus === 401 || authStatus === 403;
      const unauthReachable = unauthStatus >= 200 && unauthStatus < 300;
      const unauthBlocked = unauthStatus === 401 || unauthStatus === 403;

      if (authReachable && unauthBlocked) {
        classification = 'protected';
        authDifferentialSummary.protectedCount += 1;
      } else if (authReachable && unauthReachable) {
        classification = 'public';
        authDifferentialSummary.publicCount += 1;
      } else if (authBlocked && unauthReachable) {
        classification = 'suspected-bypass';
        authDifferentialSummary.suspectedBypassCount += 1;
      } else {
        classification = 'inconclusive';
        authDifferentialSummary.inconclusiveCount += 1;
      }

      authDifferentialSummary.results.push({
        endpoint,
        authStatus,
        unauthStatus,
        classification,
      });

      if (classification === 'suspected-bypass') {
        addFinding({
          category: 'authz',
          severity: 'high',
          confidence: 'medium',
          title: 'Potential authorization bypass pattern detected',
          description:
            'Endpoint appears reachable without auth while authenticated context returned an access-denied response. Validate manually for authz inconsistencies.',
          url: endpoint,
          method: 'HEAD',
          evidence: [
            `Auth-context status: ${authStatus}`,
            `Unauthenticated status: ${unauthStatus}`,
          ],
        });
      } else if (
        classification === 'public' &&
        Array.from(rollupEntry.riskTags).some((tag) =>
          ['admin', 'auth', 'internal', 'config'].includes(tag)
        )
      ) {
        addFinding({
          category: 'authz',
          severity: 'medium',
          confidence: 'low',
          title: 'Potentially sensitive endpoint is publicly reachable',
          description:
            'Endpoint with sensitive path indicators appears publicly reachable in both authenticated and unauthenticated checks.',
          url: endpoint,
          method: 'HEAD',
          evidence: [
            `Auth-context status: ${authStatus}`,
            `Unauthenticated status: ${unauthStatus}`,
            `Risk tags: ${Array.from(rollupEntry.riskTags).join(', ')}`,
          ],
        });
      }
    }
  }

  // GraphQL introspection checks (with optional auth differential).
  const graphqlCandidates = Array.from(endpointRollup.entries())
    .map(([endpoint]) => endpoint)
    .filter((endpoint) => {
      try {
        const parsed = new URL(endpoint);
        const lowerPath = parsed.pathname.toLowerCase();
        return lowerPath.includes('graphql') || endpointRiskTags(endpoint).includes('graphql');
      } catch {
        return false;
      }
    })
    .slice(0, ACTIVE_CHECK_LIMITS.maxGraphqlChecks);

  if (graphqlCandidates.length === 0) {
    try {
      const defaultGraphql = new URL('/graphql', `${target.protocol}//${target.host}`).toString();
      graphqlCandidates.push(defaultGraphql);
    } catch {
      // Ignore malformed default candidate.
    }
  }

  const introspectionQuery =
    'query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }';
  const introspectionBody = JSON.stringify({ query: introspectionQuery });

  for (const endpoint of graphqlCandidates) {
    if (isTimedOut()) break;
    graphqlSummary.candidatesChecked += 1;
    try {
      const response = await fetchTargetWithTimeoutInit(endpoint, 15000, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          'User-Agent': 'Shannon-GraphQL-Introspection/1.0',
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: introspectionBody,
      });
      const responseText = await readResponseSnippet(response, ACTIVE_CHECK_LIMITS.responseSnippetBytes);
      let schemaTypeCount: number | undefined;
      let success = false;
      try {
        const parsed = JSON.parse(responseText) as {
          data?: {
            __schema?: {
              types?: Array<{ name?: string }>;
            };
          };
        };
        const schemaTypes = parsed?.data?.__schema?.types;
        if (Array.isArray(schemaTypes) && schemaTypes.length > 0) {
          success = true;
          schemaTypeCount = schemaTypes.length;
        }
      } catch {
        success = false;
      }

      let unauthSuccess = false;
      if (success && authProfile.enabled && isFirstPartyUrl(endpoint, targetHost, targetRootDomain)) {
        try {
          const unauthResponse = await fetchWithTimeoutInit(endpoint, 12000, {
            method: 'POST',
            redirect: 'manual',
            headers: {
              'User-Agent': 'Shannon-GraphQL-Introspection/1.0',
              'Content-Type': 'application/json',
              Accept: 'application/json',
            },
            body: introspectionBody,
          });
          const unauthText = await readResponseSnippet(
            unauthResponse,
            ACTIVE_CHECK_LIMITS.responseSnippetBytes
          );
          const unauthParsed = JSON.parse(unauthText) as {
            data?: {
              __schema?: {
                types?: Array<{ name?: string }>;
              };
            };
          };
          unauthSuccess = Array.isArray(unauthParsed?.data?.__schema?.types) &&
            unauthParsed.data.__schema.types.length > 0;
        } catch {
          unauthSuccess = false;
        }
      }

      graphqlSummary.results.push({
        endpoint,
        status: response.status,
        success,
        ...(typeof schemaTypeCount === 'number' ? { schemaTypeCount } : {}),
      });

      if (!success) {
        continue;
      }

      graphqlSummary.introspectionEnabled += 1;
      addFinding({
        category: 'exposure',
        severity: unauthSuccess ? 'medium' : 'info',
        confidence: 'high',
        title: unauthSuccess
          ? 'GraphQL introspection exposed without authentication'
          : 'GraphQL introspection enabled',
        description: unauthSuccess
          ? 'Introspection appears enabled for unauthenticated requests, exposing complete schema metadata.'
          : 'GraphQL introspection is enabled. Validate if this aligns with production hardening requirements.',
        url: endpoint,
        method: 'POST',
        evidence: [
          `Status: ${response.status}`,
          `Schema types: ${typeof schemaTypeCount === 'number' ? schemaTypeCount : 'unknown'}`,
          `Unauthenticated introspection: ${unauthSuccess ? 'enabled' : 'not confirmed'}`,
        ],
        reproduction: {
          method: 'POST',
          url: endpoint,
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          note: 'Send IntrospectionQuery and verify whether __schema is returned.',
        },
      });
    } catch (error) {
      graphqlSummary.results.push({
        endpoint,
        status: 0,
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const findingsBySeverity: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const finding of securityFindings) {
    findingsBySeverity[finding.severity] += 1;
  }

  const reachabilityEntries: ReachabilityEntry[] = Array.from(endpointRollup.entries())
    .map(([urlValue, details]) => ({
      url: urlValue,
      status: details.status,
      lastStatusCode: details.lastStatusCode,
      methodsObserved: Array.from(details.methodsObserved),
      kinds: Array.from(details.kinds),
      discoveredFrom: Array.from(details.discoveredFrom).slice(0, 10),
      hasQueryParams: details.hasQueryParams,
      riskTags: Array.from(details.riskTags),
    }))
    .slice(0, ACTIVE_CHECK_LIMITS.maxReachabilityEntries);

  const statusTotals = {
    reachable: reachabilityEntries.filter((entry) => entry.status === 'reachable').length,
    blocked: reachabilityEntries.filter((entry) => entry.status === 'blocked').length,
    redirects: reachabilityEntries.filter((entry) => entry.status === 'redirect').length,
    errors: reachabilityEntries.filter((entry) => entry.status === 'error').length,
    unknown: reachabilityEntries.filter((entry) => entry.status === 'unknown').length,
  };

  const probeCoveragePercent = toPercent(endpointProbeInputs.length, discoveredEndpoints.size);
  const reachablePercent = toPercent(statusTotals.reachable, endpointProbeInputs.length);
  const totalRiskTagged = reachabilityEntries.filter((entry) => entry.riskTags.length > 0).length;
  const attackSurfaceScore = computeAttackSurfaceScore(
    findingsBySeverity,
    reachablePercent,
    probeCoveragePercent,
    totalRiskTagged
  );
  const topReachable = reachabilityEntries
    .filter((entry) => entry.status === 'reachable')
    .sort((a, b) => {
      if (b.riskTags.length !== a.riskTags.length) {
        return b.riskTags.length - a.riskTags.length;
      }
      return a.url.localeCompare(b.url);
    })
    .slice(0, 50)
    .map((entry) => entry.url);

  const reachabilityMap: ReachabilityMap = {
    generatedAt: new Date().toISOString(),
    target: {
      webUrl: targetUrl,
      hostname: targetHost,
      rootDomain: targetRootDomain,
    },
    totals: {
      endpointCandidates: discoveredEndpoints.size,
      endpointProbed: endpointProbeInputs.length,
      reachable: statusTotals.reachable,
      blocked: statusTotals.blocked,
      redirects: statusTotals.redirects,
      errors: statusTotals.errors,
      unknown: statusTotals.unknown,
    },
    coverage: {
      probeCoveragePercent,
      reachablePercent,
    },
    findingsBySeverity,
    attackSurfaceScore,
    topReachable,
    entries: reachabilityEntries,
  };

  const securityFindingsJsonPath = path.join(paths.recon, 'security-findings.json');
  const securityFindingsMdPath = path.join(paths.recon, 'security-findings.md');
  const reachabilityMapPath = path.join(paths.recon, 'reachability-map.json');
  const openApiSummaryPath = path.join(paths.recon, 'openapi-extracted.json');
  const graphqlSummaryPath = path.join(paths.recon, 'graphql-introspection.json');
  const authDifferentialPath = path.join(paths.recon, 'auth-differential.json');
  await writeJson(securityFindingsJsonPath, {
    generatedAt: reachabilityMap.generatedAt,
    target: reachabilityMap.target,
    findingsBySeverity,
    findings: securityFindings,
  });
  await writeText(securityFindingsMdPath, findingsToMarkdown(securityFindings, reachabilityMap));
  await writeJson(reachabilityMapPath, reachabilityMap);
  await writeJson(openApiSummaryPath, openApiSummary);
  await writeJson(graphqlSummaryPath, graphqlSummary);
  await writeJson(authDifferentialPath, authDifferentialSummary);

  // Manual source input.
  if (input.manualSource && input.manualSource.trim().length > 0) {
    const manualSource = input.manualSource.trim();
    const manualDest = path.join(paths.repos, 'manual');
    if (manualSource.startsWith('https://') && isAllowedGitUrl(manualSource)) {
      const gitUrl = normalizeRepoUrl(manualSource);
      const cloned = await cloneRepository(gitUrl, manualDest);
      const origin: SourceOrigin = {
        kind: 'manual-git',
        location: gitUrl,
        workspacePath: manualDest,
        cloned,
        ...(cloned ? {} : { note: 'git clone failed' }),
      };
      sourceOriginDetails.push(origin);
      sourceOrigins.push(`${origin.kind}:${origin.location}`);
    } else if (isValidLocalRepoName(manualSource)) {
      const copied = await copyLocalRepository(manualSource, manualDest);
      const origin: SourceOrigin = {
        kind: 'manual-local',
        location: `/repos/${manualSource}`,
        workspacePath: manualDest,
        cloned: copied,
        ...(copied ? {} : { note: 'local source repository not found' }),
      };
      sourceOriginDetails.push(origin);
      sourceOrigins.push(`${origin.kind}:${origin.location}`);
    } else {
      sourceOriginDetails.push({
        kind: 'manual-local',
        location: manualSource,
        workspacePath: '',
        cloned: false,
        note: 'manualSource rejected by validation',
      });
      sourceOrigins.push(`manual-invalid:${manualSource}`);
    }
  }

  // Auto-clone discovered public repos.
  if (options.autoClonePublicRepos) {
    const discoveredRepoList = Array.from(discoveredRepos)
      .filter((repoUrl) => isAllowedGitUrl(repoUrl))
      .slice(0, 100);
    let idx = 1;
    for (const repoUrl of discoveredRepoList) {
      if (isTimedOut()) break;
      const normalized = normalizeRepoUrl(repoUrl);
      const repoName = sanitizeSegment(`${idx}_${hashText(normalized).slice(0, 10)}`);
      const destination = path.join(paths.repos, 'discovered', repoName);
      const cloned = await cloneRepository(normalized, destination);
      const origin: SourceOrigin = {
        kind: 'discovered-public-git',
        location: normalized,
        workspacePath: destination,
        cloned,
        ...(cloned ? {} : { note: 'git clone failed' }),
      };
      sourceOriginDetails.push(origin);
      sourceOrigins.push(`${origin.kind}:${origin.location}`);
      idx += 1;
    }
  }

  const completedAt = new Date().toISOString();
  const harvestSummary =
    `URL-first workspace prepared: pages=${visitedPages.size}, assets=${downloadedAssets}, ` +
    `js=${downloadedJs}, sourcemaps=${downloadedSourcemaps}, reconstructed_files=${reconstructedFiles}, ` +
    `domains=${knownDomains.size}, endpoint_probes=${endpointProbeResults.length}, ` +
    `openapi_docs=${openApiSummary.docsParsed}, graphql_introspection=${graphqlSummary.introspectionEnabled}, ` +
    `auth_diff_bypass=${authDifferentialSummary.suspectedBypassCount}, ` +
    `reachable_endpoints=${statusTotals.reachable}, findings=${securityFindings.length}, ` +
    `attack_surface_score=${reachabilityMap.attackSurfaceScore}, auth_profile=${authProfile.summary.enabled}, ` +
    `source_origins=${sourceOriginDetails.filter((o) => o.cloned).length}`;

  const manifest = {
    analysisMode: 'url-first' as AnalysisMode,
    discoveryProfile: input.discoveryProfile || 'aggressive-broad',
    target: {
      webUrl: targetUrl,
      hostname: targetHost,
      rootDomain: targetRootDomain,
    },
    timeline: {
      startedAt,
      completedAt,
      timedOut: isTimedOut(),
      timeoutMinutes: options.harvestTimeoutMinutes,
    },
    options,
    authProfile: authProfile.summary,
    paths,
    stats: {
      pagesCrawled: visitedPages.size,
      uniqueUrls: discoveredUrls.size,
      assetsDownloaded: downloadedAssets,
      jsDownloaded: downloadedJs,
      sourcemapsDownloaded: downloadedSourcemaps,
      reconstructedFiles,
      discoveredDomains: knownDomains.size,
      endpointCandidates: discoveredEndpoints.size,
      endpointProbes: endpointProbeResults.length,
      endpointReachable: statusTotals.reachable,
      endpointBlocked: statusTotals.blocked,
      endpointRedirects: statusTotals.redirects,
      endpointErrors: statusTotals.errors,
      openApiDocsParsed: openApiSummary.docsParsed,
      openApiEndpointsAdded: openApiSummary.endpointsAdded,
      graphqlCandidatesChecked: graphqlSummary.candidatesChecked,
      graphqlIntrospectionEnabled: graphqlSummary.introspectionEnabled,
      authDifferentialCandidatesChecked: authDifferentialSummary.candidatesChecked,
      authDifferentialProtected: authDifferentialSummary.protectedCount,
      authDifferentialPublic: authDifferentialSummary.publicCount,
      authDifferentialSuspectedBypass: authDifferentialSummary.suspectedBypassCount,
      discoveredRepoCandidates: discoveredRepos.size,
      sourceOriginsCloned: sourceOriginDetails.filter((o) => o.cloned).length,
      securityFindingsTotal: securityFindings.length,
      securityFindingsBySeverity: findingsBySeverity,
      attackSurfaceScore: reachabilityMap.attackSurfaceScore,
    },
    sourceOrigins: sourceOriginDetails,
    artifacts: {
      nmap: path.join(paths.recon, 'nmap.json'),
      subfinder: path.join(paths.recon, 'subfinder.json'),
      whatweb: path.join(paths.recon, 'whatweb.json'),
      endpointProbes: path.join(paths.recon, 'endpoint-probes.json'),
      reachabilityMap: reachabilityMapPath,
      securityFindingsJson: securityFindingsJsonPath,
      securityFindingsMarkdown: securityFindingsMdPath,
      openApiExtraction: openApiSummaryPath,
      graphqlIntrospection: graphqlSummaryPath,
      authDifferential: authDifferentialPath,
    },
    summary: harvestSummary,
  };

  const manifestPath = path.join(paths.root, 'manifest.json');
  await writeJson(manifestPath, manifest);
  await writeText(path.join(paths.recon, 'harvest-summary.txt'), harvestSummary);

  logger.info('URL-first workspace prepared', {
    analysisPath: paths.root,
    pagesCrawled: visitedPages.size,
    assetsDownloaded: downloadedAssets + downloadedJs,
    sourceOrigins: sourceOriginDetails.length,
    reachableEndpoints: statusTotals.reachable,
    securityFindings: securityFindings.length,
    attackSurfaceScore: reachabilityMap.attackSurfaceScore,
    openApiDocsParsed: openApiSummary.docsParsed,
    graphqlIntrospectionEnabled: graphqlSummary.introspectionEnabled,
    authProfileEnabled: authProfile.summary.enabled,
    authDifferentialBypass: authDifferentialSummary.suspectedBypassCount,
  });

  return {
    analysisPath: paths.root,
    sourceOrigins,
    sourceOriginDetails,
    manifestPath,
    sourceInventoryPath: manifestPath,
    harvestSummary,
  };
}
