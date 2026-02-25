// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Configuration type definitions
 */

export type RuleType =
  | 'path'
  | 'subdomain'
  | 'domain'
  | 'method'
  | 'header'
  | 'parameter';

export interface Rule {
  description: string;
  type: RuleType;
  url_path: string;
}

export interface Rules {
  avoid?: Rule[];
  focus?: Rule[];
}

export type LoginType = 'form' | 'sso' | 'api' | 'basic';

export interface SuccessCondition {
  type: 'url' | 'cookie' | 'element' | 'redirect';
  value: string;
}

export interface Credentials {
  username: string;
  password: string;
  totp_secret?: string;
}

export interface Authentication {
  login_type: LoginType;
  login_url: string;
  credentials: Credentials;
  login_flow: string[];
  success_condition: SuccessCondition;
}

export interface Config {
  rules?: Rules;
  authentication?: Authentication;
  pipeline?: PipelineConfig;
  url_harvest?: UrlHarvestConfig;
}

export type RetryPreset = 'default' | 'subscription';

export interface PipelineConfig {
  retry_preset?: RetryPreset;
  max_concurrent_pipelines?: number;
}

export type UrlHarvestScopePolicy = 'same-origin' | 'first-party' | 'broad-discovery';

export interface UrlHarvestBasicAuth {
  username: string;
  password: string;
}

export interface UrlHarvestAuthConfig {
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  bearer_token?: string;
  basic_auth?: UrlHarvestBasicAuth;
}

/**
 * URL-first workspace preparation controls.
 *
 * Note: values may arrive as strings from YAML parsing and are coerced by
 * the URL harvester service.
 */
export interface UrlHarvestConfig {
  max_pages?: number | string;
  max_depth?: number | string;
  max_assets?: number | string;
  max_discovered_domains?: number | string;
  max_endpoint_probes?: number | string;
  http_concurrency?: number | string;
  probe_concurrency?: number | string;
  harvest_timeout_minutes?: number | string;
  auto_clone_public_repos?: boolean | string;
  scope_policy?: UrlHarvestScopePolicy | string;
  auth?: UrlHarvestAuthConfig;
}

export interface DistributedConfig {
  avoid: Rule[];
  focus: Rule[];
  authentication: Authentication | null;
}
