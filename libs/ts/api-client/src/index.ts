/**
 * NexusEdge Official TypeScript SDK
 * Zero-dependency, strictly-typed client for Global Infrastructure, Multi-Objective AI Orchestration,
 * Custom Edge Domains, and Real-Time Telemetry.
 */

export type RoutingStrategy =
  | 'LATENCY_OPTIMAL'
  | 'COST_MINIMAL'
  | 'CARBON_NEUTRAL'
  | 'SOVEREIGN_PINNED';

export type Jurisdiction = 'BD' | 'EU' | 'US' | 'GLOBAL';

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface CompletionRequest {
  model: string;
  messages: ChatMessage[];
  routingStrategy?: RoutingStrategy;
  jurisdiction?: Jurisdiction;
  temperature?: number;
  maxTokens?: number;
}

export interface CompletionTelemetry {
  provider: string | null;
  cost: number | null;
  ttftMs: number | null;
  region: string | null;
}

export interface CompletionChoice {
  index: number;
  message: ChatMessage;
  finish_reason?: string;
}

export interface CompletionResponse {
  id?: string;
  object?: string;
  created?: number;
  model: string;
  choices: CompletionChoice[];
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  telemetry: CompletionTelemetry;
}

export interface DomainRecord {
  id: string;
  project_id: string;
  hostname: string;
  cname_target?: string;
  origin_address?: string;
  origin_port?: number;
  origin_protocol?: string;
  status: string;
  allowed_pops?: string[];
  created_at?: string;
  updated_at?: string;
}

export interface OnboardDomainParams {
  hostname: string;
  originAddress: string;
  originPort?: number;
  originProtocol?: 'http' | 'https';
  allowedPoPs?: string[];
}

export interface OnboardDomainResult {
  domain_id: string;
  hostname: string;
  cname_target: string;
  verification_token: string;
  status: string;
  allowed_pops: string[];
}

export interface VerifyDomainResult {
  status: string;
  domain_id: string;
  hostname: string;
  state: string;
  message?: string;
}

export interface TelemetrySummary {
  project_id: string;
  total_requests: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  cache_hit_ratio: number;
  threat_blocks: number;
  success_rate: number;
  status_distribution: {
    '2xx': number;
    '4xx': number;
    '5xx': number;
  };
  pop_distribution: Record<string, number>;
  rate_limit?: {
    limit: number;
    remaining: number;
  };
}

export interface LatencyMatrixRoute {
  from_pop: string;
  to_pop?: string;
  to_target?: string;
  latency_ms: number;
  status?: string;
}

export interface LatencyMatrixResult {
  routes: LatencyMatrixRoute[];
  timestamp?: string;
}

export interface PoPHealthRecord {
  id: string;
  name: string;
  region: string;
  status: string;
  latency_p50_ms: number;
  capacity_used_pct: number;
  anycast_announced: boolean;
}

export interface NexusEdgeClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export class NexusEdgeError extends Error {
  public readonly status: number;
  public readonly code: string | number;
  public readonly details: unknown;

  constructor(status: number, message: string, code?: string | number, details?: unknown) {
    super(message);
    this.name = 'NexusEdgeError';
    this.status = status;
    this.code = code || status;
    this.details = details;
    Object.setPrototypeOf(this, NexusEdgeError.prototype);
  }
}

export class NexusEdgeClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  public readonly inference: InferenceNamespace;
  public readonly domains: DomainsNamespace;
  public readonly telemetry: TelemetryNamespace;

  constructor(options: NexusEdgeClientOptions) {
    if (!options || !options.apiKey || typeof options.apiKey !== 'string') {
      throw new NexusEdgeError(400, 'NexusEdgeClient requires a valid API key (e.g., nke_live_...)', 'INVALID_API_KEY');
    }
    this.apiKey = options.apiKey.trim();
    this.baseUrl = (options.baseUrl || 'https://dashboard.aeitron.com').replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs && options.timeoutMs > 0 ? options.timeoutMs : 30000;
    this.fetchImpl = options.fetch || (typeof fetch !== 'undefined' ? fetch : globalThis.fetch);

    if (!this.fetchImpl) {
      throw new NexusEdgeError(500, 'Global fetch implementation not found. Provide options.fetch.', 'NO_FETCH');
    }

    this.inference = new InferenceNamespace(this);
    this.domains = new DomainsNamespace(this);
    this.telemetry = new TelemetryNamespace(this);
  }

  public async request<T>(
    endpoint: string,
    options: {
      method?: string;
      body?: unknown;
      headers?: Record<string, string>;
    } = {}
  ): Promise<{ data: T; headers: Headers }> {
    const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
      'X-API-Key': this.apiKey,
      ...options.headers
    };

    let body: string | undefined;
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(options.body);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(url, {
        method: options.method || 'GET',
        headers,
        body,
        signal: controller.signal
      });

      const responseText = await response.text();
      let responseJson: any = null;
      if (responseText) {
        try {
          responseJson = JSON.parse(responseText);
        } catch {
          responseJson = { raw: responseText };
        }
      }

      if (!response.ok) {
        const errorMsg =
          (responseJson && (responseJson.error || responseJson.message)) ||
          `HTTP ${response.status} ${response.statusText}`;
        const errorCode = (responseJson && (responseJson.code || responseJson.error_code)) || response.status;
        throw new NexusEdgeError(response.status, String(errorMsg), errorCode, responseJson);
      }

      return {
        data: responseJson as T,
        headers: response.headers
      };
    } catch (err: any) {
      if (err instanceof NexusEdgeError) {
        throw err;
      }
      if (err.name === 'AbortError') {
        throw new NexusEdgeError(504, `Request timed out after ${this.timeoutMs}ms`, 'TIMEOUT');
      }
      throw new NexusEdgeError(500, err.message || 'Network request failed', 'NETWORK_ERROR', err);
    } finally {
      clearTimeout(timer);
    }
  }
}

class InferenceNamespace {
  constructor(private readonly client: NexusEdgeClient) {}

  public async createCompletion(params: CompletionRequest): Promise<CompletionResponse> {
    if (!params || !params.messages || !Array.isArray(params.messages)) {
      throw new NexusEdgeError(400, 'CompletionRequest requires a messages array', 'INVALID_PARAMS');
    }

    const extraHeaders: Record<string, string> = {};
    if (params.routingStrategy) {
      extraHeaders['X-NexusEdge-Routing-Strategy'] = params.routingStrategy;
    }
    if (params.jurisdiction) {
      extraHeaders['X-NexusEdge-Jurisdiction'] = params.jurisdiction;
    }

    const payload = {
      model: params.model || 'meta-llama/Llama-3.3-70B-Instruct',
      messages: params.messages,
      temperature: params.temperature ?? 0.7,
      max_tokens: params.maxTokens ?? 1024
    };

    const res = await this.client.request<any>('/api/proxy/inference', {
      method: 'POST',
      headers: extraHeaders,
      body: payload
    });

    const headers = res.headers;
    const data = res.data;

    const costHeader = headers.get('x-nexusedge-cost');
    const ttftHeader = headers.get('x-nexusedge-ttft-ms');

    const telemetry: CompletionTelemetry = {
      provider: headers.get('x-nexusedge-provider') || null,
      cost: costHeader !== null ? parseFloat(costHeader) : null,
      ttftMs: ttftHeader !== null ? parseInt(ttftHeader, 10) : null,
      region: headers.get('x-nexusedge-region') || null
    };

    return {
      id: data.id,
      object: data.object || 'chat.completion',
      created: data.created || Math.floor(Date.now() / 1000),
      model: data.model || params.model,
      choices: data.choices || [],
      usage: data.usage,
      telemetry
    };
  }
}

class DomainsNamespace {
  constructor(private readonly client: NexusEdgeClient) {}

  public async list(): Promise<{ domains: DomainRecord[] }> {
    const res = await this.client.request<{ domains: DomainRecord[] }>('/api/proxy/domains', {
      method: 'GET'
    });
    return res.data;
  }

  public async onboard(params: OnboardDomainParams): Promise<OnboardDomainResult> {
    if (!params || !params.hostname || !params.originAddress) {
      throw new NexusEdgeError(400, 'OnboardDomainParams requires hostname and originAddress', 'INVALID_PARAMS');
    }

    const payload = {
      hostname: params.hostname.trim().toLowerCase(),
      origin_address: params.originAddress.trim(),
      origin_port: params.originPort || 443,
      origin_protocol: params.originProtocol || 'https',
      allowed_pops: params.allowedPoPs || ['dhaka', 'singapore', 'frankfurt', 'virginia']
    };

    const res = await this.client.request<OnboardDomainResult>('/api/proxy/domains', {
      method: 'POST',
      body: payload
    });
    return res.data;
  }

  public async get(domainId: string): Promise<DomainRecord> {
    if (!domainId) {
      throw new NexusEdgeError(400, 'domainId is required', 'INVALID_PARAMS');
    }
    const res = await this.client.request<DomainRecord>(`/api/proxy/domains/${encodeURIComponent(domainId)}`, {
      method: 'GET'
    });
    return res.data;
  }

  public async verify(domainId: string, options: { force?: boolean } = {}): Promise<VerifyDomainResult> {
    if (!domainId) {
      throw new NexusEdgeError(400, 'domainId is required', 'INVALID_PARAMS');
    }
    const query = options.force ? '?force=true' : '';
    const res = await this.client.request<VerifyDomainResult>(
      `/api/proxy/domains/${encodeURIComponent(domainId)}/verify${query}`,
      { method: 'POST' }
    );
    return res.data;
  }

  public async delete(domainId: string): Promise<{ status: string; domain_id: string }> {
    if (!domainId) {
      throw new NexusEdgeError(400, 'domainId is required', 'INVALID_PARAMS');
    }
    const res = await this.client.request<{ status: string; domain_id: string }>(
      `/api/proxy/domains/${encodeURIComponent(domainId)}`,
      { method: 'DELETE' }
    );
    return res.data;
  }
}

class TelemetryNamespace {
  constructor(private readonly client: NexusEdgeClient) {}

  public async getSummary(projectId?: string): Promise<TelemetrySummary> {
    const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    const res = await this.client.request<TelemetrySummary>(`/api/proxy/analytics/summary${query}`, {
      method: 'GET'
    });
    return res.data;
  }

  public async getLatencyMatrix(): Promise<LatencyMatrixResult> {
    const res = await this.client.request<LatencyMatrixResult>('/api/proxy/pops/matrix', {
      method: 'GET'
    });
    return res.data;
  }

  public async getPoPHealth(): Promise<{ pops: PoPHealthRecord[] }> {
    const res = await this.client.request<{ pops: PoPHealthRecord[] }>('/api/proxy/pops/health', {
      method: 'GET'
    });
    return res.data;
  }
}
