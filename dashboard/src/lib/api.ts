import type {
  AgentKind,
  AuditRecord,
  Decision,
  EvalReport,
  GatewayMode,
  OutboxEmail,
  PolicyRule,
  ReviewTicket,
  RunStarted,
  ScenarioSummary,
  SessionRecord,
  ToolName,
  Verdict,
} from '../types/contracts'
import { ACTOR, API_BASE, REPLAY } from './config'
import { ApiError } from './errors'
import { replayApi } from './replay'

/*
 * Response wrappers below are not exported by contracts.ts. They mirror the field lists in
 * docs/contracts-spec.md section 3 (health, audit verify, policy) and are parsed defensively.
 */
export interface Health {
  ok: boolean
  ollama_available: boolean
  model: string | null
}
export interface AuditVerify {
  ok: boolean
  broken_at_seq: number | null
}
export type RuleInfo = Pick<PolicyRule, 'id' | 'description'> & Partial<PolicyRule>
export interface PolicyView {
  yaml: string | null
  rules: RuleInfo[]
}
export interface AuditFilters {
  session_id?: string
  tool?: ToolName | ''
  verdict?: Verdict | ''
  rule?: string
  mode?: GatewayMode | ''
}

export { ApiError }

export interface Api {
  health(): Promise<Health>
  scenarios(): Promise<ScenarioSummary[]>
  policy(): Promise<PolicyView>
  startRun(req: { scenario_id: string; agent_kind: AgentKind; split: boolean }): Promise<RunStarted>
  resetSandbox(): Promise<void>
  outbox(mode: GatewayMode): Promise<OutboxEmail[]>
  tickets(states: string): Promise<ReviewTicket[]>
  decideTicket(ticketId: string, approve: boolean): Promise<Decision>
  unfreeze(sessionId: string): Promise<SessionRecord>
  audit(filters: AuditFilters): Promise<AuditRecord[]>
  verifyAudit(): Promise<AuditVerify>
  startEval(withLlm: boolean): Promise<{ report_id: string }>
  evalReport(id: string, signal?: AbortSignal): Promise<EvalReport>
}

async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response
  try {
    res = await fetch(API_BASE + path, {
      method,
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    })
  } catch (e) {
    if (signal?.aborted) throw e
    throw new ApiError(`Gateway unreachable at ${API_BASE}`, 0, 'NETWORK')
  }
  const text = await res.text()
  let data: unknown = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = null
    }
  }
  if (!res.ok) {
    const d = data as { error?: string; code?: string } | null
    throw new ApiError(d?.error ?? `HTTP ${res.status}`, res.status, d?.code ?? 'HTTP_ERROR')
  }
  return data as T
}

/** Accept a bare array or a wrapper object holding the array. */
function asList<T>(data: unknown, keys: string[] = ['items', 'records', 'rows', 'data']): T[] {
  if (Array.isArray(data)) return data as T[]
  if (data && typeof data === 'object') {
    for (const k of keys) {
      const v = (data as Record<string, unknown>)[k]
      if (Array.isArray(v)) return v as T[]
    }
  }
  return []
}

function qs(params: Record<string, string | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v)
  const s = p.toString()
  return s ? `?${s}` : ''
}

const enc = encodeURIComponent

const liveApi: Api = {
  health: () => request<Health>('GET', '/health'),
  scenarios: async () => asList<ScenarioSummary>(await request('GET', '/scenarios')),
  policy: async () => {
    const raw = await request<Record<string, unknown>>('GET', '/policy')
    const parsed = (raw.policy ?? raw.parsed ?? raw) as { rules?: unknown }
    const rules = [...asList<RuleInfo>(raw.rules ?? parsed.rules, ['rules']), ...asList<RuleInfo>(raw.builtin_rules, ['rules'])]
    const yaml = [raw.yaml, raw.raw, raw.text, raw.yaml_text].find((v) => typeof v === 'string')
    return { yaml: (yaml as string | undefined) ?? null, rules }
  },
  startRun: (req) => request<RunStarted>('POST', '/runs', req),
  resetSandbox: async () => {
    await request('POST', '/sandbox/reset')
  },
  outbox: async (mode) => asList<OutboxEmail>(await request('GET', `/outbox${qs({ mode })}`)),
  tickets: async (states) => asList<ReviewTicket>(await request('GET', `/tickets${qs({ state: states })}`), ['tickets', 'items']),
  decideTicket: (id, approve) => request<Decision>('POST', `/tickets/${enc(id)}/decision`, { approve, by: ACTOR }),
  unfreeze: (sid) => request<SessionRecord>('POST', `/sessions/${enc(sid)}/unfreeze`, { by: ACTOR }),
  audit: async (f) =>
    asList<AuditRecord>(
      await request('GET', `/audit${qs({ session_id: f.session_id, tool: f.tool, verdict: f.verdict, rule: f.rule, mode: f.mode })}`),
    ),
  verifyAudit: () => request<AuditVerify>('GET', '/audit/verify'),
  startEval: (withLlm) => request<{ report_id: string }>('POST', '/eval/run', { with_llm: withLlm }),
  evalReport: (id, signal) => request<EvalReport>('GET', `/eval/report/${enc(id)}`, undefined, signal),
}

/** In replay mode nothing touches the network. */
export const api: Api = REPLAY ? replayApi : liveApi
