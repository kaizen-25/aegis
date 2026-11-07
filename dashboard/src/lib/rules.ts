import type { Flag, GatewayMode } from '../types/contracts'

/** Built-in rules that are not in the policy YAML (policy-rulebook.md section 2). */
export const BUILTIN_RULES: Record<string, string> = {
  'R-SCOPE': 'This action is outside the current task (possible injection)',
  'R-LLM-OBSERVER': 'The local AI observer raised a concern; a human must decide',
  'R-DEFAULT-NO-MATCH': 'No rule covers this action; a human must decide',
  'R-SYSTEM-FAIL-CLOSED': 'Aegis could not evaluate this safely, so it was blocked',
}

export const FLAG_MEANING: Record<Flag, string> = {
  OFF_TASK: 'Outside the task scope: possible injection',
  UNTRUSTED_CONTENT: 'A document read in this session contained instruction-like text',
  URGENCY_CLAIM: 'Agent text or a document claimed urgency. Urgency comes only from the task scope.',
  LLM_CONCERN: 'The optional LLM observer raised ALLOW to REVIEW',
  CONTENT_MATCH: 'The draft contains a fingerprint of confidential data read in this session',
  SYSTEM_FAIL_CLOSED: 'Aegis could not evaluate this safely, so it was blocked',
}

export const MODE_LABEL: Record<GatewayMode, string> = {
  passthrough: 'Without Aegis',
  protected: 'With Aegis',
}

/** One line of masked args, e.g. `path=confidential/customers.csv`. Values are already masked by the gateway. */
export function fmtArgs(args: Record<string, unknown> | null | undefined): string {
  if (!args) return ''
  return Object.entries(args)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join('  ')
}

export function fmtJson(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2)
  } catch {
    return String(v)
  }
}

export function shortId(id: string, n = 8): string {
  return id.length > n ? id.slice(0, n) : id
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString()
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

export function fmtMs(v: number | null | undefined): string {
  if (v === null || v === undefined) return 'Not measured'
  return `${v < 10 ? v.toFixed(2) : v.toFixed(1)} ms`
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** Time left until an ISO deadline, or "No deadline". */
export function deadlineText(deadline: string | null | undefined, now: number): string {
  if (!deadline) return 'No deadline'
  const t = new Date(deadline).getTime()
  if (Number.isNaN(t)) return deadline
  const mins = Math.round((t - now) / 60000)
  const at = new Date(t).toLocaleTimeString()
  if (mins < 0) return `Deadline passed at ${at}`
  if (mins < 1) return `Due within a minute (${at})`
  return `Due in ${mins} min (${at})`
}
