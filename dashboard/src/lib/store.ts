import { useSyncExternalStore } from 'react'
import type {
  AgentKind,
  Classification,
  Decision,
  ExecStatus,
  Flag,
  GatewayMode,
  LiveEvent,
  OutboxEmail,
  ReviewTicket,
  RunSession,
  ScenarioSummary,
  SessionRecord,
  ToolName,
  Verdict,
} from '../types/contracts'
import { api, ApiError, type Health, type RuleInfo } from './api'
import { ACTOR, REPLAY } from './config'
import { setReplaySink } from './replay'
import { errMsg } from './rules'
import { connectEvents, type SseState } from './sse'

/* ---------- state shapes ---------- */

export interface ActionView {
  action_id: string
  step: number
  tool: ToolName | null
  args: Record<string, unknown> | null
  verdict: Verdict
  status: ExecStatus
  matched_rules: string[]
  explanation: string
  llm_explanation: string | null
  flags: Flag[]
  result: Record<string, unknown> | null
  error: string | null
  ticket_id: string | null
  latency_ms: number | null
  would_verdict: Verdict | null
  taint: Classification | null
  strikes: number | null
  /** Every status this action has been seen with, oldest first. */
  history: ExecStatus[]
}

export interface SessionView {
  session_id: string
  mode: GatewayMode
  record: SessionRecord | null
  actions: ActionView[]
}

export interface ActiveRun {
  run_id: string
  scenario_id: string
  split: boolean
  agentKind: AgentKind
  /** True when this run was started by "Replay scripted" after a live LLM run. */
  scriptedReplay: boolean
  sessions: RunSession[]
  startedAt: number
}

export interface OutboxState {
  items: OutboxEmail[]
  /** idle = never loaded; error = last fetch failed (never shown as "empty"). */
  status: 'idle' | 'ok' | 'error'
  error: string | null
}

export interface AppState {
  health: { status: 'unknown' | 'ok' | 'down'; data: Health | null; error: string | null }
  sse: SseState | 'off'
  scenarios: { status: 'loading' | 'ok' | 'error'; items: ScenarioSummary[]; error: string | null }
  policy: Record<string, RuleInfo>
  sessions: Record<string, SessionView>
  run: ActiveRun | null
  runStarting: boolean
  runError: string | null
  tickets: ReviewTicket[]
  ticketsError: string | null
  outbox: Record<GatewayMode, OutboxState>
  /** Bumped when audit data may have changed. */
  auditTick: number
  /** Local AI explanations by action id, filled from explanation_ready events. */
  llmByAction: Record<string, string>
  /** When the last event for the current run arrived (ms since epoch). */
  lastEventAt: number | null
  evalProgress: Record<string, unknown> | null
  ui: { scenarioId: string | null; split: boolean; agentKind: AgentKind; selected: { session_id: string; action_id: string } | null }
}

const emptyOutbox = (): OutboxState => ({ items: [], status: 'idle', error: null })

let state: AppState = {
  health: { status: 'unknown', data: null, error: null },
  sse: 'off',
  scenarios: { status: 'loading', items: [], error: null },
  policy: {},
  sessions: {},
  run: null,
  runStarting: false,
  runError: null,
  tickets: [],
  ticketsError: null,
  outbox: { protected: emptyOutbox(), passthrough: emptyOutbox() },
  auditTick: 0,
  llmByAction: {},
  lastEventAt: null,
  evalProgress: null,
  ui: { scenarioId: null, split: true, agentKind: 'scripted', selected: null },
}

const listeners = new Set<() => void>()

function set(patch: Partial<AppState> | ((s: AppState) => Partial<AppState>)): void {
  const p = typeof patch === 'function' ? patch(state) : patch
  state = { ...state, ...p }
  listeners.forEach((l) => l())
}

export function useApp(): AppState {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    () => state,
  )
}

export const getState = (): AppState => state

/* ---------- event ingestion ---------- */

const ACTIVE_TICKET_STATES: ExecStatus[] = ['PENDING', 'PARKED', 'APPROVED']

function applyDecision(sessionId: string, mode: GatewayMode, d: Decision): void {
  set((s) => {
    const sess: SessionView = s.sessions[sessionId] ?? { session_id: sessionId, mode, record: null, actions: [] }
    let idx = sess.actions.findIndex((a) => a.action_id === d.action_id)
    // A re-checked approval may arrive under a new action id for the same step.
    if (idx < 0 && d.step != null) {
      idx = sess.actions.findIndex((a) => a.step === d.step && a.tool === (d.tool ?? a.tool) && ACTIVE_TICKET_STATES.includes(a.status))
    }
    const prev = idx >= 0 ? sess.actions[idx] : null
    const next: ActionView = {
      action_id: d.action_id,
      step: d.step ?? prev?.step ?? sess.actions.length + 1,
      tool: d.tool ?? prev?.tool ?? null,
      args: d.args_masked ?? prev?.args ?? null,
      verdict: d.verdict,
      status: d.status,
      matched_rules: d.matched_rules ?? prev?.matched_rules ?? [],
      explanation: d.explanation,
      llm_explanation: s.llmByAction[d.action_id] ?? prev?.llm_explanation ?? null,
      flags: d.flags ?? prev?.flags ?? [],
      result: d.result ?? null,
      error: d.error ?? null,
      ticket_id: d.ticket_id ?? prev?.ticket_id ?? null,
      latency_ms: d.latency_ms ?? null,
      would_verdict: d.would_verdict ?? prev?.would_verdict ?? null,
      taint: d.taint ?? prev?.taint ?? null,
      strikes: d.strikes ?? prev?.strikes ?? null,
      history: prev ? (prev.history.at(-1) === d.status ? prev.history : [...prev.history, d.status]) : [d.status],
    }
    const actions = prev ? sess.actions.map((a, i) => (i === idx ? next : a)) : [...sess.actions, next]
    actions.sort((a, b) => a.step - b.step)
    return { sessions: { ...s.sessions, [sessionId]: { ...sess, actions } } }
  })
}

function upsertTicket(t: ReviewTicket): void {
  set((s) => {
    const i = s.tickets.findIndex((x) => x.ticket_id === t.ticket_id)
    return { tickets: i >= 0 ? s.tickets.map((x, j) => (j === i ? { ...x, ...t } : x)) : [...s.tickets, t] }
  })
}

export function ingest(ev: LiveEvent): void {
  if (ev.type !== 'eval_progress' && state.run?.sessions.some((s) => s.session_id === ev.session_id)) set({ lastEventAt: Date.now() })
  switch (ev.type) {
    case 'decision': {
      const d = ev.payload as Decision
      if (!d || typeof d.action_id !== 'string') return
      applyDecision(ev.session_id, ev.mode, d)
      scheduleOutbox(ev.mode)
      bumpAudit()
      if (d.ticket_id || d.status === 'APPROVED' || d.status === 'REJECTED') void refreshTickets()
      break
    }
    case 'ticket':
    case 'ticket_update': {
      const t = ev.payload as ReviewTicket
      if (t && typeof t.ticket_id === 'string') upsertTicket(t)
      bumpAudit()
      break
    }
    case 'session_update': {
      const r = ev.payload as SessionRecord
      if (!r || typeof r.session_id !== 'string') return
      set((s) => {
        const sess: SessionView = s.sessions[ev.session_id] ?? { session_id: ev.session_id, mode: ev.mode, record: null, actions: [] }
        return { sessions: { ...s.sessions, [ev.session_id]: { ...sess, record: r } } }
      })
      break
    }
    case 'explanation_ready': {
      const p = ev.payload as Record<string, unknown>
      const text = [p.llm_explanation, p.explanation, p.text].find((v) => typeof v === 'string') as string | undefined
      if (typeof p.action_id !== 'string' || !text) return
      const actionId = p.action_id
      set((s) => {
        const sess = s.sessions[ev.session_id]
        return {
          llmByAction: { ...s.llmByAction, [actionId]: text },
          ...(sess
            ? { sessions: { ...s.sessions, [ev.session_id]: { ...sess, actions: sess.actions.map((a) => (a.action_id === actionId ? { ...a, llm_explanation: text } : a)) } } }
            : {}),
        }
      })
      bumpAudit()
      break
    }
    case 'eval_progress':
      set({ evalProgress: (ev.payload as Record<string, unknown>) ?? null })
      break
  }
}

/* ---------- data loading ---------- */

const timers: Record<string, ReturnType<typeof setTimeout> | undefined> = {}
function debounce(key: string, ms: number, fn: () => void): void {
  clearTimeout(timers[key])
  timers[key] = setTimeout(fn, ms)
}

function bumpAudit(): void {
  debounce('audit', 350, () => set((s) => ({ auditTick: s.auditTick + 1 })))
}

export async function refreshOutbox(mode: GatewayMode): Promise<void> {
  try {
    const items = await api.outbox(mode)
    set((s) => ({ outbox: { ...s.outbox, [mode]: { items, status: 'ok', error: null } } }))
  } catch (e) {
    set((s) => ({ outbox: { ...s.outbox, [mode]: { ...s.outbox[mode], status: 'error', error: errMsg(e) } } }))
  }
}

/** Refresh soon, and once more shortly after in case the file write trailed the event. */
function scheduleOutbox(mode: GatewayMode): void {
  debounce(`outbox-${mode}`, 120, () => void refreshOutbox(mode))
  debounce(`outbox2-${mode}`, 700, () => void refreshOutbox(mode))
}

export async function refreshTickets(): Promise<void> {
  try {
    const open = await api.tickets('pending,parked')
    set((s) => {
      const openIds = new Set(open.map((t) => t.ticket_id))
      // Keep tickets decided in this page session so the inbox can show what just happened.
      const decided = s.tickets.filter((t) => !openIds.has(t.ticket_id) && (t.state === 'approved' || t.state === 'rejected'))
      return { tickets: [...open, ...decided], ticketsError: null }
    })
  } catch (e) {
    set({ ticketsError: errMsg(e) })
  }
}

export async function loadScenarios(): Promise<void> {
  try {
    const items = await api.scenarios()
    set((s) => ({
      scenarios: { status: 'ok', items, error: null },
      ui: { ...s.ui, scenarioId: s.ui.scenarioId ?? items.find((x) => x.short_id === 'B1')?.id ?? items[0]?.id ?? null },
    }))
  } catch (e) {
    set({ scenarios: { status: 'error', items: [], error: errMsg(e) } })
  }
}

export async function loadPolicy(): Promise<void> {
  try {
    const p = await api.policy()
    set({ policy: Object.fromEntries(p.rules.map((r) => [r.id, r])) })
  } catch {
    /* rule text falls back to built-ins; the detail panel says when a rule is unknown */
  }
}

/** Re-fetch everything an SSE gap could have lost. */
export async function resync(): Promise<void> {
  set((s) => ({ auditTick: s.auditTick + 1 }))
  await Promise.all([refreshTickets(), refreshOutbox('protected'), refreshOutbox('passthrough')])
}

/* ---------- user actions ---------- */

export function setUi(patch: Partial<AppState['ui']>): void {
  set((s) => ({ ui: { ...s.ui, ...patch } }))
}

export function selectAction(sel: AppState['ui']['selected']): void {
  setUi({ selected: sel })
}

/** True once every session of the run has completed (the same test the Live Run banner uses). */
export function runFinished(s: AppState = state): boolean {
  return s.run != null && s.run.sessions.every((rs) => s.sessions[rs.session_id]?.record?.state === 'completed')
}

/**
 * Pick a scenario in the dropdown. A finished run of another scenario is cleared from the screen, so
 * its results never sit under the new scenario's name. A run that is still active stays visible:
 * it may be waiting on a ticket, and hiding it would hide that from the operator.
 */
export function chooseScenario(id: string): void {
  set((s) => {
    const stale = s.run != null && s.run.scenario_id !== id && runFinished(s)
    return stale
      ? { run: null, sessions: {}, lastEventAt: null, ui: { ...s.ui, scenarioId: id, selected: null } }
      : { ui: { ...s.ui, scenarioId: id, selected: null } }
  })
}

async function launch(scenarioId: string, agentKind: AgentKind, split: boolean, scriptedReplay: boolean): Promise<void> {
  const res = await api.startRun({ scenario_id: scenarioId, agent_kind: agentKind, split })
  set((s) => ({
    run: { run_id: res.run_id, scenario_id: res.scenario_id, split, agentKind, scriptedReplay, sessions: res.sessions, startedAt: Date.now() },
    runStarting: false,
    lastEventAt: Date.now(),
    ui: { ...s.ui, selected: null },
  }))
  void refreshOutbox('protected')
  void refreshOutbox('passthrough')
  void refreshTickets()
}

function clearLocalRun(): void {
  set((s) => ({ run: null, sessions: {}, tickets: [], lastEventAt: null, ui: { ...s.ui, selected: null } }))
}

export async function startRun(): Promise<void> {
  const { scenarioId, split, agentKind } = state.ui
  if (!scenarioId || state.runStarting) return
  set({ runStarting: true, runError: null })
  try {
    await launch(scenarioId, agentKind, split, false)
  } catch (e) {
    set({ runStarting: false, runError: errMsg(e) })
  }
}

/**
 * Replace the current (live) run with the scripted agent on the same scenario.
 * Reset first, because the gateway refuses a second run while one is active. If it still answers
 * 409, reset again and retry a few times instead of leaving the operator stuck.
 */
export async function replayScripted(): Promise<void> {
  const prev = state.run
  const scenarioId = prev?.scenario_id ?? state.ui.scenarioId
  if (!scenarioId || state.runStarting) return
  const split = prev?.split ?? state.ui.split
  set({ runStarting: true, runError: null })
  let lastErr: unknown = null
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      await api.resetSandbox()
      clearLocalRun()
      await launch(scenarioId, 'scripted', split, true)
      return
    } catch (e) {
      lastErr = e
      if (!(e instanceof ApiError) || e.status !== 409) break
      await new Promise((r) => setTimeout(r, 600 * (attempt + 1)))
    }
  }
  set({ runStarting: false, runError: `Replay scripted failed: ${errMsg(lastErr)}` })
}

export async function resetSandbox(): Promise<void> {
  set({ runError: null })
  try {
    await api.resetSandbox()
    clearLocalRun()
    await resync()
  } catch (e) {
    set({ runError: `Reset failed: ${errMsg(e)}` })
  }
}

export async function decideTicket(ticketId: string, approve: boolean): Promise<Decision> {
  const d = await api.decideTicket(ticketId, approve)
  // Mark it decided locally first so the card (and its outcome line) stays visible after the refetch.
  set((s) => ({
    tickets: s.tickets.map((t) => (t.ticket_id === ticketId ? { ...t, state: approve ? 'approved' : 'rejected', decided_by: ACTOR } : t)),
  }))
  await refreshTickets()
  return d
}

export async function unfreeze(sessionId: string): Promise<void> {
  const rec = await api.unfreeze(sessionId)
  set((s) => {
    const sess = s.sessions[sessionId]
    // Strikes were reset by the gateway, so drop the old per-action strike counts.
    return sess
      ? { sessions: { ...s.sessions, [sessionId]: { ...sess, record: rec, actions: sess.actions.map((a) => ({ ...a, strikes: null })) } } }
      : {}
  })
}

/* ---------- lifecycle ---------- */

let started = false

async function pollHealth(): Promise<void> {
  const wasUp = state.health.status === 'ok'
  try {
    const data = await api.health()
    set({ health: { status: data.ok ? 'ok' : 'down', data, error: null } })
    if (!wasUp && data.ok) {
      void loadScenarios()
      void loadPolicy()
      void resync()
    }
  } catch (e) {
    set({ health: { status: 'down', data: null, error: errMsg(e) } })
  }
}

/** Start health polling and the event source once. Safe to call twice (React StrictMode). */
export function startApp(): void {
  if (started) return
  started = true
  if (REPLAY) {
    setReplaySink(ingest)
    set({ health: { status: 'ok', data: { ok: true, ollama_available: false, model: null }, error: null }, sse: 'off' })
    void loadScenarios()
    void loadPolicy()
    return
  }
  void pollHealth()
  setInterval(() => void pollHealth(), 4000)
  connectEvents({
    onEvent: ingest,
    onState: (sse, reconnected) => {
      set({ sse })
      if (sse === 'open' && reconnected) void resync()
    },
  })
}
