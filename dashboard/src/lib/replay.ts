import type {
  Decision,
  ExecStatus,
  Flag,
  GatewayMode,
  LiveEvent,
  OutboxEmail,
  RunStarted,
  ScenarioCategory,
  ScenarioSummary,
  Verdict,
} from '../types/contracts'
import raw from '../fixtures/b1-split.json'
import type { Api } from './api'
import { ApiError } from './errors'

/** Recorded replay source (?replay=1). Never touches the network. */

interface Frame {
  t: number
  event: LiveEvent
  outbox_add?: OutboxEmail
}
export interface Fixture {
  meta: {
    scenario_id: string
    short_id: string
    title: string
    category: ScenarioCategory
    brief_test: string
    task: string
    /** "captured" = recorded from a running gateway; "authored" = written by hand (no longer used). */
    capture: 'authored' | 'captured'
    note: string
  }
  rule_descriptions: Record<string, string>
  frames: Frame[]
}

const VERDICTS: Verdict[] = ['ALLOW', 'BLOCK', 'REVIEW']
const STATUSES: ExecStatus[] = ['EXECUTED', 'EXECUTION_FAILED', 'BLOCKED', 'FAIL_CLOSED', 'PENDING', 'PARKED', 'APPROVED', 'REJECTED']
const FLAGS: Flag[] = ['OFF_TASK', 'UNTRUSTED_CONTENT', 'URGENCY_CLAIM', 'LLM_CONCERN', 'CONTENT_MATCH', 'SYSTEM_FAIL_CLOSED']
const MODES: GatewayMode[] = ['protected', 'passthrough']
const TYPES = ['decision', 'ticket', 'ticket_update', 'session_update', 'explanation_ready', 'eval_progress']

/** The JSON import is typed loosely, so check enum values once at load. */
function validate(f: Fixture): Fixture {
  for (const [i, fr] of f.frames.entries()) {
    const ev = fr.event
    const bad = (why: string) => {
      throw new Error(`b1-split.json frame ${i}: ${why}`)
    }
    if (!TYPES.includes(ev.type)) bad(`type ${ev.type}`)
    if (!MODES.includes(ev.mode)) bad(`mode ${ev.mode}`)
    if (ev.type === 'decision') {
      const d = ev.payload as Decision
      if (!VERDICTS.includes(d.verdict)) bad(`verdict ${d.verdict}`)
      if (!STATUSES.includes(d.status)) bad(`status ${d.status}`)
      for (const fl of d.flags ?? []) if (!FLAGS.includes(fl)) bad(`flag ${fl}`)
    }
  }
  return f
}

export const FIXTURE: Fixture = validate(raw as unknown as Fixture)

type Sink = (ev: LiveEvent) => void
let sink: Sink | null = null
let timers: ReturnType<typeof setTimeout>[] = []
let runCount = 0
let outbox: Record<GatewayMode, OutboxEmail[]> = { protected: [], passthrough: [] }

export function setReplaySink(s: Sink): void {
  sink = s
}

function stop(): void {
  for (const t of timers) clearTimeout(t)
  timers = []
}

/** Give each replay run fresh ids so a second run never merges into the first. */
function rewrite(fr: Frame, suffix: string): Frame {
  const copy: Frame = JSON.parse(JSON.stringify(fr))
  copy.event.session_id += suffix
  const p = copy.event.payload as Record<string, unknown>
  if (typeof p.session_id === 'string') p.session_id += suffix
  if (typeof p.action_id === 'string') p.action_id += suffix
  if (copy.outbox_add) {
    copy.outbox_add.session_id += suffix
    copy.outbox_add.email_id += suffix
  }
  return copy
}

const unavailable = (what: string) => new ApiError(`${what} is not available in recorded replay`, 0, 'REPLAY')

export const replayApi: Api = {
  health: async () => ({ ok: true, ollama_available: false, model: null }),
  scenarios: async (): Promise<ScenarioSummary[]> => [
    {
      id: FIXTURE.meta.scenario_id,
      short_id: FIXTURE.meta.short_id,
      title: FIXTURE.meta.title,
      category: FIXTURE.meta.category,
      brief_test: FIXTURE.meta.brief_test,
      task: FIXTURE.meta.task,
      has_llm_prompt: false,
    },
  ],
  policy: async () => ({
    yaml: null,
    rules: Object.entries(FIXTURE.rule_descriptions).map(([id, description]) => ({ id, description })),
  }),
  startRun: async ({ split }): Promise<RunStarted> => {
    stop()
    outbox = { protected: [], passthrough: [] }
    runCount += 1
    const suffix = `-r${runCount}`
    const frames = FIXTURE.frames
      .filter((f) => split || f.event.mode === 'protected')
      .map((f) => rewrite(f, suffix))
    for (const fr of frames) {
      timers.push(
        setTimeout(() => {
          if (fr.outbox_add) outbox[fr.outbox_add.mode].push(fr.outbox_add)
          sink?.(fr.event)
        }, fr.t),
      )
    }
    return {
      run_id: `replay${suffix}`,
      scenario_id: FIXTURE.meta.scenario_id,
      sessions: (split ? (['passthrough', 'protected'] as const) : (['protected'] as const)).map((mode) => ({
        session_id: `${FIXTURE.frames.find((f) => f.event.mode === mode)!.event.session_id}${suffix}`,
        mode,
      })),
    }
  },
  resetSandbox: async () => {
    stop()
    outbox = { protected: [], passthrough: [] }
  },
  outbox: async (mode) => [...outbox[mode]],
  tickets: async () => [],
  decideTicket: async () => {
    throw unavailable('Review decisions')
  },
  unfreeze: async () => {
    throw unavailable('Unfreeze')
  },
  audit: async () => {
    throw unavailable('The audit log')
  },
  verifyAudit: async () => {
    throw unavailable('Audit verification')
  },
  startEval: async () => {
    throw unavailable('Evaluation')
  },
  evalReport: async () => {
    throw unavailable('The evaluation report')
  },
}
