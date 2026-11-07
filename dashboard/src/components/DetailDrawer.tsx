import { useEffect, useRef } from 'react'
import type { RuleInfo } from '../lib/api'
import { BUILTIN_RULES, FLAG_MEANING, fmtJson, fmtMs, fmtArgs } from '../lib/rules'
import { selectAction, type ActionView, type SessionView } from '../lib/store'
import { AiNote, FlagChip, OutcomeChip, Pill, StatusChip, VerdictChip } from './Chips'

interface Props {
  action: ActionView
  session: SessionView
  policy: Record<string, RuleInfo>
}

function ruleText(id: string, policy: Record<string, RuleInfo>): { text: string; rationale: string | null; known: boolean } {
  const p = policy[id]
  if (p) return { text: p.description, rationale: p.rationale ?? null, known: true }
  if (BUILTIN_RULES[id]) return { text: BUILTIN_RULES[id], rationale: null, known: true }
  return { text: 'Description unavailable: this rule id is not in the loaded policy.', rationale: null, known: false }
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="border-t border-rule py-3">
      <div className="text-sm font-medium text-muted">{label}</div>
      <div className="mt-0.5 break-words">{children}</div>
    </div>
  )
}

export default function DetailDrawer({ action: a, session, policy }: Props) {
  const closeRef = useRef<HTMLButtonElement>(null)
  const asideRef = useRef<HTMLElement>(null)
  const passthrough = session.mode === 'passthrough'

  useEffect(() => {
    closeRef.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') selectAction(null)
    }
    // A press anywhere outside the panel closes it, so it never sits over the Run controls.
    // Pressing another timeline row still works: this closes, then that row's click opens its own detail.
    const onPointer = (e: PointerEvent) => {
      if (asideRef.current && e.target instanceof Node && !asideRef.current.contains(e.target)) selectAction(null)
    }
    window.addEventListener('keydown', onKey)
    window.addEventListener('pointerdown', onPointer)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('pointerdown', onPointer)
    }
  }, [])

  return (
    <aside
      ref={asideRef}
      role="dialog"
      aria-label="Decision detail"
      className="fixed bottom-0 right-0 top-0 z-(--z-modal) w-[min(30rem,100%)] overflow-y-auto border-l border-rule bg-paper-2 p-5"
    >
      <div className="mb-4 flex items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <OutcomeChip verdict={a.verdict} status={a.status} />
          <StatusChip status={a.status} />
          <Pill>{passthrough ? 'passthrough' : 'protected'}</Pill>
        </div>
        <button ref={closeRef} type="button" className="btn btn-sm" aria-label="Close detail panel" onClick={() => selectAction(null)}>
          Close
        </button>
      </div>

      <div className="text-lg font-medium">
        <span>Step {a.step}:</span> <span className="measured">{a.tool ?? 'unknown tool'}</span>
      </div>
      <div className="measured mt-1 break-words text-sm text-muted">{fmtArgs(a.args)}</div>
      <p className="my-4 text-xl font-medium leading-snug">{a.explanation}</p>
      {a.llm_explanation && <AiNote text={a.llm_explanation} className="mb-4" />}

      {passthrough && (
        <div className="band band-system mb-4 text-sm">
          <b className="font-medium text-cool">Passthrough: this action ran with no check.</b>
          <div className="flex flex-wrap items-center gap-2">
            Protected mode would have said:
            {a.would_verdict ? <VerdictChip verdict={a.would_verdict} /> : <span className="font-medium">not recorded</span>}
          </div>
        </div>
      )}

      <h3 className="eyebrow mb-2">Matched rules{a.matched_rules.length > 1 ? ' (winner first)' : ''}</h3>
      {a.matched_rules.length === 0 ? (
        <p className="mb-3 text-muted">No rule ids were reported.</p>
      ) : (
        <ol className="mb-3 ml-1 border-l border-rule-2">
          {a.matched_rules.map((id, i) => {
            const r = ruleText(id, policy)
            return (
              <li key={id} className={`ml-3 rounded-pill px-3 py-2 ${i === 0 ? 'bg-paper-3' : ''}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="measured font-medium">{id}</span>
                  {i === 0 && <span className="rounded-[4px] border border-rule-2 px-1.5 text-xs font-medium text-ink">decided</span>}
                </div>
                <div className={r.known ? 'mt-0.5' : 'mt-0.5 text-muted'}>{r.text}</div>
                {r.rationale && <div className="mt-0.5 text-sm text-muted">Why: {r.rationale}</div>}
              </li>
            )
          })}
        </ol>
      )}

      <Row label="Flags">
        {a.flags.length === 0 ? (
          <span className="text-muted">None</span>
        ) : (
          <ul className="flex flex-col gap-2">
            {a.flags.map((f) => (
              <li key={f} className="flex flex-col items-start gap-1">
                <FlagChip flag={f} />
                <span className="text-sm text-muted">{FLAG_MEANING[f]}</span>
              </li>
            ))}
          </ul>
        )}
      </Row>
      <Row label="Session taint at decision">{a.taint ? <span className="measured">{a.taint}</span> : <span className="text-muted">Not reported</span>}</Row>
      <Row label="Strikes at decision">{a.strikes !== null ? <span className="measured">{a.strikes}</span> : <span className="text-muted">Not reported</span>}</Row>
      {passthrough && <Row label="would_verdict">{a.would_verdict ?? <span className="text-muted">Not recorded</span>}</Row>}
      <Row label="Gateway latency (excludes the tool)">
        <span className={a.latency_ms === null ? 'text-muted' : 'measured'}>{fmtMs(a.latency_ms)}</span>
      </Row>
      <Row label="Status history">
        <span className="flex flex-wrap items-center gap-1">
          {a.history.map((h, i) => (
            <span key={`${h}-${i}`} className="flex items-center gap-1">
              {i > 0 && <span aria-hidden="true">{'→'}</span>}
              <StatusChip status={h} />
            </span>
          ))}
        </span>
      </Row>
      {a.ticket_id && (
        <Row label="Review ticket">
          <a className="measured underline decoration-rule-2 underline-offset-4 hover:text-accent" href="#/inbox">
            {a.ticket_id}
          </a>
        </Row>
      )}
      {a.error && <Row label="Tool error">{a.error}</Row>}
      {a.result && (
        <Row label="Result (masked)">
          <pre className="measured mt-1 overflow-x-auto rounded-pill bg-paper-3 p-3 text-sm">{fmtJson(a.result)}</pre>
        </Row>
      )}
    </aside>
  )
}
