import { useEffect, useMemo, useState } from 'react'
import type { AuditRecord, Decision, ReviewTicket } from '../types/contracts'
import { api } from '../lib/api'
import { REPLAY } from '../lib/config'
import { BUILTIN_RULES, deadlineText, errMsg, fmtArgs, shortId } from '../lib/rules'
import { decideTicket, refreshTickets, useApp, type ActionView, type AppState, type SessionView } from '../lib/store'
import { AiNote, FlagChip, Pill, VerdictChip } from '../components/Chips'

function findAction(sessions: AppState['sessions'], actionId: string): { session: SessionView; action: ActionView } | null {
  for (const session of Object.values(sessions)) {
    const action = session.actions.find((a) => a.action_id === actionId)
    if (action) return { session, action }
  }
  return null
}

interface Outcome {
  kind: 'ok' | 'error'
  text: string
  decision?: Decision
}

function TicketCard({
  t,
  app,
  now,
  outcome,
  busy,
  audit,
  onDecide,
}: {
  t: ReviewTicket
  app: AppState
  audit: AuditRecord | undefined
  now: number
  outcome: Outcome | undefined
  busy: boolean
  onDecide: (approve: boolean) => void
}) {
  const found = findAction(app.sessions, t.action_id)
  const tool = t.tool ?? found?.action.tool ?? audit?.tool ?? null
  const args = t.args_masked ?? found?.action.args ?? audit?.args_masked ?? null
  const flags = t.flags ?? found?.action.flags ?? audit?.flags ?? []
  const explanation = t.explanation ?? found?.action.explanation ?? audit?.explanation ?? null
  // Updates live from explanation_ready events; the audit row covers a page opened after the event.
  const llm = app.llmByAction[t.action_id] ?? found?.action.llm_explanation ?? audit?.llm_explanation ?? null
  const ruleDesc = app.policy[t.rule_id]?.description ?? BUILTIN_RULES[t.rule_id] ?? null
  const state = t.state ?? 'pending'
  const open = state === 'pending' || state === 'parked'
  const recent = (t.recent_actions ?? []).map((id) => ({ id, found: findAction(app.sessions, id) }))
  const mode = found?.session.mode

  return (
    <article className={`card flex flex-col gap-2 px-4 py-3 `} aria-label={`Review request ${t.ticket_id}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h3 className="measured text-xl font-medium">{tool ?? 'unknown tool'}</h3>
        <div className="flex flex-wrap items-baseline gap-x-5 gap-y-1 text-sm">
          <dl className="flex flex-wrap items-baseline gap-x-5 gap-y-1">
            <div>
              <dt className="inline text-muted">rule:</dt> <dd className="measured inline">{t.rule_id}</dd>
            </div>
            <div>
              <dt className="inline text-muted">risk:</dt> <dd className={`measured inline ${t.risk === 'high' ? 'font-medium text-cool' : ''}`}>{t.risk}</dd>
            </div>
            <div>
              <dt className="inline text-muted">urgency:</dt> <dd className="measured inline">{t.urgency}</dd>
            </div>
          </dl>
          <span className={state === 'parked' ? 'font-medium text-accent' : ''}>{deadlineText(t.deadline, now)}</span>
          {mode && <span>{mode}</span>}
        </div>
      </div>

      <div className="measured break-words rounded-pill bg-paper-3 px-3 py-1.5 text-sm">{fmtArgs(args)}</div>

      <div>
        <p className="text-lg font-medium leading-snug">{explanation ?? ruleDesc ?? 'No explanation reported.'}</p>
        {ruleDesc && explanation && explanation !== ruleDesc && <p className="mt-1 text-sm text-muted">Rule: {ruleDesc}</p>}
      </div>
      {llm && <AiNote text={llm} />}

      {flags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {flags.map((f) => (
            <FlagChip key={f} flag={f} />
          ))}
        </div>
      )}
      {flags.includes('URGENCY_CLAIM') && (
        <p className="text-sm font-medium text-bad">
          Urgency was claimed in agent or document text. Urgency here comes only from the task scope: {t.urgency}.
        </p>
      )}

      <div className="grid divide-y divide-rule border-y border-rule sm:grid-cols-2 sm:divide-x sm:divide-y-0">
        <div className="py-2 sm:pr-4">
          <div className="eyebrow">Impact if approved</div>
          <div className="mt-1">{t.impact_if_approved}</div>
        </div>
        <div className="py-2 sm:pl-4">
          <div className="eyebrow">Impact if rejected</div>
          <div className="mt-1">{t.impact_if_rejected}</div>
        </div>
      </div>

      {state === 'parked' && (
        <p className="band band-person">
          Waiting for you. The review window passed, so the task is suspended. Nothing was approved or rejected for you, and a late approval re-runs every rule first.
        </p>
      )}

      {open ? (
        <div className="flex flex-wrap items-center justify-end gap-2">
          <span className="basis-full text-sm text-muted sm:mr-auto sm:basis-auto">
            ticket <span className="measured">{shortId(t.ticket_id, 12)}</span>
          </span>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => onDecide(false)}>
            Reject
          </button>
          <button type="button" className="btn" disabled={busy} onClick={() => onDecide(true)}>
            {busy ? 'Working…' : 'Approve'}
          </button>
        </div>
      ) : (
        <p className="font-medium">
          {state === 'approved' ? 'Approved' : 'Rejected'}
          {t.decided_by ? ` by ${t.decided_by}` : ''}
        </p>
      )}
      {outcome && (
        <p role="status" className={`font-medium ${outcome.kind === 'error' ? 'text-bad' : 'text-ok'}`}>
          {outcome.text}
        </p>
      )}

      <details>
        <summary className="min-h-11 py-2 font-medium text-muted">Recent history ({recent.length})</summary>
        {recent.length === 0 ? (
          <p className="mt-1 text-sm text-muted">No earlier actions reported.</p>
        ) : (
          <ol className="mt-1 flex flex-col gap-2 text-sm">
            {recent.map(({ id, found: f }) => (
              <li key={id} className="flex flex-wrap items-center gap-2">
                {f ? (
                  <>
                    <span className="measured w-6 text-muted">{f.action.step}</span>
                    <span className="measured font-medium">{f.action.tool}</span>
                    <VerdictChip verdict={f.action.verdict} />
                    <span className="measured break-all text-muted">{fmtArgs(f.action.args)}</span>
                  </>
                ) : (
                  <span className="measured text-muted">{shortId(id, 12)} (details not loaded in this page)</span>
                )}
              </li>
            ))}
          </ol>
        )}
      </details>
    </article>
  )
}

export default function ReviewInbox() {
  const app = useApp()
  const [now, setNow] = useState(() => Date.now())
  const [busyId, setBusyId] = useState<string | null>(null)
  const [outcomes, setOutcomes] = useState<Record<string, Outcome>>({})
  const [auditRows, setAuditRows] = useState<Record<string, AuditRecord>>({})

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30000)
    return () => clearInterval(id)
  }, [])
  useEffect(() => {
    void refreshTickets()
  }, [])

  const { pending, parked, decided } = useMemo(() => {
    const by = (a: ReviewTicket, b: ReviewTicket) => a.created_at.localeCompare(b.created_at)
    return {
      pending: app.tickets.filter((t) => (t.state ?? 'pending') === 'pending').sort(by),
      parked: app.tickets.filter((t) => t.state === 'parked').sort(by),
      decided: app.tickets.filter((t) => t.state === 'approved' || t.state === 'rejected').sort(by).reverse(),
    }
  }, [app.tickets])

  // Tickets whose action is not in this page's event store (page opened late) get their context from the audit log.
  const missingSessions = useMemo(
    () => [...new Set(app.tickets.filter((t) => !findAction(app.sessions, t.action_id)).map((t) => t.session_id))].sort().join(','),
    [app.tickets, app.sessions],
  )
  useEffect(() => {
    if (REPLAY || !missingSessions) return
    let cancelled = false
    void Promise.all(missingSessions.split(',').map((sid) => api.audit({ session_id: sid }).catch(() => [] as AuditRecord[]))).then((lists) => {
      if (cancelled) return
      setAuditRows((prev) => ({ ...prev, ...Object.fromEntries(lists.flat().map((r) => [r.action_id, r])) }))
    })
    return () => {
      cancelled = true
    }
  }, [missingSessions, app.auditTick])

  const onDecide = async (t: ReviewTicket, approve: boolean) => {
    setBusyId(t.ticket_id)
    try {
      const d = await decideTicket(t.ticket_id, approve)
      const text = approve
        ? d.verdict === 'ALLOW' || d.status === 'EXECUTED'
          ? `Approved. Rules were re-checked and the result is ${d.status}.`
          : `Approved, but the re-check came back ${d.verdict} (${d.status}). ${d.explanation}`
        : `Rejected. The tool did not run (${d.status}).`
      setOutcomes((o) => ({ ...o, [t.ticket_id]: { kind: 'ok', text, decision: d } }))
    } catch (e) {
      setOutcomes((o) => ({ ...o, [t.ticket_id]: { kind: 'error', text: `Decision failed: ${errMsg(e)}` } }))
    } finally {
      setBusyId(null)
    }
  }

  const render = (list: ReviewTicket[]) =>
    list.map((t) => (
      <TicketCard key={t.ticket_id} t={t} app={app} audit={auditRows[t.action_id]} now={now} outcome={outcomes[t.ticket_id]} busy={busyId === t.ticket_id} onDecide={(a) => void onDecide(t, a)} />
    ))

  return (
    <div className="flex max-w-4xl flex-col gap-3">
      <header className="flex flex-col">
        <h1 className="text-3xl leading-tight">Review Inbox</h1>
        <p className="text-sm text-muted">A REVIEW never turns into ALLOW on its own. Silence is never a yes.</p>
      </header>

      {REPLAY && <div className="band band-system">Recorded replay has no review tickets: B1 never reaches REVIEW.</div>}
      {app.ticketsError && !REPLAY && (
        <div role="alert" className="band band-system">
          Could not load tickets: {app.ticketsError}
        </div>
      )}

      <section aria-label="Pending requests" className="flex flex-col gap-2">
        <h2 className="flex items-center gap-3">
          Pending <Pill tone={pending.length ? 'hot' : 'plain'}>{pending.length}</Pill>
        </h2>
        {pending.length === 0 ? <div className="card p-6 text-muted">No requests waiting.</div> : render(pending)}
      </section>

      <section aria-label="Parked requests" className="mt-3 flex flex-col gap-2">
        <h2 className="flex items-center gap-3">
          Waiting for you (parked) <Pill tone={parked.length ? 'hot' : 'plain'}>{parked.length}</Pill>
        </h2>
        {parked.length === 0 ? <div className="card p-6 text-muted">Nothing parked.</div> : render(parked)}
      </section>

      {decided.length > 0 && (
        <section aria-label="Decided this session" className="flex flex-col gap-3">
          <h2>Decided in this page session</h2>
          {render(decided)}
        </section>
      )}
    </div>
  )
}
