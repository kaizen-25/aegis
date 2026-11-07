import { Fragment, useEffect, useMemo, useState } from 'react'
import type { AuditRecord, GatewayMode, ToolName, Verdict } from '../types/contracts'
import { api, type AuditFilters, type AuditVerify } from '../lib/api'
import { REPLAY } from '../lib/config'
import { errMsg, fmtArgs, fmtJson, fmtMs, fmtTime, shortId } from '../lib/rules'
import { useApp } from '../lib/store'
import { AiNote, FlagChip, OutcomeChip, StatusChip, WouldChip } from '../components/Chips'
import { recipientFirst } from '../components/recipientFirst'

const TOOLS: ToolName[] = ['file.read', 'report.write', 'db.query', 'db.delete', 'email.draft', 'email.send']
const VERDICTS: Verdict[] = ['ALLOW', 'BLOCK', 'REVIEW']
const MODES: GatewayMode[] = ['protected', 'passthrough']

/** The row shows a short form; the tooltip and the open record carry the whole value. */
const brief = (text: string, max = 56) => (text.length > max ? `${text.slice(0, max).trimEnd()}…` : text)

export default function AuditLog() {
  const app = useApp()
  const [filters, setFilters] = useState<AuditFilters>({ session_id: '', tool: '', verdict: '', rule: '', mode: '' })
  const [rows, setRows] = useState<AuditRecord[]>([])
  const [status, setStatus] = useState<'loading' | 'ok' | 'error'>('loading')
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState<Set<number>>(new Set())
  const [verify, setVerify] = useState<{ state: 'idle' | 'running' | 'done' | 'error'; result?: AuditVerify; error?: string }>({ state: 'idle' })

  // Text inputs are debounced so each keystroke does not hit the gateway.
  const [debounced, setDebounced] = useState(filters)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(filters), 250)
    return () => clearTimeout(t)
  }, [filters])

  useEffect(() => {
    if (REPLAY) return
    let cancelled = false
    api
      .audit(debounced)
      .then((r) => {
        if (cancelled) return
        setRows([...r].sort((a, b) => b.seq - a.seq))
        setStatus('ok')
        setError(null)
      })
      .catch((e) => {
        if (cancelled) return
        setStatus('error')
        setError(errMsg(e))
      })
    return () => {
      cancelled = true
    }
  }, [debounced, app.auditTick])

  const sessionOptions = useMemo(() => [...new Set([...rows.map((r) => r.session_id), ...Object.keys(app.sessions)])], [rows, app.sessions])
  const ruleOptions = useMemo(() => [...new Set(rows.flatMap((r) => r.matched_rules))].sort(), [rows])

  const set = <K extends keyof AuditFilters>(k: K, v: AuditFilters[K]) => setFilters((f) => ({ ...f, [k]: v }))
  const anyFilter = Object.values(filters).some(Boolean)

  const runVerify = async () => {
    setVerify({ state: 'running' })
    try {
      setVerify({ state: 'done', result: await api.verifyAudit() })
    } catch (e) {
      setVerify({ state: 'error', error: errMsg(e) })
    }
  }

  const broken = verify.state === 'done' && !verify.result?.ok ? (verify.result?.broken_at_seq ?? null) : null

  if (REPLAY) {
    return (
      <div className="flex max-w-3xl flex-col gap-3">
        <h1 className="text-3xl">Audit Log</h1>
        <div className="card p-6 text-muted">The audit log is not available in recorded replay. Open the dashboard without ?replay=1 once the gateway is up.</div>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-col gap-1">
        <h1 className="text-3xl">Audit Log</h1>
        <p className="text-sm text-muted">One record per attempted action. Sensitive values are masked, and each record is hash-chained to the one before it.</p>
      </header>

      <form className="card flex flex-wrap items-end gap-x-4 gap-y-3 p-4" onSubmit={(e) => e.preventDefault()} aria-label="Audit filters">
        <label className="flex min-w-36 flex-1 flex-col gap-1">
          <span className="eyebrow">Session</span>
          <input className="field measured" list="audit-sessions" value={filters.session_id} onChange={(e) => set('session_id', e.target.value)} placeholder="any" />
          <datalist id="audit-sessions">
            {sessionOptions.map((s) => (
              <option key={s} value={s} />
            ))}
          </datalist>
        </label>
        <label className="flex min-w-32 flex-1 flex-col gap-1">
          <span className="eyebrow">Tool</span>
          <select className="field" value={filters.tool} onChange={(e) => set('tool', e.target.value as ToolName | '')}>
            <option value="">any</option>
            {TOOLS.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
        <label className="flex min-w-28 flex-1 flex-col gap-1">
          <span className="eyebrow">Verdict</span>
          <select className="field" value={filters.verdict} onChange={(e) => set('verdict', e.target.value as Verdict | '')}>
            <option value="">any</option>
            {VERDICTS.map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </label>
        <label className="flex min-w-36 flex-1 flex-col gap-1">
          <span className="eyebrow">Rule</span>
          <input className="field" list="audit-rules" value={filters.rule} onChange={(e) => set('rule', e.target.value)} placeholder="any, e.g. R-SCOPE" />
          <datalist id="audit-rules">
            {ruleOptions.map((r) => (
              <option key={r} value={r} />
            ))}
          </datalist>
        </label>
        <label className="flex min-w-28 flex-1 flex-col gap-1">
          <span className="eyebrow">Mode</span>
          <select className="field" value={filters.mode} onChange={(e) => set('mode', e.target.value as GatewayMode | '')}>
            <option value="">any</option>
            {MODES.map((m) => (
              <option key={m}>{m}</option>
            ))}
          </select>
        </label>
        <div className="ml-auto flex flex-wrap items-center justify-end gap-x-4 gap-y-2" aria-live="polite">
          {verify.state === 'done' &&
            (verify.result?.ok ? (
              <span className="text-xl font-medium text-ok">{'\u2713'} Chain intact</span>
            ) : (
              <span className="rounded-[4px] border border-bad bg-bad-soft px-2 py-0.5 text-xl font-medium text-bad">
                {'\u2715'} Chain broken{broken !== null ? ` at seq ${broken}` : ''}
              </span>
            ))}
          {verify.state === 'error' && <span className="font-medium text-bad">Verify failed: {verify.error}</span>}
          <button type="button" className="btn btn-primary" disabled={verify.state === 'running'} onClick={() => void runVerify()}>
            {verify.state === 'running' ? 'Verifying…' : 'Verify'}
          </button>
        </div>
      </form>

      {status === 'error' && (
        <div role="alert" className="band band-system">
          Could not load the audit log: {error}
        </div>
      )}
      {status === 'loading' && <div className="card p-6 text-muted">Loading…</div>}
      {status === 'ok' && rows.length === 0 && (
        <div className="card p-6 text-muted">{anyFilter ? 'No records match these filters.' : 'No decisions recorded yet. Run a scenario.'}</div>
      )}

      {rows.length > 0 && (
        <div className="@container overflow-x-auto">
          <table className="tbl tbl-stack [&_td]:py-1.5">
            <caption className="sr-only">Audit records, newest first</caption>
            <thead>
              <tr>
                {['Seq', 'Time', 'Run', 'Action', 'Outcome', 'Rules and flags', 'State'].map((h, n) => (
                  <th key={h} scope="col" className={n === 0 ? 'sticky left-0 z-(--z-raised) bg-paper' : ''}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const isOpen = open.has(r.seq)
                const bad = broken !== null && r.seq >= broken
                return (
                  <Fragment key={r.seq}>
                    <tr
                      className="group cursor-pointer align-top"
                      onClick={() =>
                        setOpen((s) => {
                          const n = new Set(s)
                          if (n.has(r.seq)) n.delete(r.seq)
                          else n.add(r.seq)
                          return n
                        })
                      }
                    >
                      <td data-label="Seq" className={`sticky left-0 z-(--z-raised) max-[60rem]:static ${bad ? 'bg-bad-soft' : 'bg-paper group-hover:bg-paper-2'}`}>
                        <button
                          type="button"
                          aria-expanded={isOpen}
                          className="measured inline-flex min-h-11 min-w-11 items-center justify-center font-medium underline decoration-rule-2 underline-offset-4 hover:text-accent max-[60rem]:min-w-0 max-[60rem]:items-start max-[60rem]:justify-start"
                          onClick={(e) => e.preventDefault()}
                        >
                          {r.seq}
                        </button>
                        {broken === r.seq && <div className="text-xs font-medium text-bad">first broken</div>}
                      </td>
                      <td data-label="Time" className={`measured whitespace-nowrap text-sm ${bad ? 'bg-bad-soft' : 'group-hover:bg-paper-2'}`}>{fmtTime(r.ts)}</td>
                      <td data-label="Run" className={`whitespace-nowrap text-sm ${bad ? 'bg-bad-soft' : 'group-hover:bg-paper-2'}`}>
                        <div className="measured">{shortId(r.scenario_id, 22)}</div>
                        <div className="flex gap-x-2 text-muted">
                          <span>{r.mode}</span>
                          <span className="border-l border-rule-2 pl-2">step {r.step}</span>
                        </div>
                      </td>
                      <td data-label="Action" className={`w-full max-w-0 min-w-24 max-[60rem]:max-w-none ${bad ? 'bg-bad-soft' : 'group-hover:bg-paper-2'}`}>
                        <div className="measured font-medium">{r.tool}</div>
                        <div className="measured break-words text-sm text-muted" title={fmtArgs(r.args_masked)}>{brief(fmtArgs(recipientFirst(r.args_masked)))}</div>
                      </td>
                      <td data-label="Outcome" className={`whitespace-nowrap min-[75rem]:min-w-48 ${bad ? 'bg-bad-soft' : 'group-hover:bg-paper-2'}`}>
                        <div className="flex flex-wrap items-center gap-1">
                          <OutcomeChip verdict={r.verdict} status={r.status} />
                          <StatusChip status={r.status} />
                        </div>
                        {r.would_verdict && r.would_verdict !== r.verdict && <div className="mt-1"><WouldChip verdict={r.would_verdict} /></div>}
                      </td>
                      <td data-label="Rules and flags" className={`${bad ? 'bg-bad-soft' : 'group-hover:bg-paper-2'}`}>
                        <div className="measured max-w-[11rem] break-words text-xs leading-5 max-[60rem]:max-w-none min-[75rem]:max-w-[19rem]">{r.matched_rules.join(', ') || 'none'}</div>
                        <div className="mt-1 flex flex-wrap gap-1 empty:hidden">
                          {r.flags.map((f) => (
                            <FlagChip key={f} flag={f} />
                          ))}
                        </div>
                      </td>
                      <td data-label="State" className={`whitespace-nowrap text-sm ${bad ? 'bg-bad-soft' : 'group-hover:bg-paper-2'}`}>
                        <div>
                          taint: <span className="measured">{r.taint}</span>
                        </div>
                        <div className="flex gap-x-2">
                          <span>
                            strikes: <span className="measured">{r.strikes}</span>
                          </span>
                          <span className={`border-l border-rule-2 pl-2 ${r.latency_ms === null || r.latency_ms === undefined ? 'text-muted' : 'measured text-muted'}`}>{fmtMs(r.latency_ms)}</span>
                        </div>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={7} className="bg-paper-2 text-sm">
                          <div className="sticky left-0 flex w-[min(100cqw,64rem)] flex-col gap-2 py-1">
                            <p className="text-base font-medium">{r.explanation}</p>
                            {r.llm_explanation && <AiNote text={r.llm_explanation} />}
                            <p className="measured break-words text-muted">{fmtArgs(r.args_masked)}</p>
                            <div className="flex flex-wrap gap-x-5 gap-y-1 text-muted">
                              <span>Task: {r.task}</span>
                              <span>
                                session <span className="measured break-all">{r.session_id}</span>
                              </span>
                              <span>
                                action <span className="measured break-all">{r.action_id}</span>
                              </span>
                            </div>
                            {r.error && <p className="text-bad">Error: {r.error}</p>}
                            {r.result_masked && <pre className="measured overflow-x-auto rounded-pill bg-paper-3 p-3">{fmtJson(r.result_masked)}</pre>}
                            <p className="text-muted">
                              prev <span className="measured break-all text-xs">{r.prev_hash}</span>
                            </p>
                            <p className="text-muted">
                              hash <span className="measured break-all text-xs">{r.hash}</span>
                            </p>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
