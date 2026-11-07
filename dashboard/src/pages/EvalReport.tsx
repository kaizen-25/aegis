import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Cell, Legend, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { EvalMetrics, EvalReport as Report, GatewayMode, Ratio, ScenarioResult } from '../types/contracts'
import { api } from '../lib/api'
import { ApiError } from '../lib/errors'
import { REPLAY } from '../lib/config'
import { errMsg, fmtDateTime, fmtMs } from '../lib/rules'
import { useApp } from '../lib/store'
import { FlagChip, Pill, VerdictChip } from '../components/Chips'

const NOT_MEASURED = 'Not measured'

/** value is read as a 0..1 fraction; the n of d line is always shown beside it. */
function pct(r: Ratio | null | undefined): number | null {
  if (!r || r.value === null || r.value === undefined) return null
  return r.value <= 1 ? r.value * 100 : r.value
}
function fmtPct(r: Ratio | null | undefined): string {
  const p = pct(r)
  return p === null ? NOT_MEASURED : `${Number(p.toFixed(1))}%`
}
function fmtCount(r: Ratio | null | undefined): string {
  return r ? `${r.numerator} of ${r.denominator}` : ''
}

interface CardSpec {
  key: string
  label: string
  hint: string
  pick: (m: EvalMetrics) => Ratio
}
const RATIO_CARDS: CardSpec[] = [
  { key: 'attack_success_rate', label: 'Attack success rate', hint: 'Attack scenarios where a violating action ran without human approval. Lower is better.', pick: (m) => m.attack_success_rate },
  { key: 'detection_precision', label: 'Detection precision', hint: 'Of actions stopped, the share that really were violations', pick: (m) => m.detection_precision },
  { key: 'detection_recall', label: 'Detection recall', hint: 'Of violating actions, the share that were stopped', pick: (m) => m.detection_recall },
  { key: 'false_block_rate', label: 'False-block rate', hint: 'Of legitimate actions, the share blocked or sent to review. Lower is better.', pick: (m) => m.false_block_rate },
  { key: 'legitimate_task_completion', label: 'Legitimate task completion', hint: 'Benign scenarios that finished with every step executed', pick: (m) => m.legitimate_task_completion },
  { key: 'execution_integrity', label: 'Execution integrity', hint: 'Blocked actions whose handler never ran', pick: (m) => m.execution_integrity },
]

function RatioCell({ r }: { r: Ratio | null }) {
  if (!r) return <span className="text-muted">{NOT_MEASURED}</span>
  return (
    <>
      <span className={`measured text-lg ${fmtPct(r) === NOT_MEASURED ? 'text-muted' : ''}`}>{fmtPct(r)}</span>
      <span className="measured ml-2 text-sm text-muted">{fmtCount(r)}</span>
    </>
  )
}

function MetricRow({ spec, prot, unprot }: { spec: CardSpec; prot: EvalMetrics | undefined; unprot: EvalMetrics | undefined }) {
  const p = prot ? spec.pick(prot) : null
  const u = unprot ? spec.pick(unprot) : null
  return (
    <tr>
      <th scope="row" className="whitespace-nowrap text-left font-medium">
        {spec.label}
      </th>
      <td data-label="Protected" className="whitespace-nowrap">
        <RatioCell r={p} />
      </td>
      <td data-label="Unprotected" className="whitespace-nowrap">
        <RatioCell r={u} />
      </td>
      <td data-label="What it means" className="min-w-64 text-sm text-muted max-[60rem]:min-w-0">{spec.hint}</td>
    </tr>
  )
}

function LatencyRow({ label, p, u }: { label: string; p: number | null | undefined; u: number | null | undefined }) {
  return (
    <tr>
      <th scope="row" className="whitespace-nowrap text-left font-medium">
        Enforcement latency <span className="font-normal text-muted">{label}</span>
      </th>
      <td data-label="Protected" className={`measured whitespace-nowrap text-lg ${p == null ? 'text-muted' : ''}`}>{fmtMs(p)}</td>
      <td data-label="Unprotected" className={`measured whitespace-nowrap text-lg ${u == null ? 'text-muted' : ''}`}>{fmtMs(u)}</td>
      <td data-label="What it means" className="min-w-64 text-sm text-muted max-[60rem]:min-w-0">Gateway time per action, excluding the tool.</td>
    </tr>
  )
}

const ATTACK_CATEGORIES = ['injection', 'exfiltration', 'destructive', 'circumvention', 'known_miss'] as const

function categoryData(scenarios: ScenarioResult[]) {
  return ATTACK_CATEGORIES.map((c) => {
    const row: Record<string, string | number | null> = { name: c.replace('_', ' ') }
    for (const mode of ['passthrough', 'protected'] as GatewayMode[]) {
      const rs = scenarios.filter((s) => s.category === c && s.mode === mode && s.attack_succeeded !== null && s.attack_succeeded !== undefined)
      row[mode] = rs.length ? Math.round((rs.filter((s) => s.attack_succeeded).length / rs.length) * 100) : null
      row[`${mode}_n`] = rs.length
    }
    return row
  }).filter((r) => (r.passthrough_n as number) > 0 || (r.protected_n as number) > 0)
}

const AXIS = { fill: 'var(--color-muted)', fontSize: 13 }
const TIP = {
  background: 'var(--color-paper-2)',
  border: '1px solid var(--color-rule-2)',
  borderRadius: 'var(--radius-pill)',
  color: 'var(--color-ink)',
}

function outcomeText(r: ScenarioResult | undefined): { text: string; tone: string } {
  if (!r) return { text: NOT_MEASURED, tone: 'text-muted' }
  if (r.attack_succeeded === true) return { text: 'Attack succeeded', tone: 'text-bad font-medium' }
  if (r.attack_succeeded === false) return { text: 'Attack stopped', tone: 'text-ok font-medium' }
  return { text: 'No attack', tone: 'text-muted' }
}

export default function EvalReport() {
  const app = useApp()
  const [report, setReport] = useState<Report | null>(null)
  const [phase, setPhase] = useState<'loading' | 'none' | 'ready' | 'error'>('loading')
  const [error, setError] = useState<string | null>(null)
  const [running, setRunning] = useState(false)
  const [withLlm, setWithLlm] = useState(false)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const abort = useRef<AbortController | null>(null)

  const poll = useCallback(async (id: string) => {
    abort.current?.abort()
    const ac = new AbortController()
    abort.current = ac
    const deadline = Date.now() + 15 * 60_000
    setRunning(true)
    try {
      for (;;) {
        const r = await api.evalReport(id, ac.signal)
        setReport(r)
        setPhase('ready')
        if (r.status !== 'running') break
        if (Date.now() > deadline) throw new Error('Gave up waiting for the report after 15 minutes')
        await new Promise((res) => setTimeout(res, 1500))
        if (ac.signal.aborted) return
      }
      setError(null)
    } catch (e) {
      if (ac.signal.aborted) return
      setError(errMsg(e))
      setPhase((p) => (p === 'ready' ? p : 'error'))
    } finally {
      if (!ac.signal.aborted) setRunning(false)
    }
  }, [])

  useEffect(() => {
    if (REPLAY) return
    const ac = new AbortController()
    api
      .evalReport('latest', ac.signal)
      .then((r) => {
        setReport(r)
        setPhase('ready')
      })
      .catch((e) => {
        if (ac.signal.aborted) return
        if (e instanceof ApiError && e.status === 404) setPhase('none')
        else {
          setPhase('error')
          setError(errMsg(e))
        }
      })
    return () => {
      ac.abort()
      abort.current?.abort()
    }
  }, [poll])

  const [openId, setOpenId] = useState('')
  const openById = async () => {
    const id = openId.trim()
    if (!id) return
    setError(null)
    try {
      const r = await api.evalReport(id)
      setReport(r)
      setPhase('ready')
    } catch (e) {
      setError(e instanceof ApiError && e.status === 404 ? `No report with id "${id}".` : errMsg(e))
    }
  }

  const start = async () => {
    setError(null)
    setRunning(true)
    try {
      const { report_id } = await api.startEval(withLlm)
      await poll(report_id)
    } catch (e) {
      setError(errMsg(e))
      setRunning(false)
    }
  }

  const prot = report?.metrics?.find((m) => m.mode === 'protected')
  const unprot = report?.metrics?.find((m) => m.mode === 'passthrough')
  const scenarios = useMemo(() => report?.scenarios ?? [], [report])
  const catData = useMemo(() => categoryData(scenarios), [scenarios])
  const headline = [
    { name: 'Unprotected', value: pct(unprot?.attack_success_rate) },
    { name: 'Protected', value: pct(prot?.attack_success_rate) },
  ].filter((d) => d.value !== null)

  const byScenario = useMemo(() => {
    const m = new Map<string, { id: string; title: string; category: string; pt?: ScenarioResult; pr?: ScenarioResult }>()
    for (const s of scenarios) {
      const e = m.get(s.scenario_id) ?? { id: s.scenario_id, title: s.title, category: s.category }
      if (s.mode === 'protected') e.pr = s
      else e.pt = s
      m.set(s.scenario_id, e)
    }
    return [...m.values()]
  }, [scenarios])

  if (REPLAY) {
    return (
      <div className="flex max-w-3xl flex-col gap-3">
        <h1 className="text-3xl">Evaluation Report</h1>
        <div className="card p-6 text-muted">The evaluation report is not available in recorded replay. Open the dashboard without ?replay=1 once the gateway is up.</div>
      </div>
    )
  }

  const progress = app.evalProgress
  const progressText = progress
    ? Object.entries(progress)
        .filter(([, v]) => typeof v === 'number' || typeof v === 'string')
        .map(([k, v]) => `${k}: ${v}`)
        .join(', ')
    : ''
  // Only a run started from this page is polled. The gateway also answers 200 "running" for an id it has never seen.
  const live = running
  const idleRunning = !running && report?.status === 'running'
  const lead = RATIO_CARDS[0]
  const leadP = prot ? lead.pick(prot) : null
  const leadU = unprot ? lead.pick(unprot) : null
  const count = (r: Ratio | null) => (r && r.value !== null && r.value !== undefined ? fmtCount(r) : NOT_MEASURED)

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
        <div className="flex flex-col">
          <h1 className="text-3xl leading-tight">Evaluation Report</h1>
          <p className="text-sm text-muted">Every scenario runs unprotected and protected against an answer key written before any run.</p>
        </div>
        <div className="flex flex-wrap items-end gap-x-4 gap-y-3">
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              void openById()
            }}
          >
            <label className="sr-only" htmlFor="report-id">
              Report id
            </label>
            <input id="report-id" className="field measured w-40 text-sm" placeholder="report id" value={openId} onChange={(e) => setOpenId(e.target.value)} />
            <button type="submit" className="btn" disabled={!openId.trim()}>
              Open
            </button>
          </form>
          <label className="flex min-h-11 items-center gap-2 text-sm text-ink-2">
            <input
              type="checkbox"
              className="size-5 accent-cool"
              checked={withLlm}
              disabled={running || app.health.data?.ollama_available !== true}
              onChange={(e) => setWithLlm(e.target.checked)}
            />
            Also run rules + LLM (may vary slightly)
          </label>
          <button type="button" className="btn btn-primary" disabled={running || app.health.status !== 'ok'} onClick={() => void start()}>
            {running ? 'Running…' : 'Run evaluation'}
          </button>
        </div>
      </header>

      {error && (
        <div role="alert" className="band band-bad font-medium text-bad">
          {error}
        </div>
      )}
      {live && (
        <div role="status" className="band band-system">
          Evaluation running… <span className="measured">{progressText}</span>
        </div>
      )}
      {phase === 'loading' && <div className="card p-6 text-muted">Loading the latest report…</div>}
      {phase === 'none' && !live && (
        <div className="card flex flex-col gap-1 p-6">
          <p className="text-xl font-medium">No evaluation report yet.</p>
          <p className="text-muted">Press Run evaluation. Nothing is shown here until a report exists.</p>
        </div>
      )}

      {idleRunning && report && (
        <div role="status" className="band band-system">
          <span>
            Report <b className="measured font-medium">{report.report_id}</b> is marked as running, or the gateway has no report with that id. Nothing is shown until it completes. Open it again to refresh.
          </span>
        </div>
      )}
      {report && phase === 'ready' && report.status === 'failed' && (
        <div role="alert" className="band band-bad font-medium text-bad">
          This evaluation failed{report.error ? `: ${report.error}` : '.'}
        </div>
      )}

      {report && report.status !== 'failed' && (report.metrics?.length || scenarios.length > 0) ? (
        <>
          {report.with_llm ? (
            <div role="note" className="band band-system">
              <span>
                <b className="text-lg font-medium text-cool">Rules + LLM report: may vary slightly.</b>{' '}
                The local model took part in these decisions, so these numbers can change between runs. The rules-only report is the reproducible one.
              </span>
            </div>
          ) : (
            <p role="note" className="text-sm text-ink-2">
              <b className="font-medium">Rules only.</b> No model took part in this report.
            </p>
          )}
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
            <p role="note" className="mr-2 text-ink-2">
              Results describe this test suite only. They are not a general security guarantee.
            </p>
            <Pill>
              report <span className="measured ml-1">{report.report_id}</span>
            </Pill>
            <Pill>{report.status}</Pill>
            <Pill tone={report.with_llm ? 'hot' : 'plain'}>{report.with_llm ? 'rules + LLM (may vary slightly)' : 'rules only'}</Pill>
            {report.generated_at && (
              <Pill>
                generated <span className="measured ml-1">{fmtDateTime(report.generated_at)}</span>
              </Pill>
            )}
          </div>

          {prot && (
            <section aria-label="Attack success rate" className="flex flex-col gap-1 border-y border-rule py-3">
              <h2 className="eyebrow">{lead.label}</h2>
              <div className="flex flex-wrap items-baseline gap-x-3 text-muted">
                <span>Unprotected</span>
                <s className="measured text-lg">{count(leadU)}</s>
              </div>
              <div className="flex flex-wrap items-baseline gap-x-5">
                <span className="reading">{count(leadP)}</span>
                <span className={`measured text-2xl ${fmtPct(leadP) === NOT_MEASURED ? 'text-muted' : 'text-ink-2'}`}>{fmtPct(leadP)}</span>
                <span className="text-muted">Protected</span>
              </div>
              <p className="text-sm text-muted">{lead.hint}</p>
            </section>
          )}

          <section aria-label="Metrics" className="mt-3 min-w-0">
            <div className="overflow-x-auto">
              <table className="tbl tbl-stack">
                <caption className="sr-only">Metrics, protected and unprotected</caption>
                <thead>
                  <tr>
                    <th scope="col">Metric</th>
                    <th scope="col">Protected</th>
                    <th scope="col">Unprotected</th>
                    <th scope="col">What it means</th>
                  </tr>
                </thead>
                <tbody>
                  {RATIO_CARDS.slice(1).map((c) => (
                    <MetricRow key={c.key} spec={c} prot={prot} unprot={unprot} />
                  ))}
                  <LatencyRow label="p50" p={prot?.latency_p50_ms} u={unprot?.latency_p50_ms} />
                  <LatencyRow label="p95" p={prot?.latency_p95_ms} u={unprot?.latency_p95_ms} />
                </tbody>
              </table>
            </div>
          </section>

          <section aria-label="Protected versus unprotected" className="panels mt-5 min-w-0 md:grid-cols-2">
            <div className="min-w-0 p-4">
              <h2 className="mb-2">Attack success rate</h2>
              {headline.length === 0 ? (
                <p className="text-muted">{NOT_MEASURED}</p>
              ) : (
                <div role="img" aria-label={`Attack success rate: ${headline.map((h) => `${h.name} ${h.value}%`).join(', ')}`} className="h-80 w-full min-w-0">
                  <ResponsiveContainer>
                    <BarChart data={headline} margin={{ top: 20, right: 10, left: 0, bottom: 0 }}>
                      <CartesianGrid stroke="var(--color-rule)" vertical={false} />
                      <XAxis dataKey="name" tick={AXIS} stroke="var(--color-rule-2)" />
                      <YAxis domain={[0, 100]} unit="%" tick={AXIS} stroke="var(--color-rule-2)" />
                      <Tooltip contentStyle={TIP} cursor={{ fill: 'var(--color-paper-3)' }} formatter={(v) => [`${Number(v)}%`, 'Attack success']} />
                      <Bar dataKey="value" maxBarSize={36} isAnimationActive={false}>
                        {headline.map((h) => (
                          <Cell key={h.name} fill={h.name === 'Protected' ? 'var(--color-cool)' : 'var(--color-bad)'} />
                        ))}
                        <LabelList dataKey="value" position="top" fill="var(--color-ink)" formatter={(v) => `${Number(Number(v).toFixed(1))}%`} />
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
            <div className="min-w-0 p-4">
              <h2 className="mb-1">Attacks that succeeded, by category</h2>
              <p className="mb-2 text-xs text-muted">Computed from the per-scenario rows below.</p>
              {catData.length === 0 ? (
                <p className="mt-2 text-muted">{NOT_MEASURED}</p>
              ) : (
                <div role="img" aria-label="Share of attack scenarios that succeeded, by category, unprotected versus protected" className="h-80 w-full min-w-0">
                  <ResponsiveContainer>
                    <BarChart data={catData} layout="vertical" margin={{ top: 4, right: 48, left: 0, bottom: 0 }} barGap={2} barCategoryGap="22%">
                      <CartesianGrid stroke="var(--color-rule)" horizontal={false} />
                      <XAxis type="number" domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} interval={0} unit="%" tick={AXIS} stroke="var(--color-rule-2)" />
                      <YAxis type="category" dataKey="name" interval={0} width={96} tick={AXIS} stroke="var(--color-rule-2)" />
                      <Tooltip contentStyle={TIP} cursor={{ fill: 'var(--color-paper-3)' }} formatter={(v) => `${Number(v)}%`} />
                      <Legend wrapperStyle={{ color: 'var(--color-ink-2)' }} />
                      <Bar dataKey="passthrough" name="Unprotected" fill="var(--color-bad)" minPointSize={3} isAnimationActive={false}>
                        <LabelList dataKey="passthrough" position="right" fontSize={12} fill="var(--color-ink)" formatter={(v) => (v === null || v === undefined ? '' : `${Number(v)}%`)} />
                      </Bar>
                      <Bar dataKey="protected" name="Protected" fill="var(--color-cool)" minPointSize={3} isAnimationActive={false}>
                        <LabelList dataKey="protected" position="right" fontSize={12} fill="var(--color-ink)" formatter={(v) => (v === null || v === undefined ? '' : `${Number(v)}%`)} />
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </section>

          <section aria-label="Per-scenario results" className="mt-5 flex min-w-0 flex-col gap-2">
            <h2>Per-scenario results</h2>
            {byScenario.length === 0 ? (
              <p className="text-muted">The report has no per-scenario rows.</p>
            ) : (
              <div className="@container overflow-x-auto">
                <table className="tbl tbl-stack">
                  <thead>
                    <tr>
                      {['Scenario', 'Category', 'Unprotected', 'Protected', 'Detail'].map((h, n) => (
                        <th key={h} scope="col" className={n === 0 ? 'sticky left-0 z-(--z-raised) bg-paper' : ''}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {byScenario.map((s) => {
                      const o1 = outcomeText(s.pt)
                      const o2 = outcomeText(s.pr)
                      const isOpen = expanded.has(s.id)
                      return (
                        <Fragment key={s.id}>
                          <tr className="align-top">
                            <td className="sticky left-0 z-(--z-raised) min-w-44 bg-paper max-[60rem]:static">
                              <div className="measured font-medium">{s.id}</div>
                              <div className="text-sm text-muted">{s.title}</div>
                            </td>
                            <td data-label="Category" className="whitespace-nowrap text-sm">{s.category.replace('_', ' ')}</td>
                            {[
                              [s.pt, o1],
                              [s.pr, o2],
                            ].map(([r, o], i) => (
                              <td key={i} data-label={i === 0 ? 'Unprotected' : 'Protected'} className="whitespace-nowrap text-sm">
                                <div className={(o as typeof o1).tone}>{(o as typeof o1).text}</div>
                                {r && (
                                  <div className={(r as ScenarioResult).passed ? 'text-ok' : 'font-medium text-bad'}>
                                    {(r as ScenarioResult).passed ? '✓ check passed' : '✕ check failed'}
                                  </div>
                                )}
                              </td>
                            ))}
                            <td data-label="Detail">
                              <button
                                type="button"
                                className="btn btn-sm"
                                aria-expanded={isOpen}
                                onClick={() =>
                                  setExpanded((e) => {
                                    const n = new Set(e)
                                    if (n.has(s.id)) n.delete(s.id)
                                    else n.add(s.id)
                                    return n
                                  })
                                }
                              >
                                {isOpen ? 'Hide steps' : 'Show steps'}
                              </button>
                            </td>
                          </tr>
                          {isOpen && (
                            <tr>
                              <td colSpan={5} className="bg-paper-2">
                                <div className="sticky left-0 w-[min(100cqw,64rem)]">
                                  {([s.pt, s.pr] as (ScenarioResult | undefined)[]).filter((x): x is ScenarioResult => !!x).map((r) => (
                                    <div key={r.mode} className="mb-4">
                                      <div className="font-medium">
                                        {r.mode === 'protected' ? 'Protected' : 'Unprotected'}
                                        {r.detail ? <span className="font-normal text-muted">: {r.detail}</span> : null}
                                      </div>
                                      <div className="overflow-x-auto">
                                        <table className="tbl mt-1 text-sm">
                                          <thead>
                                            <tr>
                                              <th scope="col">Step</th>
                                              <th scope="col">Tool</th>
                                              <th scope="col">Expected</th>
                                              <th scope="col">Actual</th>
                                              <th scope="col">Rules and flags</th>
                                              <th scope="col">Check</th>
                                            </tr>
                                          </thead>
                                          <tbody>
                                            {r.steps.map((st) => (
                                              <tr key={st.step}>
                                                <td className="measured">{st.step}</td>
                                                <td className="measured">{st.tool}</td>
                                                <td>
                                                  <VerdictChip verdict={st.expected} />
                                                </td>
                                                <td>
                                                  <VerdictChip verdict={st.actual} /> <span className="text-xs text-muted">{st.status}</span>
                                                </td>
                                                <td>
                                                  <span className="measured text-xs">{(st.matched_rules ?? []).join(', ')}</span>
                                                  <span className="ml-1 inline-flex flex-wrap gap-1">
                                                    {(st.flags ?? []).map((f) => (
                                                      <FlagChip key={f} flag={f} />
                                                    ))}
                                                  </span>
                                                </td>
                                                <td className={`font-medium ${st.passed ? 'text-ok' : 'text-bad'}`}>{st.passed ? '✓' : '✕'}</td>
                                              </tr>
                                            ))}
                                          </tbody>
                                        </table>
                                      </div>
                                    </div>
                                  ))}
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
          </section>

          <section aria-label="Checks" className="mt-5 flex flex-col gap-2">
            <h2>Checks</h2>
            {report.checks && Object.keys(report.checks).length > 0 ? (
              <ul className="grid gap-x-8 sm:grid-cols-2">
                {Object.entries(report.checks).map(([k, ok]) => (
                  <li key={k} className="flex flex-wrap items-baseline gap-x-3 border-b border-rule py-2">
                    <span className={`font-medium ${ok ? 'text-ok' : 'text-bad'}`}>{ok ? '✓ pass' : '✕ fail'}</span>
                    <span className="measured break-all text-sm">{k}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-muted">The report has no checks.</p>
            )}
          </section>

          <section aria-label="Known misses" className="mt-5 flex flex-col gap-2">
            <h2>Known misses</h2>
            <p className="text-sm text-muted">Leaks Aegis is known not to catch today. They count against recall.</p>
            {!report.known_misses || report.known_misses.length === 0 ? (
              <p className="text-muted">The report lists no known misses.</p>
            ) : (
              <ul className="border-y border-rule">
                {report.known_misses.map((k) => (
                  <li key={k.scenario_id} className="border-b border-rule bg-bad-soft p-4 last:border-b-0">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="measured font-medium">{k.scenario_id}</span>
                      <span className="font-medium">{k.title}</span>
                      <span className={`rounded-[4px] border px-2 py-0.5 text-xs font-medium ${k.leaked ? 'border-bad bg-bad-soft text-bad' : 'border-rule-2 bg-ok-soft text-ok'}`}>
                        {k.leaked ? 'LEAKED' : 'did not leak'}
                      </span>
                    </div>
                    <p className="mt-1">
                      <span className="font-medium">Why:</span> {k.why}
                    </p>
                    <p>
                      <span className="font-medium">Future fix:</span> {k.future_fix}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      ) : null}
    </div>
  )
}
