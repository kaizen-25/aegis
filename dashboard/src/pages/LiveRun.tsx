import { useEffect, useMemo, useState } from 'react'
import type { AgentKind, GatewayMode } from '../types/contracts'
import { REPLAY } from '../lib/config'
import { errMsg } from '../lib/rules'
import { chooseScenario, loadScenarios, replayScripted, resetSandbox, setUi, startRun, useApp, type AppState } from '../lib/store'
import { Pill } from '../components/Chips'
import DetailDrawer from '../components/DetailDrawer'
import RunPanel from '../components/RunPanel'

function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: T
  options: { value: T; text: string; disabled?: boolean; title?: string }[]
  onChange: (v: T) => void
}) {
  return (
    <div role="radiogroup" aria-label={label} className="seg">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          disabled={o.disabled}
          title={o.title}
          onClick={() => onChange(o.value)}
        >
          {o.text}
        </button>
      ))}
    </div>
  )
}

const STALL_SECONDS = 10

/** Says which agent produced this run, and offers the scripted fallback while a live LLM run is going. */
function RunBanner({ app }: { app: AppState }) {
  const run = app.run
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])
  if (!run) return null

  const finished = run.sessions.every((s) => app.sessions[s.session_id]?.record?.state === 'completed')
  const live = run.agentKind === 'llm'
  const silentFor = Math.max(0, Math.floor((now - (app.lastEventAt ?? run.startedAt)) / 1000))
  const stalled = live && !finished && silentFor >= STALL_SECONDS
  const waitingOnHuman = app.tickets.some((t) => (t.state ?? 'pending') === 'pending' && run.sessions.some((s) => s.session_id === t.session_id))

  if (run.scriptedReplay) {
    return (
      <div role="status" className="band band-system">
        <b className="font-medium text-cool">SCRIPTED REPLAY</b>
        <span>This run is the scripted agent, started after a live LLM run. It is not the live model.</span>
      </div>
    )
  }
  if (!live) {
    return (
      <div className="flex flex-wrap items-center gap-2 text-sm text-muted">
        <Pill>Scripted agent</Pill> {finished ? 'Run finished.' : null}
      </div>
    )
  }
  return (
    <div role="status" className={`band ${stalled ? 'band-person' : 'band-system'}`}>
      <b className="text-lg font-medium text-cool">Live LLM run</b>
      <span className="text-sm text-ink-2">{app.health.data?.model ?? 'local model'}, running offline on this laptop.</span>
      {finished ? (
        <span className="font-medium">Run finished.</span>
      ) : (
        <>
          <span className={stalled ? 'num font-medium text-accent' : 'num text-sm text-ink-2'} aria-live="polite">
            {stalled ? `No new event for ${silentFor} s.` : `Last event ${silentFor} s ago.`}
            {waitingOnHuman ? ' Waiting on a review ticket.' : ''}
          </span>
          <button
            type="button"
            className={stalled ? 'btn ml-auto min-h-12 border-ink px-6 text-lg' : 'btn btn-sm ml-auto'}
            disabled={app.runStarting}
            onClick={() => void replayScripted()}
          >
            {app.runStarting ? 'Replaying…' : 'Replay scripted'}
          </button>
        </>
      )}
    </div>
  )
}

export default function LiveRun() {
  const app = useApp()
  const { scenarios, ui, run, sessions, outbox, health } = app
  const [resetting, setResetting] = useState(false)

  useEffect(() => {
    if (scenarios.status === 'error' && health.status === 'ok') void loadScenarios()
  }, [scenarios.status, health.status])

  const scenario = scenarios.items.find((s) => s.id === ui.scenarioId) ?? null
  // While a run is on screen its task line describes that run, even if the dropdown has moved on.
  const shownScenario = (run && scenarios.items.find((s) => s.id === run.scenario_id)) || scenario
  const ollama = health.data?.ollama_available === true
  const liveAllowed = !REPLAY && ollama && scenario?.has_llm_prompt === true

  // If Live was chosen and then becomes unavailable, fall back to scripted.
  useEffect(() => {
    if (ui.agentKind === 'llm' && !liveAllowed) setUi({ agentKind: 'scripted' })
  }, [ui.agentKind, liveAllowed])

  const selected = ui.selected
  const detail = useMemo(() => {
    if (!selected) return null
    const session = sessions[selected.session_id]
    const action = session?.actions.find((a) => a.action_id === selected.action_id)
    return session && action ? { session, action } : null
  }, [selected, sessions])

  const modes: GatewayMode[] = run ? (['passthrough', 'protected'] as const).filter((m) => run.sessions.some((s) => s.mode === m)) : []
  const gatewayDown = !REPLAY && health.status === 'down'
  // During a run the ledger needs the height: the field labels stay for screen readers.
  const labelClass = run ? 'sr-only' : 'eyebrow'
  const taskLine = shownScenario && (
    <p className={`min-w-0 text-muted ${run ? 'text-sm' : 'basis-full'}`}>
      <span className="font-medium text-ink-2">Task:</span> {shownScenario.task}
      <span className="ml-3 border-l border-rule-2 pl-3">{shownScenario.category}</span>
    </p>
  )

  const onReset = async () => {
    setResetting(true)
    await resetSandbox()
    setResetting(false)
  }

  return (
    <div className={`flex flex-col ${run ? 'gap-1.5' : 'gap-4'}`}>
      <section className={`card flex flex-wrap items-end gap-x-4 ${run ? 'gap-y-1.5 px-3 py-1.5' : 'gap-y-3 p-4'}`} aria-label="Run controls">
        <label className="flex min-w-[16rem] flex-1 flex-col gap-1">
          <span className={labelClass}>Scenario</span>
          <select
            className="field"
            value={ui.scenarioId ?? ''}
            disabled={scenarios.items.length === 0}
            onChange={(e) => chooseScenario(e.target.value)}
          >
            {scenarios.items.length === 0 && <option value="">{scenarios.status === 'loading' ? 'Loading scenarios…' : 'No scenarios'}</option>}
            {scenarios.items.map((s) => (
              <option key={s.id} value={s.id}>
                {s.short_id}: {s.title}
              </option>
            ))}
          </select>
        </label>
        <div className="flex flex-col gap-1">
          <span className={labelClass}>View</span>
          <Segmented
            label="Single or split view"
            value={ui.split ? 'split' : 'single'}
            onChange={(v) => setUi({ split: v === 'split' })}
            options={[
              { value: 'single', text: 'Single' },
              { value: 'split', text: 'Split' },
            ]}
          />
        </div>
        <div className="flex flex-col gap-1">
          <span className={labelClass}>Agent</span>
          <Segmented<AgentKind>
            label="Scripted or live agent"
            value={ui.agentKind}
            onChange={(v) => setUi({ agentKind: v })}
            options={[
              { value: 'scripted', text: 'Scripted' },
              {
                value: 'llm',
                text: 'Live LLM',
                disabled: !liveAllowed,
                title: liveAllowed ? undefined : 'Needs Ollama running and a scenario with an LLM prompt',
              },
            ]}
          />
        </div>
        <div className="flex gap-2">
          <button type="button" className="btn btn-primary" disabled={!ui.scenarioId || app.runStarting || gatewayDown} onClick={() => void startRun()}>
            {app.runStarting ? 'Starting…' : 'Run'}
          </button>
          <button type="button" className="btn" disabled={resetting || gatewayDown} onClick={onReset}>
            {resetting ? 'Resetting…' : 'Reset'}
          </button>
        </div>
        {scenario && !run && taskLine}
      </section>

      {app.runError && (
        <div role="alert" className="band band-bad font-medium text-bad">
          {errMsg(app.runError)}
        </div>
      )}
      {scenarios.status === 'error' && !REPLAY && (
        <div role="alert" className="band band-system">
          Could not load scenarios: {scenarios.error}
        </div>
      )}

      {run && (
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
          {taskLine}
          <RunBanner app={app} />
        </div>
      )}

      {!run ? (
        <section className="flex flex-col gap-4 py-4" aria-label="How a verdict is reached">
          <h2 className="max-w-[24ch] text-3xl">The agent can only ask. Only the gateway can act.</h2>
          <p className="max-w-[60ch] text-lg text-ink-2">
            Pick a scenario and press Run. In Split view the same agent and the same attack run twice: without Aegis on the left, with it on the right.
          </p>
          <div className="panels md:grid-cols-3">
            <div className="bg-ok-soft p-4">
              <b className="font-medium text-ok">{'\u2713'} ALLOW</b>
              <p className="mt-1 text-ink-2">A rule permits it and it fits the task. The tool runs.</p>
            </div>
            <div className="bg-accent-soft p-4">
              <b className="font-medium text-accent">! REVIEW</b>
              <p className="mt-1 text-ink-2">Aegis cannot be sure. A human decides.</p>
            </div>
            <div className="bg-bad-soft p-4">
              <b className="font-medium text-bad">{'\u2715'} BLOCK</b>
              <p className="mt-1 text-ink-2">A rule forbids it. The tool is never called.</p>
            </div>
          </div>
        </section>
      ) : (
        <div className={`panels ${modes.length > 1 ? 'min-[40rem]:grid-cols-2' : 'max-w-3xl'}`}>
          {modes.map((m) => {
            const rs = run.sessions.find((s) => s.mode === m)
            if (!rs) return null
            return (
              <RunPanel
                key={rs.session_id}
                mode={m}
                sessionId={rs.session_id}
                session={sessions[rs.session_id]}
                outbox={outbox[m]}
                selectedActionId={selected?.session_id === rs.session_id ? selected.action_id : null}
                reserveBand={run.sessions.some((s) => ['frozen', 'on_watch'].includes(sessions[s.session_id]?.record?.state ?? ''))}
              />
            )
          })}
        </div>
      )}

      {detail && <DetailDrawer key={detail.action.action_id} action={detail.action} session={detail.session} policy={app.policy} />}
    </div>
  )
}
