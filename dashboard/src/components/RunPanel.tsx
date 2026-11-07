import { useEffect, useRef, useState } from 'react'
import type { GatewayMode } from '../types/contracts'
import { fmtArgs, MODE_LABEL, errMsg } from '../lib/rules'
import { selectAction, unfreeze, type OutboxState, type SessionView } from '../lib/store'
import { FlagChip, OutcomeChip, Pill, StatusChip, WouldChip } from './Chips'
import OutboxPanel from './OutboxPanel'
import { recipientFirst } from './recipientFirst'

interface Props {
  mode: GatewayMode
  sessionId: string
  session: SessionView | undefined
  outbox: OutboxState
  selectedActionId: string | null
  /** True when either column shows a session band, so both reserve its height and rows stay aligned. */
  reserveBand?: boolean
}

export default function RunPanel({ mode, sessionId, session, outbox, selectedActionId, reserveBand = false }: Props) {
  const prot = mode === 'protected'
  const rec = session?.record ?? null
  const last = session?.actions.at(-1)
  // Session updates and decision events can arrive in either order, and both only ever raise taint and strikes
  // (unfreeze clears the strikes on the stored actions), so show the higher of the two.
  const order = ['public', 'internal', 'confidential', 'restricted'] as const
  const taint = [rec?.taint, last?.taint].reduce<(typeof order)[number]>(
    (hi, t) => (t && order.indexOf(t) > order.indexOf(hi) ? t : hi),
    'public',
  )
  const strikes = Math.max(rec?.strikes ?? 0, last?.strikes ?? 0)
  const state = rec?.state ?? 'active'
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  // Follow the newest row, so a step past the fold is never decided off-screen.
  const newestRow = useRef<HTMLLIElement | null>(null)
  const rowCount = session?.actions.length ?? 0
  useEffect(() => {
    if (rowCount > 0) newestRow.current?.scrollIntoView({ block: 'nearest' })
  }, [rowCount])

  const doUnfreeze = async () => {
    setBusy(true)
    setErr(null)
    try {
      await unfreeze(sessionId)
    } catch (e) {
      setErr(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-w-0 flex-col" data-testid={`panel-${mode}`}>
      <div className="px-3 py-1.5">
        <div className="flex flex-col gap-1 min-[60rem]:flex-row min-[60rem]:items-center min-[60rem]:justify-between min-[60rem]:gap-3">
          <h2 className="whitespace-nowrap text-xl leading-tight max-[75rem]:text-lg">{MODE_LABEL[mode]}</h2>
          <div className="flex flex-wrap gap-1 min-[60rem]:flex-nowrap">
            <Pill tone={taint === 'confidential' || taint === 'restricted' ? 'hot' : 'plain'}><span>taint: <span className="measured text-xs">{taint}</span></span></Pill>
            <Pill tone={strikes > 0 ? 'hot' : 'plain'}><span>strikes: <span className="measured text-xs">{strikes}/3</span></span></Pill>
            <Pill tone={state === 'frozen' ? 'hot' : 'plain'}>{state.replace('_', ' ')}</Pill>
          </div>
        </div>
        <p className="truncate text-xs text-muted">{prot ? 'protected: every call is checked first' : 'passthrough: verdicts are logged, never enforced'}</p>
      </div>

      <div className={reserveBand ? 'min-h-[9.25rem] px-3 pb-2' : ''}>
      {state === 'frozen' && (
        <div role="alert" className="band band-person justify-between">
          <div>
            <div className="text-lg font-medium text-accent">Session frozen</div>
            <div className="text-sm">
              {prot
                ? 'Three strikes. Every action is blocked until a human unfreezes it.'
                : 'Three strikes were recorded. Passthrough enforces nothing, so actions still run.'}
            </div>
            {err && <div className="mt-1 text-sm font-medium text-bad">Unfreeze failed: {err}</div>}
          </div>
          <button type="button" className="btn btn-sm" disabled={busy} onClick={doUnfreeze}>
            {busy ? 'Unfreezing…' : 'Unfreeze'}
          </button>
        </div>
      )}
      {state === 'on_watch' && (
        <div className="band band-person text-sm font-medium">
          On watch (strike 2): every non-read action needs REVIEW.
        </div>
      )}
      </div>

      <OutboxPanel mode={mode} outbox={outbox} session={session} />

      <div>
        <h3 className="sr-only">Timeline</h3>
        {!session || session.actions.length === 0 ? (
          <p className="p-3 text-muted">Waiting for the first action…</p>
        ) : (
          <ol>
            {session.actions.map((a, index) => {
              const selected = a.action_id === selectedActionId
              const wouldDiffers = a.would_verdict && a.would_verdict !== a.verdict
              const tint = a.verdict === 'BLOCK' ? 'bg-bad-soft' : a.verdict === 'REVIEW' ? 'bg-accent-soft' : 'bg-paper-2'
              return (
                <li key={a.action_id} ref={index === session.actions.length - 1 ? newestRow : undefined} className="row-in scroll-mb-3 border-b border-rule">
                  <button
                    type="button"
                    onClick={() => selectAction({ session_id: sessionId, action_id: a.action_id })}
                    aria-pressed={selected}
                    title="Show decision detail"
                    className={`grid h-[3.75rem] w-full grid-cols-[1.5rem_minmax(0,1fr)] items-start gap-x-2 overflow-hidden px-3 py-1 text-left max-[60rem]:h-20 outline-offset-0 hover:outline hover:outline-1 hover:-outline-offset-1 hover:outline-rule-2 aria-pressed:outline aria-pressed:outline-1 aria-pressed:-outline-offset-1 aria-pressed:outline-ink-2 ${tint}`}
                  >
                    <span className="measured pt-0.5 text-muted">{a.step}</span>
                    <span className="flex min-w-0 flex-col gap-0.5">
                      <span className="flex items-center justify-between gap-2">
                        <span className="measured truncate font-medium">{a.tool ?? 'unknown tool'}</span>
                        <span className="flex shrink-0 items-center gap-1">
                          <OutcomeChip verdict={a.verdict} status={a.status} />
                          <StatusChip status={a.status} />
                        </span>
                      </span>
                      <span className="flex items-center justify-between gap-2 max-[60rem]:flex-wrap">
                        <span className="measured min-w-0 truncate text-sm leading-snug text-muted">{fmtArgs(recipientFirst(a.args))}</span>
                        {(a.flags.length > 0 || wouldDiffers) && (
                          <span className="flex shrink-0 items-center gap-1 max-[60rem]:flex-wrap">
                            {a.flags.map((f) => (
                              <FlagChip key={f} flag={f} />
                            ))}
                            {wouldDiffers && a.would_verdict && <WouldChip verdict={a.would_verdict} />}
                          </span>
                        )}
                      </span>
                    </span>
                  </button>
                </li>
              )
            })}
          </ol>
        )}
      </div>
    </div>
  )
}
