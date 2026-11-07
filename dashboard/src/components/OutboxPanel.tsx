import type { GatewayMode } from '../types/contracts'
import type { OutboxState, SessionView } from '../lib/store'
import { fmtTime } from '../lib/rules'

const isInternal = (to: string) => to.trim().toLowerCase().endsWith('@novacorp.local')

/** Live outbox for one mode. An empty outbox is stated plainly; a failed fetch is never shown as empty. */
export default function OutboxPanel({ mode, outbox, session }: { mode: GatewayMode; outbox: OutboxState; session: SessionView | undefined }) {
  const sends = session?.actions.filter((a) => a.tool === 'email.send') ?? []
  const executed = sends.some((a) => a.status === 'EXECUTED')
  const stopped = sends.some((a) => a.status === 'BLOCKED' || a.status === 'REJECTED' || a.status === 'FAIL_CLOSED')
  const waiting = sends.some((a) => a.status === 'PENDING' || a.status === 'PARKED')

  const mine = outbox.items.filter((m) => m.session_id === session?.session_id)
  const earlier = outbox.items.filter((m) => m.session_id !== session?.session_id)
  const leaked = mine.some((m) => !isInternal(m.to))

  let tone = 'bg-paper-2'
  if (leaked) tone = 'bg-bad-soft'
  else if (mine.length === 0 && outbox.status === 'ok' && stopped && !executed) tone = 'bg-ok-soft'

  return (
    <section className={`min-h-24 border-y border-rule px-3 py-2 ${tone}`} aria-label={`Outbox, ${mode}`} aria-live="polite">
      <h3 className="eyebrow">Outbox ({mode})</h3>
      {outbox.status === 'error' && (
        <p className="mt-1 font-medium text-cool">Could not load outbox: {outbox.error}</p>
      )}
      {outbox.status === 'idle' && <p className="mt-1 text-muted">Loading…</p>}
      {outbox.status !== 'idle' && mine.length === 0 && outbox.status === 'ok' && (
        <p
          className={`mt-1 font-display text-2xl font-medium leading-tight ${stopped && !executed ? 'text-ok' : waiting ? 'text-accent' : 'text-muted'}`}
        >
          {stopped && !executed
            ? 'Empty. email.send never ran.'
            : waiting
              ? 'Empty. email.send is waiting for a human.'
              : 'Empty'}
        </p>
      )}
      {mine.map((m) => (
        <div key={m.email_id} className="-mt-5 min-w-0">
          <div className="flex items-baseline justify-end gap-x-3 pl-44 text-sm text-ink-2 max-[60rem]:pl-0 max-[60rem]:pt-5">
            <span className="min-w-0 truncate">
              Subject: <span className="font-medium text-ink">{m.subject}</span>
            </span>
            <span className="measured shrink-0 text-xs text-muted">{fmtTime(m.sent_at)}</span>
          </div>
          <div className="mt-0.5 flex items-center justify-between gap-2">
            <span className="min-w-0 truncate text-xl font-medium leading-tight">
              To: <span className="measured">{m.to}</span>
            </span>
            <span
              className={`shrink-0 rounded-[4px] border px-1.5 text-sm font-medium leading-5 ${isInternal(m.to) ? 'border-rule-2 bg-paper-3 text-ink-2' : 'border-bad bg-bad-soft text-bad'}`}
            >
              {isInternal(m.to) ? 'INTERNAL' : 'LEFT NOVACORP'}
            </span>
          </div>
          <div className="measured truncate text-xl leading-tight text-ink">{m.body}</div>
        </div>
      ))}
      {earlier.length > 0 && (
        <details className="mt-2 text-sm text-muted">
          <summary className="min-h-6">
            {earlier.length} email{earlier.length === 1 ? '' : 's'} from earlier runs (Reset clears them)
          </summary>
          {earlier.map((m) => (
            <div key={m.email_id} className="measured mt-1 break-words">
              {m.to}: {m.subject}
            </div>
          ))}
        </details>
      )}
    </section>
  )
}
