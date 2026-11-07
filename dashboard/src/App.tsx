import { lazy, Suspense, useEffect, useState } from 'react'
import { API_BASE, REPLAY } from './lib/config'
import { FIXTURE } from './lib/replay'
import { startApp, useApp } from './lib/store'
import AuditLog from './pages/AuditLog'
import LiveRun from './pages/LiveRun'
import ReviewInbox from './pages/ReviewInbox'

// Recharts is only needed on this page.
const EvalReport = lazy(() => import('./pages/EvalReport'))

const ROUTES = [
  { path: '/live', label: 'Live Run' },
  { path: '/inbox', label: 'Review Inbox' },
  { path: '/audit', label: 'Audit Log' },
  { path: '/eval', label: 'Evaluation Report' },
] as const

type RoutePath = (typeof ROUTES)[number]['path']

function currentRoute(): RoutePath {
  const h = window.location.hash.replace(/^#/, '')
  return ROUTES.find((r) => r.path === h)?.path ?? '/live'
}

function useRoute(): RoutePath {
  const [route, setRoute] = useState<RoutePath>(currentRoute)
  useEffect(() => {
    const on = () => setRoute(currentRoute())
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return route
}

function ConnectionStatus() {
  const { health, sse } = useApp()
  if (REPLAY) {
    return (
      <span className="rounded-[4px] border border-cool bg-cool-soft px-2 py-0.5 text-sm font-medium text-cool" title="No gateway calls are made in replay mode">
        Recorded replay
      </span>
    )
  }
  if (health.status === 'unknown') return <span className="text-sm text-muted">Checking gateway…</span>
  if (health.status === 'down') {
    return (
      <span className="flex flex-wrap items-center gap-x-3">
        <span className="rounded-[4px] border border-bad bg-bad-soft px-2 py-0.5 text-sm font-medium text-bad" title={health.error ?? undefined}>
          Gateway offline
        </span>
        <a className="inline-flex min-h-11 items-center text-sm text-ink-2 underline decoration-rule-2 hover:text-accent" href={`?replay=1${window.location.hash}`}>
          Use recorded replay
        </a>
      </span>
    )
  }
  const feed = sse === 'open' ? 'live feed on' : sse === 'off' ? 'no feed' : 'feed reconnecting'
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-sm min-[60rem]:flex-nowrap">
      <span className="shrink-0 whitespace-nowrap rounded-[4px] border border-ok bg-ok-soft px-2 py-0.5 font-medium text-ok">Gateway connected</span>
      <span className={`shrink-0 whitespace-nowrap ${sse === 'open' ? 'text-muted' : 'font-medium text-cool'}`}>{feed}</span>
      <span className="min-w-0 truncate text-muted" title={health.data?.model ?? undefined}>{health.data?.ollama_available ? `Ollama on (${health.data.model ?? 'model'})` : 'Ollama off'}</span>
    </span>
  )
}

function ReplayBanner() {
  const captured = FIXTURE.meta.capture === 'captured'
  const exit = `${window.location.pathname}${window.location.hash}`
  return (
    <div role="status" className="border-b border-rule bg-cool-soft py-3 text-ink">
      <div className="container">
        <b className="font-medium text-cool">RECORDED REPLAY. Not live data.</b>{' '}
        <span>
          {captured
            ? `A recorded run of scenario ${FIXTURE.meta.short_id} from a real gateway (scripted agent), played back from a stored file.`
            : `Scenario ${FIXTURE.meta.short_id} from a stored fixture that was written by hand, not captured from a gateway.`}{' '}
          The gateway is not contacted.{' '}
          <a className="font-medium underline decoration-rule-2 underline-offset-4 hover:text-accent" href={exit}>
            Exit replay
          </a>
        </span>
      </div>
    </div>
  )
}

export default function App() {
  const route = useRoute()
  const { tickets } = useApp()
  useEffect(() => startApp(), [])
  const pending = tickets.filter((t) => (t.state ?? 'pending') === 'pending').length

  return (
    <div className="flex min-h-svh flex-col">
      <header className="top-0 z-(--z-sticky-nav) border-b border-rule bg-paper-2 [@media(min-height:700px)_and_(min-width:60rem)]:sticky">
        <div className="container flex flex-wrap items-center gap-x-6 min-[60rem]:flex-nowrap">
          <a href="#/live" className="flex h-14 shrink-0 items-center gap-2 font-display text-lg font-medium text-ink no-underline">
            <svg viewBox="0 0 24 24" className="h-5 w-5 text-ink-2" fill="currentColor" aria-hidden="true">
              <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z" />
            </svg>
            Aegis
          </a>
          <nav aria-label="Pages" className="order-3 flex w-full overflow-x-auto [scrollbar-width:thin] min-[60rem]:order-none min-[60rem]:w-auto min-[60rem]:shrink-0">
            {ROUTES.map((r) => (
              <a
                key={r.path}
                href={`#${r.path}`}
                aria-current={route === r.path ? 'page' : undefined}
                className={`relative flex h-11 shrink-0 items-center whitespace-nowrap px-2 font-medium no-underline min-[60rem]:px-3 after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 min-[60rem]:h-14 ${route === r.path ? 'text-accent after:bg-accent' : 'text-ink-2 hover:text-ink'}`}
              >
                {r.label}
                {r.path === '/inbox' && pending > 0 && (
                  <span aria-label={`${pending} pending`} className="measured ml-2 inline-block min-w-6 rounded-[4px] border border-rule-2 bg-paper-3 px-1.5 text-center text-sm text-ink">
                    {pending}
                  </span>
                )}
              </a>
            ))}
          </nav>
          <div className="ml-auto flex min-h-14 min-w-0 items-center justify-end py-2">
            <ConnectionStatus />
          </div>
        </div>
      </header>
      {REPLAY && <ReplayBanner />}
      <main className="container w-full flex-1 py-3">
        {route === '/live' && <LiveRun />}
        {route === '/inbox' && <ReviewInbox />}
        {route === '/audit' && <AuditLog />}
        {route === '/eval' && (
          <Suspense fallback={<p className="text-muted">Loading…</p>}>
            <EvalReport />
          </Suspense>
        )}
      </main>
      <footer className="container pb-4 text-xs text-muted">
        Gateway: <span className="measured">{REPLAY ? 'not used (replay)' : API_BASE}</span>
      </footer>
    </div>
  )
}
