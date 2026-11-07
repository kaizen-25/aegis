import type { LiveEvent } from '../types/contracts'
import { API_BASE } from './config'

export type SseState = 'connecting' | 'open' | 'reconnecting'

const EVENT_TYPES = ['decision', 'ticket', 'ticket_update', 'session_update', 'explanation_ready', 'eval_progress'] as const

function isLiveEvent(v: unknown): v is LiveEvent {
  if (!v || typeof v !== 'object') return false
  const o = v as Record<string, unknown>
  return typeof o.type === 'string' && typeof o.session_id === 'string' && typeof o.mode === 'string' && 'payload' in o
}

export interface EventsHandlers {
  onEvent(ev: LiveEvent): void
  /** `reconnected` is true when this open follows an earlier connection or a failure. */
  onState(state: SseState, reconnected: boolean): void
}

/**
 * SSE client for GET /events. Reconnects with backoff on any error, because EventSource gives up
 * for good on some failures (for example a non-200 response while the gateway is starting).
 * Returns a function that stops it.
 */
export function connectEvents(h: EventsHandlers): () => void {
  let es: EventSource | null = null
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let attempt = 0
  let seenBefore = false

  const handle = (m: MessageEvent) => {
    try {
      const data: unknown = JSON.parse(String(m.data))
      if (isLiveEvent(data)) h.onEvent(data)
    } catch {
      /* ignore keep-alives and malformed frames */
    }
  }

  const open = () => {
    if (stopped) return
    h.onState(attempt === 0 ? 'connecting' : 'reconnecting', false)
    es = new EventSource(`${API_BASE}/events`)
    es.onopen = () => {
      const reconnected = seenBefore
      seenBefore = true
      attempt = 0
      h.onState('open', reconnected)
    }
    es.onmessage = handle
    for (const t of EVENT_TYPES) es.addEventListener(t, handle as EventListener)
    es.onerror = () => {
      es?.close()
      es = null
      if (stopped) return
      seenBefore = true
      attempt += 1
      h.onState('reconnecting', false)
      timer = setTimeout(open, Math.min(5000, 500 * 2 ** Math.min(attempt, 4)))
    }
  }
  open()

  return () => {
    stopped = true
    if (timer) clearTimeout(timer)
    es?.close()
  }
}
