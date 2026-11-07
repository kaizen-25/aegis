const base = (import.meta.env.VITE_API_BASE as string | undefined)?.trim()

/** Gateway base URL. Override with VITE_API_BASE. */
export const API_BASE: string = (base || 'http://127.0.0.1:8000').replace(/\/+$/, '')

/** ?replay=1 serves the recorded B1 fixture instead of talking to the gateway. */
export const REPLAY: boolean = new URLSearchParams(window.location.search).get('replay') === '1'

/** Identity sent as `by` on reviewer and unfreeze calls. */
export const ACTOR = 'dashboard'
