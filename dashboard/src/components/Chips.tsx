import type { ExecStatus, Flag, Verdict } from '../types/contracts'
import { FLAG_MEANING } from '../lib/rules'

/*
 * Every outcome has a symbol, a label and a tint, so none relies on colour alone.
 * ALLOW ok, BLOCK bad, REVIEW amber (a person decides).
 * EXECUTION_FAILED and FAIL_CLOSED are cool: the instrument failed, not the policy.
 * They differ from each other and from BLOCK by symbol, label and border.
 */
const base =
  'inline-flex items-center gap-1 whitespace-nowrap rounded-[4px] border px-2 py-0.5 text-sm font-medium leading-5'

function WarnIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" aria-hidden="true">
      <path d="M8 2 15 14H1z" />
      <path d="M8 6.5v3.5M8 12v.01" strokeLinecap="round" />
    </svg>
  )
}

function StopIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="8" cy="8" r="6.2" />
      <path d="M3.8 12.2 12.2 3.8" strokeLinecap="round" />
    </svg>
  )
}

const OUTCOME: Record<string, { cls: string; icon?: 'warn' | 'stop'; label: string }> = {
  ALLOW: { cls: 'border-ok bg-ok-soft text-ok', label: '✓ ALLOW' },
  BLOCK: { cls: 'border-bad bg-bad-soft text-bad', label: '✕ BLOCK' },
  REVIEW: { cls: 'border-accent bg-accent-soft text-accent', label: '! REVIEW' },
  EXECUTION_FAILED: { cls: 'border-dashed border-cool bg-cool-soft text-cool', icon: 'warn', label: 'TOOL FAILED' },
  FAIL_CLOSED: { cls: 'border-2 border-double border-cool bg-cool-soft text-cool', icon: 'stop', label: 'FAIL-CLOSED' },
}

function OutcomeBody({ o }: { o: (typeof OUTCOME)[string] }) {
  return (
    <>
      {o.icon === 'warn' && <WarnIcon />}
      {o.icon === 'stop' && <StopIcon />}
      {o.label}
    </>
  )
}

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  const o = OUTCOME[verdict]
  return (
    <span className={`${base} ${o.cls}`}>
      <OutcomeBody o={o} />
    </span>
  )
}

/** The headline chip for a row: a tool failure or system failure outranks the verdict. */
export function OutcomeChip({ verdict, status }: { verdict: Verdict; status: ExecStatus }) {
  const key = status === 'EXECUTION_FAILED' || status === 'FAIL_CLOSED' ? status : verdict
  const o = OUTCOME[key]
  return (
    <span className={`${base} ${o.cls}`}>
      <OutcomeBody o={o} />
    </span>
  )
}

const STATUS: Record<ExecStatus, string> = {
  EXECUTED: 'border-rule-2 bg-ok-soft text-ok',
  EXECUTION_FAILED: 'border-dashed border-cool bg-cool-soft text-cool',
  BLOCKED: 'border-rule-2 bg-bad-soft text-bad',
  FAIL_CLOSED: 'border-cool bg-cool-soft text-cool',
  PENDING: 'border-rule-2 bg-accent-soft text-accent',
  PARKED: 'border-rule-2 bg-accent-soft text-accent',
  APPROVED: 'border-rule-2 bg-accent-soft text-accent',
  REJECTED: 'border-rule-2 bg-accent-soft text-accent',
}

export function StatusChip({ status }: { status: ExecStatus }) {
  return (
    <span className={`inline-flex items-center whitespace-nowrap rounded-[4px] border px-2 py-0.5 text-xs font-medium leading-4 ${STATUS[status]}`}>
      {status}
    </span>
  )
}

export function WouldChip({ verdict }: { verdict: Verdict }) {
  const cls =
    verdict === 'ALLOW'
      ? 'border-rule-2 bg-ok-soft text-ok'
      : verdict === 'BLOCK'
        ? 'border-bad bg-bad-soft text-bad'
        : 'border-accent bg-accent-soft text-accent'
  return (
    <span className={`inline-flex items-center whitespace-nowrap rounded-[4px] border px-2 py-0.5 text-xs font-medium leading-4 ${cls}`} title="What protected mode would have decided">
      would {verdict}
    </span>
  )
}

export function FlagChip({ flag }: { flag: Flag }) {
  const cls =
    flag === 'URGENCY_CLAIM'
      ? 'border-bad bg-bad-soft text-bad'
      : flag === 'SYSTEM_FAIL_CLOSED' || flag === 'LLM_CONCERN'
        ? 'border-cool bg-cool-soft text-cool'
        : 'border-rule-2 bg-paper-3 text-ink-2'
  return (
    <span className={`inline-flex items-center whitespace-nowrap rounded-[4px] border px-2 py-0.5 text-xs font-medium leading-4 ${cls}`} title={FLAG_MEANING[flag]}>
      {flag === 'LLM_CONCERN' ? (
        <>
          <span>LLM_CONCERN</span>
          <span className="ml-2 border-l border-cool pl-2 font-normal">AI observer</span>
        </>
      ) : (
        flag
      )}
    </span>
  )
}

/** Text written by the local model. Always labelled, and always shown after the rule text. */
export function AiNote({ text, className = '' }: { text: string; className?: string }) {
  return (
    <div className={`rounded-card border border-rule bg-cool-soft p-3 text-sm ${className}`}>
      <div className="text-sm font-medium text-cool">Written by the local AI</div>
      <div className="mt-1 text-ink">{text}</div>
      <div className="mt-1 text-xs text-muted">Not part of the decision. The rule text above is what decided.</div>
    </div>
  )
}

export function Pill({ children, tone = 'plain', title }: { children: React.ReactNode; tone?: 'plain' | 'hot' | 'ok'; title?: string }) {
  const cls =
    tone === 'hot'
      ? 'border-cool bg-cool-soft text-cool'
      : tone === 'ok'
        ? 'border-rule-2 bg-ok-soft text-ok'
        : 'border-rule-2 bg-paper-3 text-ink-2'
  return (
    <span title={title} className={`inline-flex items-center whitespace-nowrap rounded-[4px] border px-2 py-0.5 text-sm font-medium leading-5 ${cls}`}>
      {children}
    </span>
  )
}
