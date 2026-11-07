/** Rows shorten their arguments, so an email's recipient, the fact that matters most, goes first. */
export function recipientFirst<T>(args: T): T {
  if (!args || typeof args !== 'object' || !('to' in args)) return args
  const { to, ...rest } = args as Record<string, unknown>
  return { to, ...rest } as T
}
