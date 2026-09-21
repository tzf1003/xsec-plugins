type LogContext = Record<string, boolean | number | string | undefined>;

/** Log an action boundary while preserving its result or thrown error. */
export async function loggedAction<T>(
  event: string,
  context: LogContext,
  action: () => Promise<T>,
): Promise<T> {
  console.info(`${event}.started`, context);
  try {
    const result = await action();
    console.info(`${event}.completed`, context);
    return result;
  } catch (error) {
    console.error(`${event}.failed`, context);
    throw error;
  }
}
