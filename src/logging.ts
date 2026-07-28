import type {
  Action,
  AnalysisResult,
  LogLevel,
  LoggingOptions,
  OutputAnalysisResult,
  ProtectionEvent,
  ProtectionLogger,
  SeverityLevel,
  ThreatCategory,
} from './types.js';

const DEFAULT_LOG_LEVELS: LogLevel[] = ['blocked', 'flagged'];
const DEFAULT_MAX_CONTENT = 200;

function actionToLogLevel(action: Action, direction: 'input' | 'output'): LogLevel {
  if (action === 'block') return 'blocked';
  if (action === 'flag') return 'flagged';
  return direction === 'input' ? 'allowed' : 'clean';
}

function eventType(
  direction: 'input' | 'output',
  action: Action,
): ProtectionEvent['type'] {
  if (direction === 'input') {
    if (action === 'block') return 'input.blocked';
    if (action === 'flag') return 'input.flagged';
    return 'input.allowed';
  }
  if (action === 'block') return 'output.blocked';
  if (action === 'flag') return 'output.flagged';
  return 'output.clean';
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + '…';
}

function buildEvent(
  direction: 'input' | 'output',
  score: number,
  action: Action,
  severity: SeverityLevel,
  categories: ThreatCategory[],
  ruleIds: string[],
  content: string | undefined,
  options: LoggingOptions,
): ProtectionEvent {
  const event: ProtectionEvent = {
    type: eventType(direction, action),
    timestamp: new Date().toISOString(),
    score,
    action,
    severity,
    categories,
    ruleIds,
    direction,
  };

  if (options.includeContent === true && content !== undefined) {
    const max = options.maxContentLength ?? DEFAULT_MAX_CONTENT;
    const preview = truncate(content, max);
    if (direction === 'input') {
      event.promptPreview = preview;
    } else {
      event.contentPreview = preview;
    }
  }

  return event;
}

function shouldLog(action: Action, direction: 'input' | 'output', options: LoggingOptions): boolean {
  const levels = options.logLevels ?? DEFAULT_LOG_LEVELS;
  return levels.includes(actionToLogLevel(action, direction));
}

function emitSafe(logger: ProtectionLogger, event: ProtectionEvent, options: LoggingOptions): void {
  try {
    const result = logger.log(event);
    if (result !== undefined && typeof result.then === 'function') {
      void result.catch((err: unknown) => {
        options.onLoggerError?.(err);
      });
    }
  } catch (err) {
    options.onLoggerError?.(err);
  }
}

/** Emit a protection event for an input analysis result when a logger is configured. */
export function emitInputLog(
  result: AnalysisResult,
  content: string,
  options: LoggingOptions,
): void {
  if (!options.logger) return;
  if (!shouldLog(result.action, 'input', options)) return;

  const event = buildEvent(
    'input',
    result.score,
    result.action,
    result.severity,
    result.categories,
    result.matches.map((m) => m.rule.id),
    content,
    options,
  );
  emitSafe(options.logger, event, options);
}

/** Emit a protection event for an output analysis result when a logger is configured. */
export function emitOutputLog(
  result: OutputAnalysisResult,
  content: string,
  options: LoggingOptions,
): void {
  if (!options.logger) return;
  if (!shouldLog(result.action, 'output', options)) return;

  const event = buildEvent(
    'output',
    result.score,
    result.action,
    result.severity,
    result.threats,
    result.matches.map((m) => m.rule.id),
    content,
    options,
  );
  emitSafe(options.logger, event, options);
}

/** Dev convenience logger that writes events to `console`. */
export function createConsoleLogger(): ProtectionLogger {
  return {
    log(event: ProtectionEvent): void {
      // eslint-disable-next-line no-console
      console.log('[prompt-protection]', event.type, {
        score: event.score,
        action: event.action,
        categories: event.categories,
        ruleIds: event.ruleIds,
      });
    },
  };
}
