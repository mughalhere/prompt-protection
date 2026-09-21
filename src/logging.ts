import type {
  Action,
  AnalysisResult,
  FlowSummary,
  LogLevel,
  LoggingOptions,
  OutputAnalysisResult,
  ProtectionEvent,
  ProtectionLogger,
  SeverityLevel,
  ThreatCategory,
} from './types.js';

/** Shape of a guard decision as seen by the logger (avoids importing guard types). */
export interface ToolCallEventSource {
  action: Action;
  toolName: string;
  toolCallId?: string;
  policy?: string;
  reasons?: string[];
  sink?: string;
  flows?: FlowSummary[];
  argsAnalysis: AnalysisResult;
  mode?: 'enforce' | 'observe';
  observedAction?: Action;
}

const DEFAULT_LOG_LEVELS: LogLevel[] = ['blocked', 'flagged'];
const DEFAULT_MAX_CONTENT = 200;

type Direction = ProtectionEvent['direction'];

function actionToLogLevel(action: Action, direction: Direction): LogLevel {
  if (action === 'block') return 'blocked';
  if (action === 'flag') return 'flagged';
  return direction === 'output' ? 'clean' : 'allowed';
}

function eventType(
  direction: Direction,
  action: Action,
): ProtectionEvent['type'] {
  if (direction === 'input') {
    if (action === 'block') return 'input.blocked';
    if (action === 'flag') return 'input.flagged';
    return 'input.allowed';
  }
  if (direction === 'tool-call') {
    if (action === 'block') return 'tool-call.blocked';
    if (action === 'flag') return 'tool-call.flagged';
    return 'tool-call.allowed';
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
  direction: Direction,
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
    if (direction === 'output') {
      event.contentPreview = preview;
    } else {
      event.promptPreview = preview;
    }
  }

  return event;
}

function shouldLog(action: Action, direction: Direction, options: LoggingOptions): boolean {
  const levels = options.logLevels ?? DEFAULT_LOG_LEVELS;
  return levels.includes(actionToLogLevel(action, direction));
}

function emitSafe(logger: ProtectionLogger, event: ProtectionEvent, options: LoggingOptions, content = ''): void {
  try {
    const result = logger.logWithContent ? logger.logWithContent(event, content) : logger.log(event);
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
  if (result.error) event.error = result.error.message;
  emitSafe(options.logger, event, options, content);
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
  if (result.error) event.error = result.error.message;
  emitSafe(options.logger, event, options, content);
}

/** Emit a `tool-call.*` event for a guard decision when a logger is configured. */
export function emitToolCallLog(
  decision: ToolCallEventSource,
  argsText: string,
  options: LoggingOptions,
): void {
  if (!options.logger) return;
  if (!shouldLog(decision.action, 'tool-call', options)) return;

  const analysis = decision.argsAnalysis;
  const event = buildEvent(
    'tool-call',
    analysis.score,
    decision.action,
    analysis.severity,
    analysis.categories,
    analysis.matches.map((m) => m.rule.id),
    argsText,
    options,
  );
  event.toolName = decision.toolName;
  if (decision.toolCallId !== undefined) event.toolCallId = decision.toolCallId;
  if (decision.policy !== undefined) event.policy = decision.policy;
  if (decision.reasons !== undefined) event.reasons = decision.reasons;
  if (decision.sink !== undefined) event.sink = decision.sink;
  if (decision.flows !== undefined) event.flows = decision.flows;
  if (decision.mode !== undefined) event.mode = decision.mode;
  if (decision.observedAction !== undefined) event.observedAction = decision.observedAction;
  if (analysis.error) event.error = analysis.error.message;
  emitSafe(options.logger, event, options, argsText);
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
