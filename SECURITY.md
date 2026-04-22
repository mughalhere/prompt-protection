# Security Policy

## Scope

This package is a **detection layer** — it is not a guaranteed security boundary. It uses pattern matching and heuristics that can be bypassed by sufficiently novel attacks. Do not use it as your sole defence against adversarial inputs.

## Reporting a Vulnerability

If you discover a bypass technique (a prompt that should be blocked but isn't) or a false-positive regression, please report it privately:

- **Email**: open a GitHub security advisory at https://github.com/mughalhere/prompt-protection/security/advisories/new

Please include:
- The exact prompt
- The `analyzePrompt()` output (score, categories, matches)
- The attack category you believe it represents

We will respond within 72 hours and aim to publish a fix within 7 days for critical bypasses.

## Supported Versions

Only the latest release receives security fixes.
