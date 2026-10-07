# Security Policy

## Supported versions

Security fixes are applied to the default branch. Older commits or releases may not receive security updates.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public issue.

Include:
- a clear description of the issue and affected component;
- reproduction steps or a minimal proof of concept;
- the potential security impact;
- any relevant logs, traces, or sample files that can be shared safely.

Do not include secrets, credentials, personal data, or other sensitive material in a public issue.

## Scope

This project is intended for defensive security research and analysis. Findings about third-party systems should be reported to the affected project or vendor through its own responsible-disclosure process.

## Disclosure

Please allow reasonable time for investigation and remediation before public disclosure. Coordinated disclosure is preferred where practical.

## Trust boundaries

The umbrella scanner treats repositories, source files, manifests, RAG documents, training datasets, and agent traces as untrusted input. Adapters should parse these inputs as data and must not execute target-project code as part of a static scan.

Optional specialist scanners are external dependencies. Pin versions in production CI and review dependency changes before rollout. A clean result is not proof that a repository or AI system is safe; detection is heuristic and coverage depends on the installed scanner versions and selected inputs.

The GitHub Action may write SARIF and JSON artifacts to the workflow workspace. Review artifact contents and workflow permissions before publishing them to shared systems.
