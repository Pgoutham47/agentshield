# Product positioning

## Position

**AgentShield: task-bound authorization for coding agents.**

Give a coding agent enough access to finish an issue, with a verifiable boundary around what it may read, change, and publish.

This is a positioning hypothesis to validate with design partners, not a researched claim of market uniqueness. The source documents' broad claim that no existing control provides an enforcement point is too absolute to use without a current competitive study.

## First customer and workflow

Start with platform and application-security teams running coding agents on infrastructure they control, with GitHub as the system of record. The buyer is the engineering/security owner approving agent access; the installer is a platform engineer; developers and designated reviewers use the workflow.

The first job is narrow: take one issue in one repository to a draft pull request without disclosing private material, changing release authority, or interrupting safe work unnecessarily. Teams using a closed agent product with no controllable execution path are outside the initial enforcement promise.

## Product promise

1. Authority follows the task: explicit resources, issue, operations, destination, expiry, and budgets.
2. Review means this action: show exact payload and target; bind approval to immutable bytes and current state.
3. Useful work continues: deny or hold an unsafe action without abandoning the legitimate fix.
4. Coverage is visible: tell the operator what is mocked, disconnected, untested, or enforced.
5. Evidence records outcomes: distinguish attempted, denied, held, completed, failed, and unknown.

Avoid “impossible to bypass,” “eliminates prompt injection,” and unsupported prevention percentages. The defensible claim depends on tested deployment boundaries.

## Demonstration narrative

Lead with the work: an agent opens a useful draft PR. Then introduce an unrelated repository read and show deterministic denial. End with the harder case: a comment is permitted by repository and issue scope, but its content exposes internal configuration. Show the exact comment, the reason it is held, the review, and the completed fix.

Show both the AI-off baseline and fixture/live distinction. Publish the mode and denominator next to every evaluation number. The offline fixture proves enforcement behavior, not model intelligence.

## What makes this first build better

The implementation improves the brief's in-memory baseline with transactional persistence, restart recovery, immutable approval lineage, identity separation, full-envelope digest checks, concurrent replay tests, and an inspectable console. The scope remains small enough to evaluate honestly.

“Better tech stack” here means fewer operational dependencies and stronger verification at this stage. It does not require replacing the PRD's longer-term architecture before a customer workflow has been validated.

## Pilot gates and discovery questions

- Identify a design partner whose runner, credentials, and tool route can actually be controlled.
- Choose the issue-to-PR agent and a disposable GitHub repository for connector conformance.
- Agree on data handling and the live evaluator provider before sending real code or content.
- Measure time to integrate, legitimate task completion, review burden, outcome accuracy, and prevented actions per attack family.
- Validate willingness to pay around a protected workflow and operational accountability; do not set pricing from token usage alone without customer evidence.

The next product milestone is one real, explicitly scoped GitHub workflow in a controlled environment. Generic MCP expansion, multiple SaaS connectors, and enterprise administration follow demonstrated need.
