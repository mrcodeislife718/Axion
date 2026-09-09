# Agent Identity and Authority Architecture

## Decision

Axion should extend its digital-passport model so an AI worker's durable identity remains separate from the temporary model/provider session used to execute work.

Axion remains a neutral identity and trust layer. Registration alone never grants execution authority.

## Durable worker identity

An AI worker or system should have a stable identity that can survive:

- model switching;
- provider switching;
- process restart;
- machine restart;
- client disconnect;
- runtime replacement;
- long-running tasks.

A provider session is an execution detail, not the identity itself.

Example:

```text
Axion identity: axion:agent:codeable-builder-17
Role: Builder
Capabilities: repository-read, bounded-patch, test-run
Declared authority requirements: repository-write approval
Qualification: verified for TypeScript implementation

Provider session A: local Qwen
Provider session B: Codex
Provider session C: Claude
```

All three provider sessions may act on behalf of the same durable worker identity when a governing runtime permits it.

## Identity contract

A worker identity should be able to describe or reference:

- canonical identity;
- version;
- publisher/controller;
- role;
- declared capabilities;
- required permissions;
- supported runtimes and protocols;
- compatible model/provider classes;
- qualification/evaluation evidence;
- trust signals;
- governance requirements;
- credential-scope requirements;
- audit support;
- lifecycle state;
- revocation state;
- manifest version and digest.

## Capability is not authority

Axion must preserve a strict distinction between:

- **Capability** — what the worker/tool claims or proves it can do.
- **Authority requirement** — what permission it needs to perform an operation.
- **Authority grant** — a runtime/customer decision allowing a specific action under defined limits.
- **Execution evidence** — proof of what happened after authorization.

Axion may describe authority requirements and record attributable grants or references, but it must not imply that registry presence authorizes execution.

## Bounded authority grants

Where integrations choose to record authority grants through Axion-compatible records, grants should be bounded by properties such as:

- subject / worker identity;
- task or mission;
- repository or environment;
- capability/action class;
- filesystem scope;
- network scope;
- secret/credential scope;
- time window;
- approval source;
- maximum consequence tier;
- revocation conditions;
- evidence/audit destination.

Broad permanent authority should not be the default.

## Qualification and trust history

Axion can strengthen worker selection by associating identity versions with evidence such as:

- tasks successfully completed;
- task classes qualified for;
- verification pass rates;
- security/policy violations;
- rollback frequency;
- provider compatibility;
- resource/cost characteristics;
- benchmark/evaluation records;
- operator or organizational attestations.

These remain attributable signals, not one unexplained trust score.

## Runtime relationship

### Codeable

Codeable may use Axion identity and qualification records when selecting workers, assigning roles, and determining what authority a task requires.

### Dev-Zero

Dev-Zero may resolve the durable identity behind an execution request and combine Axion metadata with local policy. Local policy remains authoritative for machine access.

### Sessions

Sessions may reference Axion identity, manifest version, role, capability declarations, and authority-grant references in execution lineage.

## Provider-session binding

A runtime should be able to record a temporary binding:

```text
Durable Axion identity
  -> current task/role
  -> temporary provider/model session
  -> execution segment
  -> evidence
```

The binding should be auditable and revocable. Ending or replacing the provider session does not erase the durable worker's history.

## Revocation and compromise

Axion should support lifecycle states that allow a worker/system identity or release to be:

- active;
- suspended;
- superseded;
- revoked;
- retired.

A compromised provider credential, failed qualification, policy violation, or vulnerable release should be able to invalidate future trust without erasing historical evidence.

## Product invariant

Axion should always preserve the difference between:

> who the worker is, what it can do, what permission it requires, what permission was actually granted elsewhere, and what evidence exists about its past behavior.

Identity must remain stable even when the underlying AI model is replaced.