# AI Workspace Guardrails

AI Workspace Guardrails is a defensive Windows toolkit for isolating project data used by employees, contractors, reviewers, and automation agents. It turns a human-readable policy into preflight authorization checks, NTFS access plans, integrity manifests, and a hash-chained evidence ledger.

It is designed for annotation, evaluation, recruiting, research, and other multi-project workflows where one person or agent must not read or modify another project's data. It is not affiliated with any data-work platform.

## What it protects

- project-to-project data separation;
- least-privilege read, write, review, export, and administration roles;
- agent preflight checks before a tool touches a path;
- protected input zones and write-only output zones;
- file integrity with SHA-256 manifests;
- append-only-style, hash-chained audit evidence;
- explicit export approval and safe handoff records;
- ACL drift detection and scheduled verification.

## Honest security boundary

An AI model is not a Windows security principal. If an agent runs as Alice, Windows sees Alice. Strong separation therefore requires distinct Windows users, groups, service accounts, sandbox identities, or a broker service. Prompt instructions are useful policy, but they are not an access-control boundary.

This project supplies both layers:

1. `Test-AgentAccess.ps1` gives an agent a fail-closed preflight gate.
2. `Set-WorkspaceBoundary.ps1` can enforce the same policy with Windows identities and NTFS ACLs.

Local administrators can ultimately take ownership of local files. Organizations needing stronger guarantees should combine this toolkit with managed identities, EDR, device management, encrypted storage, network controls, and centralized audit retention.

## Quick start

1. Copy `config/example.policy.json` to a private configuration location.
2. Replace sample paths and principal SIDs with your organization's values.
3. Create the workspace root and place an empty `.workspace-guard-root.json` marker in it.
4. Validate the policy:

   ```powershell
   pwsh -NoProfile -File .\scripts\Test-WorkspacePolicy.ps1 -PolicyPath .\config\example.policy.json
   ```

5. Preview ACL changes (no changes are made):

   ```powershell
   pwsh -NoProfile -File .\scripts\Set-WorkspaceBoundary.ps1 -PolicyPath .\config\example.policy.json -Mode Plan
   ```

6. Ask the gate whether an operation is allowed:

   ```powershell
   pwsh -NoProfile -File .\scripts\Test-AgentAccess.ps1 `
     -PolicyPath .\config\example.policy.json `
     -TargetPath C:\GuardedWork\Project-Example\input\record.json `
     -Operation Read
   ```

7. Create and verify an integrity manifest:

   ```powershell
   pwsh -NoProfile -File .\scripts\New-IntegrityManifest.ps1 -PolicyPath .\config\example.policy.json
   pwsh -NoProfile -File .\scripts\Test-WorkspaceIntegrity.ps1 -PolicyPath .\config\example.policy.json
   ```

## Apply gate

ACL application is deliberately difficult to trigger. It requires elevation, the root marker, a policy that passes validation, a path outside protected operating-system locations, `-ConfirmApply`, and the exact acknowledgement string shown by the plan. An ACL backup is written before changes.

Start with a disposable test directory. Never point the sample policy at a live production workspace until the organization has tested recovery and approved the identity mapping.

## Policy model

The example policy defines:

- stable project and policy identifiers;
- a workspace root;
- identities identified by SID, never display name alone;
- roles and allowed operations;
- zones with classification, allowed identities, and inheritance behavior;
- paths that can never be exported;
- evidence and manifest locations outside guarded data zones.

Unknown identities, unknown operations, paths outside the workspace, ambiguous zones, reparse points that escape the root, and policy-validation failures are denied.

## Repository map

- `scripts/WorkspaceGuard.psm1` — shared validation, identity, path, hash, and ledger functions.
- `scripts/Test-WorkspacePolicy.ps1` — schema and boundary validation.
- `scripts/Test-AgentAccess.ps1` — fail-closed authorization preflight for agents and tools.
- `scripts/Set-WorkspaceBoundary.ps1` — dry-run-first ACL planner and applier.
- `scripts/New-IntegrityManifest.ps1` — manifest creation.
- `scripts/Test-WorkspaceIntegrity.ps1` — content and policy drift verification.
- `scripts/Export-GuardEvidence.ps1` — redacted evidence bundle creation.
- `scripts/Install-GuardVerificationTask.ps1` — optional SYSTEM verification schedule.
- `docs/THREAT-MODEL.md` — assets, adversaries, controls, and residual risk.
- `docs/DEPLOYMENT.md` — staged rollout and rollback testing.
- `docs/INCIDENT-RESPONSE.md` — containment and evidence handling.

## Safety and privacy

The public example contains no real customer names, worker data, credentials, SIDs, or platform-specific secrets. Audit evidence records normalized metadata and hashes; it does not copy project content. Review `DISCLAIMER.md` before use.

## License

MIT. See `LICENSE`.
