# Deployment

## Phase 1: design

Inventory projects, data classes, required operations, worker groups, automation identities, reviewers, custodians, retention, and export destinations. Use group SIDs instead of individual display names where possible.

## Phase 2: disposable validation

Create a test root with synthetic data. Add the root marker, validate the policy, run the access gate as each test identity, preview the ACL plan, apply it, and prove that a documented recovery identity can restore access.

## Phase 3: parallel evidence

Run preflight checks and integrity verification without enforcing production ACLs. Investigate every false denial and ambiguous path. Forward ledger copies to storage that workspace operators cannot rewrite.

## Phase 4: staged enforcement

Enable one project at a time. Keep inputs read-only, work areas project-specific, review areas reviewer-only, and exports empty until approved. Record policy review and rollback ownership.

## Phase 5: operations

Run verification daily and after policy or membership changes. Rotate service credentials, review group membership, rehearse incident response, and expire projects rather than silently reusing their directories.

## Recovery

ACL application writes an `icacls` backup before changing a zone. Test restore commands only in the disposable environment and store the approved production procedure in the organization's protected runbook. Never rely on a copy inside the same guarded workspace.
