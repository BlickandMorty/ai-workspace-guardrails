# Threat model

## Assets

- customer or project input;
- intermediate work and model output;
- reviewer decisions and approved exports;
- authorization policy, integrity manifests, and audit evidence.

## Security goals

1. An identity assigned to Project A cannot read or alter Project B.
2. Agents fail closed before operating outside an authorized zone.
3. Input data is read-only to ordinary operators and agents.
4. Only reviewers or custodians can approve exports.
5. Changes to guarded evidence are detectable.
6. Evidence does not duplicate protected content.

## In-scope threats

- accidental selection of the wrong workspace;
- prompt injection asking an agent to cross project boundaries;
- a contractor browsing a sibling project directory;
- compromised scripts attempting unauthorized writes;
- output being moved directly from work to an external destination;
- policy, ACL, or input drift.

## Controls

- stable SID-based principals;
- default-deny role and zone policy;
- root containment and traversal checks;
- optional reparse-point refusal;
- NTFS ACLs owned and verified by SYSTEM;
- separate review and approved-export zones;
- preflight authorization for every agent file operation;
- SHA-256 manifests and a hash-chained event ledger;
- scheduled verification and independently retained evidence.

## Residual risk

This design does not defeat a local administrator, kernel compromise, stolen authorized credentials, offline disk access, or deliberate copying by a person who is legitimately allowed to read data. Mitigate those risks with managed devices, least-privilege accounts, encryption, DLP, EDR, remote attestation where appropriate, and server-side authorization.
