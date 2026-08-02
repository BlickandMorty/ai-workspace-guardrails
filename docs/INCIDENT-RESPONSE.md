# Incident response

1. Stop affected automation and revoke the compromised identity's active sessions.
2. Preserve the policy, manifest, ledger, Windows security logs, EDR telemetry, and server-side access logs.
3. Do not "repair" files before acquiring evidence and hashes.
4. Determine whether the event was a policy denial, ACL drift, integrity drift, credential misuse, or administrative takeover.
5. Rotate affected credentials and review every project membership sharing the identity.
6. Restore data only from a verified, independently retained backup.
7. Issue a new policy version and manifest; never rewrite old evidence to make the chain appear continuous.
8. Complete any contractual, privacy, and regulatory notification process with qualified personnel.

The hash chain detects ordinary editing and truncation when a trusted copy of the latest hash is held elsewhere. It is not a digital signature and is not tamper-proof if an attacker controls both the ledger and every anchor copy.
