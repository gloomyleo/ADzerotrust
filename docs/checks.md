# Checks

The following collectors run read-only queries and return JSON:
- KRBTGT password age
- Pre-auth disabled users (AS-REP roastable)
- Delegation audit (unconstrained/constrained/RBCD)
- AdminSDHolder drift signal
- SPN service accounts snapshot
- gMSA usage
- LDAP/SMB signing (hints)
- NTLM posture (hints)
- LAPS coverage
- AD CS risky templates (signals)

Edit `checks/manifest.yaml` to add/disable checks.
