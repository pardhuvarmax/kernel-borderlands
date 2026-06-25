# Immutable Audit Trail

SHA-256 chained audit log for every KB action.

## Properties
- Append-only (chattr +a at filesystem level)
- Every entry hashes previous entry (blockchain-style)
- Tamper detection on every read
- Remote SIEM shipping (before local write confirms)
- Full attribution: who, what, when, why

## Entry Structure
{
  id, timestamp, monotonic_ts,
  action, subject, actor, reason,
  prev_hash, hash
}
