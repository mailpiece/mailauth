# Changelog

## Unreleased

- SPF: `allows_any`, true when a record read during the check carries `+all` and so lets any host pass
- `SpfResult#record`: the checked domain's own SPF record as published
- DKIM, ARC: an `l=` past the end of the body is a permerror instead of raising
- SPF: a macro keeping zero labels is a permerror, and one keeping more than there are keeps them all
- ARC: `claimed` reads only the method opening each result, never comments, quoted strings or properties
- DMARC, DKIM: an internationalized From domain or `d=` is looked up and reported by its A-label
- DKIM, ARC: a long `h=` costs a lookup per name instead of a pass over every header field
- A comment inside a From address, as in `ceo@(c)bank.example`, no longer hides its domain
- Authentication-Results is built from valid UTF-8, so a UTF-8 value beside message bytes or invalid UTF-8 no longer raises
- DKIM: an encrypted key in a key record is unreadable instead of prompting the terminal for a passphrase
- DKIM, ARC: the body is canonicalized once per form instead of once per signature

## 0.6.0

- iprev (RFC 8601 §2.7.3): the connecting address's reverse name, confirmed by resolving it forward, as `result.iprev` and an `iprev=` clause

## 0.5.0

- Initial public release