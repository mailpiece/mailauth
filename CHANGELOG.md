# Changelog

## Unreleased

- SPF: `allows_any`, true when a record read during the check carries `+all` and so lets any host pass
- `SpfResult#record`: the checked domain's own SPF record as published
- DKIM, ARC: an `l=` past the end of the body is a permerror instead of raising
- SPF: a macro keeping zero labels is a permerror, and one keeping more than there are keeps them all

## 0.6.0

- iprev (RFC 8601 §2.7.3): the connecting address's reverse name, confirmed by resolving it forward, as `result.iprev` and an `iprev=` clause

## 0.5.0

- Initial public release