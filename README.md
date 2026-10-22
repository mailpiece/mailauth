# mailauth

✉️ Email authentication for Ruby.

Verify SPF, DKIM, DMARC, and ARC on received mail, sign outgoing mail with DKIM, and seal what you forward with ARC.

**mailauth** checks whether a message's sender, signature, and policy all agree, and signs outgoing mail so others can check yours.

For mail receivers deciding whether to trust a message, and senders proving theirs is legitimate: inbound MTAs generating Authentication-Results headers, spam/phishing pipelines feeding authentication verdicts into a scoring system, outbound senders DKIM-signing mail before delivery.

**mailauth** handles:

- iprev (RFC 8601 §2.7.3), the connecting address's name confirmed by resolving it back
- SPF verification (RFC 7208)
- DKIM verification (RFC 6376), RSA and Ed25519
- DKIM signing (RFC 6376), RSA and Ed25519, oversigning by default
- DMARC verification (RFC 7489), strict and relaxed alignment
- Authentication-Results header generation (RFC 8601)
- ARC verification (RFC 8617), reporting what each hop sealed and left to you to trust
- ARC sealing (RFC 8617), adding a set that hands the next hop what this one concluded
- Injectable resolver, so tests run against a hash instead of a network

> Not a spam filter.

## Contents

- [Installation](#installation)
- [Authentication](#authentication)
- [Results](#results)
- [Individual Checks](#individual-checks)
- [When It Doesn't Pass](#when-it-doesnt-pass)
- [Resolver](#resolver)
- [ARC](#arc)
- [Signing](#signing)
- [Testing](#testing)
- [History](#history)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Installation

Add this line to your application's Gemfile:

```ruby
gem "mailauth"
```

Requires Ruby >= 3.4

## Authentication

```ruby
result = MailAuth.authenticate(raw_message, ip:, helo:, mail_from:, mta:, resolver:, now:)
# => #<MailAuth::Result spf:, dkim:, dmarc:, arc:, iprev:, authentication_results:>
```

- **raw_message** - the RFC 822 bytes as they arrived
- **ip** - IP address of the connecting client
- **helo** - optional, hostname from the HELO/EHLO command
- **mail_from** - optional, envelope sender; empty means `postmaster@helo` is checked
- **mta** - optional, your authserv-id, for the generated header
- **resolver** - optional, defaults to `MailResolver::Resolver.new` (see [Resolver](#resolver))
- **now** - optional `Time`, for signature expiry, defaults to `Time.now`

```ruby
require "mailauth"

result = MailAuth.authenticate(raw_message,
  ip: "209.85.220.41",
  helo: "mail-sor-f41.google.com",
  mail_from: "someone@gmail.com",
  mta: "mx.example.com")

puts result.authentication_results
```

```ruby
mx.example.com;
iprev=pass (mail-sor-f41.google.com) policy.iprev=209.85.220.41;
spf=pass
(domain of someone@gmail.com designates 209.85.220.41 as permitted sender)
smtp.mailfrom=gmail.com;
dkim=pass header.d=gmail.com header.s=20251104 header.a=rsa-sha256;
dmarc=pass (p=NONE) header.from=gmail.com
```

## Results

```ruby
result.iprev.status    # => "pass"
result.iprev.name      # => "mail-sor-f41.google.com" - the connecting address's name, only once it resolved back

result.spf.status      # => "pass"
result.spf.domain      # => "gmail.com"

result.dkim.status     # => "pass" - the best of every signature on the message
result.dkim.signatures # => [#<MailAuth::Signature status: "pass", domain: "gmail.com", ...>]

result.dmarc.status    # => "pass"
result.dmarc.policy    # => "reject" - what the domain asked for
result.dmarc.alignment # => { dkim: true, spf: false }
```

Every status is one of `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror` - the RFC 8601 vocabulary as plain strings, so a verdict persists without translation.

iprev has no `none`: an address nobody named is a `permerror`, as RFC 8601 files it, and a name that resolves somewhere else is a `fail`. Whoever runs the reverse zone can write any name there; only the forward lookup proves they run the name too.

`status` and `policy` stay separate. A DMARC `fail` under `p=none` and one under `p=reject` are the same failure; only the second is a reason to refuse the mail.

A DKIM signature can `pass` and still carry `under_sized` — the number of canonicalized body bytes past what its `l=` tag covered, content the signature says nothing about and that an attacker could have appended. `nil` unless the message carries an `l=` tag with bytes left uncovered.

## Individual Checks

Each protocol is usable on its own. iprev needs only the connection, and SPF no message at all, so both can answer at `RCPT TO` time, before any data has arrived:

```ruby
MailAuth::Iprev.check(ip: "209.85.220.41")
# => #<MailAuth::IprevResult status: "pass", name: "mail-sor-f41.google.com", comment: nil>

MailAuth::Spf.check(ip: "209.85.220.41", helo: "mail-sor-f41.google.com",
  mail_from: "someone@gmail.com")
# => #<MailAuth::SpfResult status: "pass", domain: "gmail.com", lookups: 1, ...>

message = MailAuth::Message.new(raw_message)

MailAuth::Dkim.verify(message)
# => #<MailAuth::DkimResult signatures: [...]>

MailAuth::Dmarc.check(header_from: message.header_from_domain, spf: spf, dkim: dkim)
# => #<MailAuth::DmarcResult status: "pass", policy: "none", ...>

MailAuth::Arc.verify(message)
# => #<MailAuth::ArcResult status: "pass", sets: [...], ...>
```

DMARC takes the SPF and DKIM results rather than recomputing them - alignment is a comparison, not a check of its own. ARC takes neither: a chain says what an earlier hop concluded, a separate question from what this one measured.

## When It Doesn't Pass

Nothing raises. A verdict is always returned, and the interesting ones carry a `comment`:

```ruby
result.dkim.signatures.each do |signature|
  puts "#{signature.domain}: #{signature.status} #{signature.comment}"
end
# gmail.com: fail body hash did not verify
# example.com: temperror DNS failure resolving sel._domainkey.example.com
```

- `fail` - the check ran and the message did not pass it
- `temperror` - DNS didn't answer; the same message may well pass later, don't treat it as a failure
- `permerror` - the record or signature is broken; retrying changes nothing
- `none` - the domain published no policy, or the message carried no signature

## Resolver

DNS resolution is [mailresolver](https://github.com/mailpiece/mailresolver), a separate gem, injected as `resolver:` everywhere a lookup happens:

```ruby
MailAuth.authenticate(raw, ip: ip, resolver: MailResolver::Resolver.new)
```

A resolver needs `txt`, `a`, `aaaa`, `mx`, and `ptr`, raising `MailResolver::NotFound` for a void lookup (SPF counts these against a limit), `MailResolver::Timeout` or `MailResolver::ServerFailure` for no answer, which produces a `temperror` that stops evaluation. Collapsing those into empty arrays loses a distinction SPF spends much of its rulebook on.

The default resolver uses [dnsruby](https://github.com/alexdalitz/dnsruby) rather than `Resolv`, which collapses SERVFAIL/REFUSED into the same empty answer as NXDOMAIN. If your app also uses `mta_sts` or talks to DNS itself, build one `MailResolver::Resolver` and pass it everywhere — see mailresolver's README for why.

## ARC

Forwarding breaks SPF, and mailing lists that rewrite a subject line break DKIM. An Authenticated Received Chain carries what each hop concluded before that happened, sealed against later editing:

```ruby
result.arc.status    # => "pass" - the chain is intact
result.arc.sealers   # => ["lists.example.org"] - oldest hop first
result.arc.newest.claimed
# => { "spf" => "pass", "dkim" => "pass", "dmarc" => "pass" }
```

An intact chain is not a reason to believe it. Sealing a chain over a message of one's own costs nothing, so a `pass` from a sealer you've never heard of means only that they signed what they signed. This library reports who sealed and what they asserted; deciding whose word counts is yours:

```ruby
if result.arc.intact? && TRUSTED_SEALERS.include?(result.arc.newest.seal.domain)
  result.arc.newest.claimed["dmarc"]
end
```

For the same reason a chain never touches the DMARC verdict. `result.dmarc` is what this hop measured; letting a chain speak for it would sell a pass for the price of a signature.

## Signing

```ruby
signed = MailAuth::Dkim.sign(raw_message,
  domain: "example.com", selector: "mail",
  key: OpenSSL::PKey.read(File.read("private.pem")))
# => the message with a DKIM-Signature field prepended
```

The algorithm comes from the key: an RSA key signs `rsa-sha256`, an Ed25519 key `ed25519-sha256` (RFC 8463). Canonicalization is `relaxed/relaxed`. RSA keys under 1024 bits are refused; RFC 8301 §3.2 recommends 2048+ for any key you generate today.

- **headers** - names to sign; defaults to the RFC 6376 §5.4.1 set
- **oversign** - names listed in `h=` once more than they occur, so an instance added after signing breaks it. Defaults to `from`, `to`, `cc`, `subject`, `date`, `reply-to`, `message-id`. Pass `[]` to disable
- **expires_in** - seconds, writes `x=`; omitted by default
- **now** - the signing instant for `t=`, defaults to `Time.now`

`MailAuth::Dkim::Signer#field` returns just the `DKIM-Signature` field, for callers assembling messages themselves.

Sealing adds three fields rather than one, saying what this hop found before it passed the message on:

```ruby
result = MailAuth.authenticate(raw_message, ip: ip, mta: "lists.example.org")

sealed = MailAuth::Arc.seal(raw_message,
  authentication_results: result.authentication_results,
  chain_status: result.arc.status,
  domain: "lists.example.org", selector: "arc",
  key: OpenSSL::PKey.read(File.read("private.pem")))
# => the message with ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results prepended
```

Authenticate first: sealing resolves nothing and re-checks nothing. Both what the set records and the status of the chain it continues are the caller's, which is what makes a seal a statement rather than a second opinion.

- **authentication_results** - the RFC 8601 value with no field name, as `result.authentication_results` returns it
- **chain_status** - `none`, `pass`, or `fail` for the chain that arrived, from `result.arc.status`
- **domain**, **selector**, **key** - as for DKIM signing, algorithm again taken from the key
- **headers** - names for the message signature's `h=`; an ARC name is refused, since the seal signs that signature (RFC 8617 §4.1.2)
- **oversign** - defaults to none: an oversigned name is one no later hop may add, and a sealed message is one still travelling
- **now** - the sealing instant for `t=`

The instance number is one above the highest already on the message. A chain someone has sealed `cv=fail` is finished (RFC 8617 §5.1.3): `result.arc` says so, and whether to seal one anyway is yours to decide.

`MailAuth::Arc::Sealer` returns the fields one at a time — `#seal_field`, `#message_signature_field`, `#authentication_results_field` — for callers assembling messages themselves.

## Testing

```sh
bundle install
rake
```

## History

View the [changelog](CHANGELOG.md).

## Contributing

Everyone is encouraged to help improve this project:

- [Report bugs](https://github.com/mailpiece/mailauth/issues)
- Fix bugs and submit pull requests
- Write, clarify, or fix documentation
- Suggest or add new features

## Acknowledgments

View the [acknowledgments](ACKNOWLEDGMENTS.md).

## License

MIT. See [LICENSE](LICENSE).