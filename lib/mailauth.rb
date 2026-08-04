require "mailresolver"
require "mailauth/version"
require "mailauth/result"
require "mailauth/message"
require "mailauth/spf"
require "mailauth/dkim"
require "mailauth/dmarc"
require "mailauth/arc"
require "mailauth/authentication_results"

# Authenticates a received message against SPF, DKIM, DMARC, and ARC, returning
# the verdicts and the RFC 8601 Authentication-Results header stating them.
# Says nothing about whether the message is wanted.
module MailAuth
  def self.authenticate(raw, ip:, helo: nil, mail_from: nil, mta: nil, resolver: MailResolver::Resolver.new, now: Time.now)
    message = Message.new(raw)

    spf = Spf.check(ip: ip, helo: helo, mail_from: mail_from, resolver: resolver)
    dkim = Dkim.verify(message, resolver: resolver, now: now)
    dmarc = Dmarc.check(header_from: message.header_from_domain, spf: spf, dkim: dkim, resolver: resolver)

    # DMARC is measured against this hop and ARC reports on earlier ones, so the
    # two are answered apart. Letting a chain speak for DMARC would hand any
    # sender a pass for the price of sealing their own message.
    arc = Arc.verify(message, resolver: resolver, now: now)

    Result.new(spf:, dkim:, dmarc:, arc:,
      authentication_results: AuthenticationResults.new(spf:, dkim:, dmarc:, arc:, mta:,
        header_from: message.header_from_domain).to_s)
  end
end
