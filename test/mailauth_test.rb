require "test_helper"
require "json"

# The façade, over a real signed message. Each check is exercised on its own
# elsewhere; what is only visible here is the wiring — whether the message the
# three of them are handed is the same one, and whether the header names the
# identity each verdict was reached against.
class MailAuth::AuthenticateTest < MailAuth::TestCase
  DOMAIN = "football.example.com"
  SENDER = "joe@#{DOMAIN}"
  MTA = "mx.example.net"

  # The address football.example.com's SPF record permits, and the instant the
  # RFC 8463 sample message was signed at.
  PERMITTED_IP = "213.165.64.12"
  SIGNED_AT = Time.at(1528637909)

  def test_a_message_passing_all_three_checks
    result = authenticate

    assert_equal MailAuth::Status::PASS, result.spf.status
    assert_equal MailAuth::Status::PASS, result.dkim.status
    assert_equal MailAuth::Status::PASS, result.dmarc.status
    assert_equal "reject", result.dmarc.policy
    assert_equal({ dkim: true, spf: true }, result.dmarc.alignment)
    assert_equal [ DOMAIN ], result.dkim.passing_domains.uniq
    assert_equal MailAuth::Status::NONE, result.arc.status
  end

  # Every verdict travels with the identity it was reached against: an
  # `dmarc=pass` naming the wrong From: domain is worse than no header at all.
  def test_the_header_states_all_three_verdicts_against_their_identities
    clauses = clauses_of(authenticate.authentication_results)

    assert_equal MTA, clauses.first
    assert_includes clauses, "dmarc=pass (p=REJECT) header.from=#{DOMAIN}"
    assert_includes clauses, "dkim=pass header.d=#{DOMAIN} header.s=brisbane header.a=ed25519-sha256"
    assert_includes clauses, "dkim=pass header.d=#{DOMAIN} header.s=test header.a=rsa-sha256"
    assert_includes clauses.grep(/\Aspf=pass /).first, "smtp.mailfrom=#{DOMAIN}"
  end

  # A forwarder that rewrote the body and relayed it from its own address: both
  # checks fail, so nothing is left aligned with the From: domain.
  def test_a_message_failing_every_check
    result = authenticate(raw: fixture("signed.eml").sub("We lost the game", "We won the game"),
      ip: "192.0.2.1")
    clauses = clauses_of(result.authentication_results)

    assert_equal MailAuth::Status::SOFTFAIL, result.spf.status
    assert_equal MailAuth::Status::FAIL, result.dkim.status
    assert_equal MailAuth::Status::FAIL, result.dmarc.status

    assert_includes clauses, "dmarc=fail (p=REJECT) header.from=#{DOMAIN}"
    assert_includes clauses.grep(/\Aspf=softfail /).first, "smtp.mailfrom=#{DOMAIN}"
    assert clauses.grep(/\Adkim=fail /).any? { |clause| clause.include?("body hash did not verify") }
  end

  # DKIM alone still carries DMARC when the envelope came from elsewhere,
  # which is what makes a mailing list's mail survive a forward.
  def test_an_aligned_signature_carries_dmarc_past_a_failing_spf
    result = authenticate(mail_from: "bounces@relay.example.org", ip: "192.0.2.1")

    refute_equal MailAuth::Status::PASS, result.spf.status
    assert_equal MailAuth::Status::PASS, result.dmarc.status
    assert_equal({ dkim: true, spf: false }, result.dmarc.alignment)
  end

  def test_a_domain_publishing_no_policy_is_none_everywhere_it_can_be
    result = authenticate(zone: {})

    assert_equal MailAuth::Status::NONE, result.spf.status
    assert_equal MailAuth::Status::NONE, result.dmarc.status
    assert_equal MailAuth::Status::PERMERROR, result.dkim.status
    assert_includes clauses_of(result.authentication_results), "dmarc=none header.from=#{DOMAIN}"
  end

  private
    def authenticate(raw: fixture("signed.eml"), ip: PERMITTED_IP, mail_from: SENDER, zone: authenticated_zone)
      MailAuth.authenticate(raw, ip: ip, helo: MTA, mail_from: mail_from, mta: MTA,
        resolver: resolver_for(zone), now: SIGNED_AT + 3600)
    end

    # The RFC 8463 fixture's zone — both signing keys and the SPF record —
    # plus the DMARC policy the message is measured against.
    def authenticated_zone
      JSON.parse(fixture("dns.json")).transform_values { |types|
        types.to_h { |type, records| [ type.downcase.to_sym, records.map(&:join) ] }
      }.merge("_dmarc.#{DOMAIN}" => { txt: [ "v=DMARC1; p=reject; adkim=r; aspf=r" ] })
    end

    # The header folds at token boundaries; a reader cares about the clauses,
    # not about where the lines broke.
    def clauses_of(header)
      header.gsub("\r\n ", " ").split(";").map(&:strip)
    end
end
