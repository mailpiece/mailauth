require "test_helper"

class MailAuth::DmarcTest < MailAuth::TestCase
  # Discovery

  def test_a_record_at_the_exact_domain_is_used
    result = check("example.com", record("p=reject"))

    assert_equal MailAuth::Status::FAIL, result.status
    assert_equal "reject", result.policy
    assert_equal "v=DMARC1; p=reject", result.record
  end

  def test_no_record_anywhere_is_none
    result = check("example.com", zone)

    assert_equal MailAuth::Status::NONE, result.status
    assert_nil result.policy
    assert_nil result.record
  end

  def test_a_record_that_is_not_dmarc_is_none
    result = check("example.com", zone("_dmarc.example.com" => [ "v=spf1 -all" ]))

    assert_equal MailAuth::Status::NONE, result.status
  end

  def test_a_record_without_a_policy_is_none
    result = check("example.com", record("rua=mailto:dmarc@example.com"))

    assert_equal MailAuth::Status::NONE, result.status
  end

  def test_a_record_with_an_unknown_policy_is_none
    result = check("example.com", record("p=discard"))

    assert_equal MailAuth::Status::NONE, result.status
  end

  def test_two_dmarc_records_are_none
    result = check("example.com", zone("_dmarc.example.com" => [ "v=DMARC1; p=reject", "v=DMARC1; p=none" ]))

    assert_equal MailAuth::Status::NONE, result.status
  end

  def test_a_second_non_dmarc_record_is_ignored
    result = check("example.com",
      zone("_dmarc.example.com" => [ "some-verification-token", "v=DMARC1; p=quarantine" ]))

    assert_equal "quarantine", result.policy
  end

  def test_the_version_tag_is_matched_case_insensitively
    result = check("example.com", zone("_dmarc.example.com" => [ "V=DMARC1; P=Reject" ]))

    assert_equal "reject", result.policy
  end

  def test_a_record_for_a_longer_version_is_not_dmarc1
    result = check("example.com", zone("_dmarc.example.com" => [ "v=DMARC10; p=reject" ]))

    assert_equal MailAuth::Status::NONE, result.status
  end

  def test_a_timeout_is_temperror
    result = check("example.com", zone("_dmarc.example.com" => :timeout))

    assert_equal MailAuth::Status::TEMPERROR, result.status
  end

  def test_a_server_failure_is_temperror
    result = check("example.com", zone("_dmarc.example.com" => :servfail))

    assert_equal MailAuth::Status::TEMPERROR, result.status
  end

  # Must not quietly fall back to the parent's policy: we don't know yet
  # whether the subdomain publishes one of its own.
  def test_a_timeout_at_the_subdomain_does_not_fall_back_to_the_organizational_domain
    result = check("mail.example.com",
      zone("_dmarc.mail.example.com" => :timeout, "_dmarc.example.com" => [ "v=DMARC1; p=reject" ]))

    assert_equal MailAuth::Status::TEMPERROR, result.status
  end

  def test_no_from_domain_is_permerror
    assert_equal MailAuth::Status::PERMERROR, check(nil, zone).status
  end

  def test_two_from_domains_are_permerror
    assert_equal MailAuth::Status::PERMERROR, check([ "example.com", "example.net" ], zone).status
  end

  def test_one_from_domain_in_an_array_is_evaluated
    result = check([ "example.com" ], record("p=none"))

    assert_equal "none", result.policy
  end

  def test_discovery_queries_the_underscore_dmarc_name
    resolver = resolver_for(record("p=none"))
    MailAuth::Dmarc.check(header_from: "mail.example.com", spf: nil, dkim: nil, resolver: resolver)

    assert_equal [ [ "_dmarc.mail.example.com", :txt ], [ "_dmarc.example.com", :txt ] ], resolver.queries
  end

  # Subdomain policy

  def test_the_organizational_records_sp_applies_to_a_subdomain
    result = check("mail.example.com", record("p=reject; sp=quarantine"))

    assert_equal "quarantine", result.policy
  end

  def test_the_organizational_records_p_applies_to_a_subdomain_without_sp
    result = check("mail.example.com", record("p=reject"))

    assert_equal "reject", result.policy
  end

  # sp governs the parent's *subdomains*; the organizational domain itself
  # still answers to p even when sp is published.
  def test_a_records_own_p_applies_at_the_exact_domain_even_when_sp_is_set
    result = check("example.com", record("p=reject; sp=none"))

    assert_equal "reject", result.policy
  end

  def test_a_subdomains_own_record_wins_over_the_parents
    result = check("mail.example.com",
      record("p=none; sp=reject", at: "mail.example.com").merge(record("p=reject")))

    assert_equal "none", result.policy
  end

  # Organizational domains

  def test_the_organizational_domain_of_a_multi_label_suffix_is_registrable
    result = check("news.bar.co.uk", record("p=reject", at: "bar.co.uk"))

    assert_equal "reject", result.policy
  end

  def test_a_public_suffix_is_never_an_organizational_domain
    resolver = resolver_for(record("p=reject", at: "co.uk"))
    result = MailAuth::Dmarc.check(header_from: "bar.co.uk", spf: nil, dkim: nil, resolver: resolver)

    assert_equal MailAuth::Status::NONE, result.status
    assert_equal [ [ "_dmarc.bar.co.uk", :txt ] ], resolver.queries
  end

  def test_relaxed_alignment_spans_a_multi_label_suffix
    result = check("bar.co.uk", record("p=reject", at: "bar.co.uk"), dkim: dkim_pass("mail.bar.co.uk"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  # The trap label-counting falls into: bar.co.uk and attacker.co.uk would
  # both reduce to co.uk, aligning every UK domain with every other.
  def test_two_domains_under_the_same_multi_label_suffix_do_not_align
    result = check("bar.co.uk", record("p=reject", at: "bar.co.uk"), dkim: dkim_pass("attacker.co.uk"))

    assert_equal MailAuth::Status::FAIL, result.status
  end

  def test_relaxed_alignment_spans_a_com_au_suffix
    result = check("shop.bar.com.au", record("p=reject", at: "bar.com.au"), spf: spf_pass("mail.bar.com.au"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  def test_two_domains_under_com_au_do_not_align
    result = check("bar.com.au", record("p=reject", at: "bar.com.au"), spf: spf_pass("attacker.com.au"))

    assert_equal MailAuth::Status::FAIL, result.status
  end

  # DKIM alignment

  def test_relaxed_dkim_alignment_accepts_a_subdomain_signature
    result = check("example.com", record("p=reject"), dkim: dkim_pass("mail.example.com"))

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal({ dkim: true, spf: false }, result.alignment)
  end

  def test_relaxed_is_the_default_when_adkim_is_absent_or_unknown
    [ "p=reject", "p=reject; adkim=r", "p=reject; adkim=bogus" ].each do |tags|
      result = check("example.com", record(tags), dkim: dkim_pass("mail.example.com"))

      assert_equal MailAuth::Status::PASS, result.status, tags
    end
  end

  # The bug this test exists to prove absent: strict must not fall through to
  # relaxed once the exact comparison misses.
  def test_strict_dkim_alignment_rejects_a_subdomain_signature
    result = check("example.com", record("p=reject; adkim=s"), dkim: dkim_pass("mail.example.com"))

    assert_equal MailAuth::Status::FAIL, result.status
    assert_equal({ dkim: false, spf: false }, result.alignment)
  end

  def test_strict_dkim_alignment_rejects_a_parent_domain_signature
    result = check("mail.example.com", record("p=reject; adkim=s", at: "mail.example.com"),
      dkim: dkim_pass("example.com"))

    assert_equal MailAuth::Status::FAIL, result.status
  end

  def test_strict_dkim_alignment_accepts_the_exact_domain
    result = check("example.com", record("p=reject; adkim=s"), dkim: dkim_pass("example.com"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  def test_strict_dkim_alignment_is_matched_case_insensitively
    result = check("example.com", record("p=reject; ADKIM=S"), dkim: dkim_pass("Example.COM"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  def test_a_passing_signature_for_an_unrelated_domain_does_not_align
    result = check("example.com", record("p=reject"), dkim: dkim_pass("mailer.example.net"))

    assert_equal MailAuth::Status::FAIL, result.status
    assert_equal({ dkim: false, spf: false }, result.alignment)
  end

  def test_an_aligned_signature_that_did_not_verify_does_not_align
    signatures = [ MailAuth::Signature.new(status: MailAuth::Status::FAIL, domain: "example.com") ]
    result = check("example.com", record("p=reject"), dkim: MailAuth::DkimResult.new(signatures: signatures))

    assert_equal MailAuth::Status::FAIL, result.status
  end

  def test_one_aligned_signature_among_several_is_enough
    result = check("example.com", record("p=reject"), dkim: dkim_pass("forwarder.example.net", "example.com"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  # SPF alignment

  def test_relaxed_spf_alignment_accepts_a_subdomain_envelope
    result = check("example.com", record("p=reject"), spf: spf_pass("bounces.example.com"))

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal({ dkim: false, spf: true }, result.alignment)
  end

  def test_strict_spf_alignment_rejects_a_subdomain_envelope
    result = check("example.com", record("p=reject; aspf=s"), spf: spf_pass("bounces.example.com"))

    assert_equal MailAuth::Status::FAIL, result.status
  end

  def test_strict_spf_alignment_accepts_the_exact_domain
    result = check("example.com", record("p=reject; aspf=s"), spf: spf_pass("example.com"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  def test_an_aligned_domain_that_did_not_pass_spf_does_not_align
    spf = MailAuth::SpfResult.new(status: MailAuth::Status::SOFTFAIL, domain: "example.com")
    result = check("example.com", record("p=reject"), spf: spf)

    assert_equal MailAuth::Status::FAIL, result.status
  end

  # The two modes are set independently, and one strict tag must not tighten the
  # other.
  def test_adkim_and_aspf_are_independent
    strict_dkim = check("example.com", record("p=reject; adkim=s; aspf=r"),
      dkim: dkim_pass("mail.example.com"), spf: spf_pass("bounces.example.com"))

    assert_equal MailAuth::Status::PASS, strict_dkim.status
    assert_equal({ dkim: false, spf: true }, strict_dkim.alignment)

    strict_spf = check("example.com", record("p=reject; adkim=r; aspf=s"),
      dkim: dkim_pass("mail.example.com"), spf: spf_pass("bounces.example.com"))

    assert_equal MailAuth::Status::PASS, strict_spf.status
    assert_equal({ dkim: true, spf: false }, strict_spf.alignment)
  end

  # Verdict

  def test_dkim_aligned_alone_passes
    result = check("example.com", record("p=reject"), dkim: dkim_pass("example.com"), spf: spf_pass("example.net"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  def test_spf_aligned_alone_passes
    result = check("example.com", record("p=reject"), dkim: dkim_pass("example.net"), spf: spf_pass("example.com"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  def test_neither_aligned_fails
    result = check("example.com", record("p=reject"), dkim: dkim_pass("example.net"), spf: spf_pass("example.org"))

    assert_equal MailAuth::Status::FAIL, result.status
  end

  def test_the_from_domain_is_compared_case_insensitively
    result = check("Example.COM", record("p=reject"), dkim: dkim_pass("example.com"))

    assert_equal MailAuth::Status::PASS, result.status
  end

  # pct

  def test_pct_defaults_to_one_hundred
    assert_equal 100, check("example.com", record("p=reject")).pct
  end

  def test_pct_is_parsed
    assert_equal 20, check("example.com", record("p=reject; pct=20")).pct
  end

  def test_a_nonsense_pct_falls_back_to_one_hundred
    assert_equal 100, check("example.com", record("p=reject; pct=most")).pct
  end

  # Sampling is a consumer's decision: pct=0 asks us to act on none of the
  # failures, but the message still failed, and the result says so.
  def test_pct_is_never_applied_to_the_verdict
    result = check("example.com", record("p=reject; pct=0"), dkim: dkim_pass("example.net"))

    assert_equal MailAuth::Status::FAIL, result.status
    assert_equal 0, result.pct
    assert_equal "reject", result.policy
  end

  private
    def check(header_from, zone, spf: nil, dkim: nil)
      MailAuth::Dmarc.check(header_from: header_from, spf: spf, dkim: dkim, resolver: resolver_for(zone))
    end

    def record(tags, at: "example.com")
      zone("_dmarc.#{at}" => [ "v=DMARC1; #{tags}" ])
    end

    def zone(records = {})
      records.transform_values { |txt| { txt: txt } }
    end

    def spf_pass(domain)
      MailAuth::SpfResult.new(status: MailAuth::Status::PASS, domain: domain)
    end

    def dkim_pass(*domains)
      signatures = domains.map { |domain| MailAuth::Signature.new(status: MailAuth::Status::PASS, domain: domain) }

      MailAuth::DkimResult.new(signatures: signatures)
    end
end
