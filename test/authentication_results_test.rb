require "test_helper"

class MailAuth::AuthenticationResultsTest < MailAuth::TestCase
  def test_states_all_three_results
    header = results(spf: spf, dkim: dkim(signature), dmarc: dmarc, mta: "mx.example.com",
      header_from: "example.com")

    assert_equal "mx.example.com;\r\n" \
      " spf=pass smtp.mailfrom=sender@example.com;\r\n" \
      " dkim=pass header.d=example.com header.s=selector header.a=rsa-sha256;\r\n" \
      " dmarc=pass (p=REJECT) header.from=example.com", header
  end

  def test_a_missing_mta_is_reported_as_unknown
    assert_equal "unknown", results(dmarc: dmarc).split(";").first
  end

  def test_an_authserv_id_that_is_not_a_token_is_quoted
    assert_equal %("mx one.example.com"), results(dmarc: dmarc, mta: "mx one.example.com").split(";").first
  end

  def test_nothing_checked_is_none
    assert_equal "unknown;\r\n none", results
  end

  # Collapsing these would lose which domain the passing signature belonged to.
  def test_one_clause_per_signature
    signatures = %w[ example.com forwarder.example.net example.org ].map do |domain|
      MailAuth::Signature.new(status: MailAuth::Status::PASS, domain: domain, selector: "s")
    end
    header = results(dkim: dkim(*signatures), mta: "mx.example.com")

    assert_equal 3, header.scan("dkim=pass").length
    assert_includes header, "header.d=forwarder.example.net"
  end

  def test_a_result_that_was_not_computed_is_left_out
    header = results(spf: spf, mta: "mx.example.com")

    assert_equal "mx.example.com;\r\n spf=pass smtp.mailfrom=sender@example.com", header
  end

  def test_a_property_without_a_value_is_left_out
    header = results(spf: MailAuth::SpfResult.new(status: MailAuth::Status::NONE), mta: "mx.example.com")

    assert_equal "mx.example.com;\r\n spf=none", header
  end

  def test_a_dmarc_result_without_a_policy_carries_no_comment
    header = results(dmarc: MailAuth::DmarcResult.new(status: MailAuth::Status::NONE), mta: "mx.example.com")

    assert_equal "mx.example.com;\r\n dmarc=none", header
  end

  def test_an_arc_result_names_the_newest_sealer
    header = results(arc: arc(sealer: "lists.example.org"), mta: "mx.example.com")

    assert_equal "mx.example.com;\r\n arc=pass (i=2 d=lists.example.org)", header
  end

  # A sealer is only named when a seal was reached: a chain that failed its
  # structure never verified one.
  def test_an_arc_result_without_a_verified_seal_carries_no_comment
    header = results(arc: arc(sealer: nil, status: MailAuth::Status::FAIL), mta: "mx.example.com")

    assert_equal "mx.example.com;\r\n arc=fail", header
  end

  def test_an_undersized_signature_says_how_much_went_unsigned
    undersized = MailAuth::Signature.new(status: MailAuth::Status::PASS, domain: "example.com", under_sized: 4096)

    assert_includes results(dkim: dkim(undersized)), "(undersized signature: 4096 bytes unsigned)"
  end

  # Quoting

  def test_an_addr_spec_travels_unquoted
    assert_includes results(spf: spf), "smtp.mailfrom=sender@example.com"
  end

  def test_a_value_with_a_special_character_is_quoted
    assert_includes results(spf: spf("sender;drop@example.com")), %(smtp.mailfrom="sender;drop@example.com")
  end

  def test_quotes_and_backslashes_inside_a_quoted_value_are_escaped
    assert_includes results(spf: spf(%(a "quoted\\ name))), %(smtp.mailfrom="a \\"quoted\\\\ name")
  end

  def test_parentheses_and_backslashes_inside_a_comment_are_escaped
    signature = MailAuth::Signature.new(status: MailAuth::Status::FAIL, domain: "example.com",
      comment: "bad signature (rsa) \\ here")

    assert_includes results(dkim: dkim(signature)), "(bad signature \\(rsa\\) \\\\ here)"
  end

  # A CR or LF that survived into a DNS-sourced value would let a remote
  # party append headers of their own.
  def test_line_breaks_are_stripped_from_values
    header = results(spf: spf("example.com\r\nX-Spoofed: yes"), mta: "mx.example.com")

    assert_equal 2, header.split("\r\n").length
    assert_includes header, %(smtp.mailfrom="example.com X-Spoofed: yes")
  end

  def test_line_breaks_are_stripped_from_comments
    signature = MailAuth::Signature.new(status: MailAuth::Status::FAIL, domain: "example.com",
      comment: "broken\r\nX-Spoofed: yes")

    assert_equal 2, results(dkim: dkim(signature)).split("\r\n").length
  end

  # Folding

  def test_long_headers_fold_within_the_line_width
    header = results(spf: spf, dkim: dkim(long_signature), dmarc: dmarc,
      mta: "mx.a-rather-long-hostname.example.com", header_from: "example.com")
    lines = header.split("\r\n")

    assert lines.length > 4, "expected the header to fold"
    assert lines.all? { |line| line.length <= 78 }, lines.map(&:length).inspect
    assert lines.drop(1).all? { |line| line.start_with?(" ") && !line.start_with?("  ") }
  end

  # Folding happens at token boundaries: a comment can carry a space, and
  # breaking one across lines would change what it says.
  def test_a_folded_header_never_breaks_a_comment
    header = results(spf: spf, dkim: dkim(long_signature), dmarc: dmarc, mta: "mx.example.com")

    assert_includes header, "(#{long_signature.comment})"
  end

  private
    def results(spf: nil, dkim: nil, dmarc: nil, arc: nil, mta: nil, header_from: nil)
      MailAuth::AuthenticationResults.new(spf: spf, dkim: dkim, dmarc: dmarc, arc: arc, mta: mta,
        header_from: header_from).to_s
    end

    def spf(domain = "sender@example.com")
      MailAuth::SpfResult.new(status: MailAuth::Status::PASS, domain: domain)
    end

    def dkim(*signatures)
      MailAuth::DkimResult.new(signatures: signatures)
    end

    def arc(sealer:, status: MailAuth::Status::PASS)
      seal = MailAuth::ArcSeal.new(status: status, domain: sealer) if sealer

      MailAuth::ArcResult.new(status: status, sets: [ MailAuth::ArcSet.new(instance: 2, seal: seal) ])
    end

    def signature
      MailAuth::Signature.new(status: MailAuth::Status::PASS, domain: "example.com", selector: "selector",
        algorithm: "rsa-sha256")
    end

    def long_signature
      MailAuth::Signature.new(status: MailAuth::Status::FAIL, domain: "a-long-signing-domain.example.com",
        selector: "an-unusually-long-selector-name", algorithm: "rsa-sha256",
        comment: "body hash did not verify against the signed content")
    end

    def dmarc
      MailAuth::DmarcResult.new(status: MailAuth::Status::PASS, policy: "reject", pct: 100,
        alignment: { dkim: true, spf: true }, record: "v=DMARC1; p=reject")
    end
end
