require "test_helper"
require "json"
require "openssl"

class MailAuth::DkimSigningTest < MailAuth::TestCase
  CRLF = "\r\n".b
  DOMAIN = "football.example.com"

  # The instant the RFC 8463 sample message was signed, so t= matches.
  SIGNED_AT = Time.at(1528637909)

  UNSIGNED = [
    "From: Joe SixPack <joe@football.example.com>",
    "To: Suzie Q <suzie@shopping.example.net>",
    "Subject: Is dinner ready?",
    "",
    "Hi.",
    "",
    "We lost the game.  Are you hungry yet?",
    "",
    "Joe.",
    ""
  ].join(CRLF).freeze

  test_directory = File.expand_path("../fixtures", __dir__)
  RSA_KEY = OpenSSL::PKey.read(File.binread(File.join(test_directory, "private-rsa.key")))
  ED25519_KEY = OpenSSL::PKey.new_raw_private_key("ED25519", File.binread(File.join(test_directory, "private-ec.key")).strip.unpack1("m"))

  # Both algorithms are deterministic, so signing the RFC 8463 Appendix A
  # message over its own h= and tags must reproduce its published b= byte for
  # byte — an authority outside this gem.
  def test_rfc8463_signatures_reproduce_byte_for_byte_from_the_published_keys
    message = MailAuth::Message.new(fixture("signed.eml"))

    signature_fields(message).each do |field, tags|
      published = tags["b"].gsub(/[ \t\r\n]+/n, "").unpack1("m")

      assert_equal published, resign(message, field, tags), tags["a"]
    end
  end

  def test_rfc8463_body_hash_reproduces_the_published_value
    message = MailAuth::Message.new(fixture("signed.eml"))
    digest = OpenSSL::Digest::SHA256.digest(MailAuth::Dkim::Canonicalization.body(message.body, "relaxed"))

    assert_equal "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=", [ digest ].pack("m0")
  end

  def test_rsa_signed_message_verifies
    result = verify(sign)

    assert_equal MailAuth::Status::PASS, result.status
    signature = result.signatures.first
    assert_equal "rsa-sha256", signature.algorithm
    assert_equal "relaxed/relaxed", signature.canonicalization
    assert_equal DOMAIN, signature.domain
    assert_equal "test", signature.selector
    assert signature.aligned
  end

  def test_ed25519_signed_message_verifies
    result = verify(sign(key: ED25519_KEY, selector: "brisbane"))

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal "ed25519-sha256", result.signatures.first.algorithm
  end

  def test_tampered_body_fails
    assert_equal MailAuth::Status::FAIL, verify(sign.sub("We lost", "We won")).status
  end

  def test_tampered_signed_header_fails
    assert_equal MailAuth::Status::FAIL, verify(sign.sub("Subject: Is dinner ready?", "Subject: Is dinner served?")).status
  end

  # The oversigned names forbid what the message doesn't carry: Reply-To was
  # never present, so a first instance added in transit must read as forgery.
  def test_header_added_after_signing_breaks_the_signature
    signed = sign

    assert_equal MailAuth::Status::PASS, verify(signed).status
    assert_equal MailAuth::Status::FAIL, verify("Reply-To: attacker@evil.example\r\n" + signed).status
  end

  def test_every_present_instance_of_a_signed_header_is_covered
    doubled = "X-Trace: upper\r\nX-Trace: lower\r\n" + UNSIGNED
    signed = sign(raw: doubled, headers: %w[ from x-trace ])

    assert_includes signed, "h=x-trace:x-trace:from:"
    assert_equal MailAuth::Status::PASS, verify(signed).status
    assert_equal MailAuth::Status::FAIL, verify(signed.sub("X-Trace: upper", "X-Trace: rewritten")).status
    assert_equal MailAuth::Status::FAIL, verify(signed.sub("X-Trace: lower", "X-Trace: rewritten")).status
  end

  def test_field_alone_carries_the_signature_for_composition
    field = MailAuth::Dkim::Signer.new(UNSIGNED, domain: DOMAIN, selector: "test", key: RSA_KEY, now: SIGNED_AT).field

    assert field.start_with?("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;")
    assert field.end_with?(CRLF)
    assert_equal MailAuth::Status::PASS, verify(field + UNSIGNED).status
  end

  def test_signs_at_the_given_instant
    assert_includes sign, "t=#{SIGNED_AT.to_i};"
  end

  def test_expiration_is_written_and_enforced
    signed = sign(expires_in: 3600)

    assert_includes signed, "x=#{SIGNED_AT.to_i + 3600};"
    assert_equal MailAuth::Status::PASS, verify(signed, now: SIGNED_AT + 60).status
    assert_equal MailAuth::Status::FAIL, verify(signed, now: SIGNED_AT + 7200).status
  end

  def test_no_expiration_by_default
    refute_includes sign, "x="
  end

  def test_internationalized_domain_and_selector_are_signed_as_a_labels
    signed = MailAuth::Dkim::Signer.new(UNSIGNED, domain: "fußball.example.com", selector: "münchen", key: RSA_KEY, now: SIGNED_AT).field

    assert_match(/d=xn--[a-z0-9-]+\.example\.com;/, signed)
    assert_match(/s=xn--[a-z0-9-]+; /, signed)
  end

  def test_unsupported_key_type_is_refused
    error = assert_raises(ArgumentError) do
      MailAuth::Dkim.sign(UNSIGNED, domain: DOMAIN, selector: "test", key: OpenSSL::PKey::EC.generate("prime256v1"))
    end

    assert_match(/unsupported key type/, error.message)
  end

  def test_leaving_from_unsigned_is_refused
    assert_raises(ArgumentError) do
      MailAuth::Dkim.sign(UNSIGNED, domain: DOMAIN, selector: "test", key: RSA_KEY, headers: %w[ to ], oversign: [])
    end
  end

  # RFC 6376 §5.4 asks for From in h=, which oversigning provides; a From the
  # message does carry is then covered even when it isn't in headers:.
  def test_from_outside_the_signed_list_is_still_covered_through_oversigning
    signed = sign(headers: %w[ to subject ])

    assert_equal MailAuth::Status::PASS, verify(signed).status
    assert_equal MailAuth::Status::FAIL, verify(signed.sub("From: Joe", "From: Moe")).status
  end

  def test_an_rsa_key_the_verifier_would_reject_is_refused
    error = assert_raises(ArgumentError) do
      MailAuth::Dkim.sign(UNSIGNED, domain: DOMAIN, selector: "test", key: OpenSSL::PKey::RSA.new(512))
    end

    assert_match(/shorter than/, error.message)
  end

  # A name oversigned but not signed gets covered once when present — its
  # count in h= equals its occurrences, so a later addition goes unnoticed.
  def test_an_oversigned_name_outside_the_signed_list_is_covered_only_once
    dated = "Date: Thu, 14 Jan 2015 15:00:01 -0800\r\n" + UNSIGNED
    signed = sign(raw: dated, headers: %w[ from to subject ])

    assert_equal 1, signed[/(?<!b)h=[^;]+/].scan("date").count
    assert_equal MailAuth::Status::PASS, verify("Date: Thu, 1 Apr 2021 00:00:00 -0800\r\n" + signed).status
  end

  def test_eight_bit_body_round_trips
    body = "Dîner: \xE9t\xE9. Ready? \xC3\xA9\xF0\x9F\x8D\x95\r\n".b
    raw = "From: joe@#{DOMAIN}\r\n\r\n" + body

    assert_equal MailAuth::Status::PASS, verify(sign(raw: raw)).status
  end

  private
    def sign(raw: UNSIGNED, key: RSA_KEY, selector: key.equal?(RSA_KEY) ? "test" : "brisbane", **options)
      MailAuth::Dkim.sign(raw, domain: DOMAIN, selector:, key:, now: SIGNED_AT, **options)
    end

    def verify(raw, now: SIGNED_AT + 60)
      MailAuth::Dkim.verify(MailAuth::Message.new(raw), resolver: resolver_for(zone_from_fixture), now:)
    end

    def zone_from_fixture
      JSON.parse(fixture("dns.json")).transform_values do |types|
        types.to_h { |type, records| [ type.downcase.to_sym, records.map(&:join) ] }
      end
    end

    def signature_fields(message)
      message.fields_named("dkim-signature").map do |field|
        [ field, MailAuth::Dkim.parse_tags(field.split(":", 2).last) ]
      end
    end

    # The Appendix A layout carries tags our signer doesn't emit (i=, q=), so
    # the reconstruction follows the fixture's own h= and field — through the
    # same canonicalization and the same two signing calls the Signer uses.
    def resign(message, field, tags)
      data = select_fields(message, tags["h"].gsub(/[ \t\r\n]+/n, "").downcase.split(":"))
        .map { |signed| MailAuth::Dkim::Canonicalization.field(signed, "relaxed") + CRLF }.join +
        MailAuth::Dkim::Canonicalization.field(field, "relaxed").sub(/([;:\s]+b=)[^;]*/n, '\1')

      if tags["a"] == "ed25519-sha256"
        ED25519_KEY.sign(nil, OpenSSL::Digest::SHA256.digest(data))
      else
        RSA_KEY.sign(OpenSSL::Digest::SHA256.new, data)
      end
    end

    def select_fields(message, names)
      remaining = message.fields.dup

      names.filter_map do |name|
        if index = remaining.rindex { |field| message.field_name(field) == name }
          remaining.delete_at(index)
        end
      end
    end
end
