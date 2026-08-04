require "test_helper"
require "json"
require "openssl"

class MailAuth::DkimTest < MailAuth::TestCase
  CRLF = "\r\n".b
  DOMAIN = "football.example.com"

  # The RFC 8463 sample message is signed at this instant; everything we check
  # against it is measured from just after.
  SIGNED_AT = Time.at(1528637909)

  HEADERS = [
    "From: Joe SixPack <joe@football.example.com>",
    "To: Suzie Q <suzie@shopping.example.net>",
    "Subject: Is dinner ready?"
  ].freeze

  BODY = "Hi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n".b

  test_directory = File.expand_path("../fixtures", __dir__)
  RSA_KEY = OpenSSL::PKey.read(File.binread(File.join(test_directory, "private-rsa.key")))
  ED25519_KEY = OpenSSL::PKey.new_raw_private_key("ED25519", File.binread(File.join(test_directory, "private-ec.key")).strip.unpack1("m"))

  def test_rfc8463_sample_verifies_both_signatures
    result = verify(fixture("signed.eml"))

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal 2, result.signatures.length
    assert_equal [ MailAuth::Status::PASS, MailAuth::Status::PASS ], result.signatures.map(&:status)
    assert_equal %w[ ed25519-sha256 rsa-sha256 ], result.signatures.map(&:algorithm)
    assert_equal %w[ brisbane test ], result.signatures.map(&:selector)
    assert_equal [ DOMAIN, DOMAIN ], result.signatures.map(&:domain)
    assert result.signatures.all?(&:aligned)
    assert_equal [ DOMAIN ], result.passing_domains.uniq
  end

  def test_unsigned_message_is_none
    result = verify(HEADERS.join(CRLF) + CRLF + CRLF + BODY)

    assert_equal MailAuth::Status::NONE, result.status
    assert_equal 1, result.signatures.length
    assert_equal "message not signed", result.signatures.first.comment
  end

  def test_tampered_body_fails_on_the_body_hash
    result = verify(fixture("signed.eml").sub("We lost the game", "We won the game"))

    assert_equal MailAuth::Status::FAIL, result.status
    assert_equal [ "body hash did not verify" ], result.signatures.map(&:comment).uniq
  end

  def test_tampered_signed_header_fails_the_signature
    result = verify(fixture("signed.eml").sub("Subject: Is dinner ready?", "Subject: Is dinner served?"))

    assert_equal MailAuth::Status::FAIL, result.status
    assert_equal [ "bad signature" ], result.signatures.map(&:comment).uniq
  end

  def test_missing_key_is_permerror
    result = verify(fixture("signed.eml"), resolver: resolver_for({}))

    assert_equal MailAuth::Status::PERMERROR, result.status
    assert_equal "no key for test._domainkey.#{DOMAIN}", result.signatures.last.comment
  end

  def test_dns_timeout_is_temperror
    zone = zone_from_fixture.transform_values { { txt: :timeout } }

    assert_equal MailAuth::Status::TEMPERROR, verify(fixture("signed.eml"), resolver: resolver_for(zone)).status
  end

  def test_rsa_key_shorter_than_1024_bits_is_rejected
    short_key = OpenSSL::PKey::RSA.generate(512)
    result = verify(signed, resolver: resolver_for(zone_publishing("v=DKIM1; k=rsa; p=#{[ short_key.public_to_der ].pack("m0")}")))

    assert_equal MailAuth::Status::PERMERROR, result.status
    assert_equal "rsa key shorter than 1024 bits", result.signatures.first.comment
  end

  def test_unreadable_key_is_permerror
    result = verify(signed, resolver: resolver_for(zone_publishing("v=DKIM1; k=rsa; p=bm90LWEta2V5")))

    assert_equal "unreadable public key", result.signatures.first.comment
  end

  def test_revoked_key_is_permerror
    result = verify(signed, resolver: resolver_for(zone_publishing("v=DKIM1; k=rsa; p=")))

    assert_equal "key revoked", result.signatures.first.comment
  end

  def test_expired_signature_fails
    message = signed(tags: { "t" => SIGNED_AT.to_i, "x" => SIGNED_AT.to_i + 60 })

    assert_equal MailAuth::Status::PASS, verify(message, now: SIGNED_AT + 30).status
    assert_equal MailAuth::Status::FAIL, verify(message, now: SIGNED_AT + 120).status
    assert_equal "signature expired", verify(message, now: SIGNED_AT + 120).signatures.first.comment
  end

  def test_signature_from_the_future_fails
    message = signed(tags: { "t" => (SIGNED_AT + 7200).to_i })

    assert_equal "signature timestamp in the future", verify(message).signatures.first.comment
  end

  def test_every_canonicalization_combination_verifies
    %w[ simple relaxed ].product(%w[ simple relaxed ]).each do |header, body|
      canonicalization = "#{header}/#{body}"

      # Both canonicalizations must survive this — simple by preserving the
      # folded header and whitespace, relaxed by removing them.
      message = signed(canonicalization:,
        headers: HEADERS + [ "X-Long: one\r\n two\tthree" ], body: "Hi. \r\n\r\nWe  lost.\r\n")

      assert_equal MailAuth::Status::PASS, verify(message).status, canonicalization
      assert_equal canonicalization, verify(message).signatures.first.canonicalization
    end
  end

  def test_ed25519_signature_verifies
    result = verify(signed(algorithm: "ed25519-sha256", selector: "brisbane"))

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal "ed25519-sha256", result.signatures.first.algorithm
  end

  def test_relaxed_body_survives_whitespace_a_relay_rewrote
    message = signed(canonicalization: "relaxed/relaxed", body: "We  lost the game.\r\n")
    relayed = message.sub("We  lost the game.\r\n", "We\tlost the game.   \r\n\r\n\r\n")

    assert_equal MailAuth::Status::PASS, verify(relayed).status
  end

  # RFC 6376 §3.4.4 a.1 ignores whitespace at the end of every line, and the
  # last line of a body is a line whether or not a CRLF terminates it. Leave
  # its trailing whitespace in place and a signature the signer computed over
  # the stripped bytes reads as forged.
  def test_relaxed_body_strips_whitespace_from_an_unterminated_final_line
    message = signed(canonicalization: "relaxed/relaxed", body: "abc\r\n")

    assert_equal MailAuth::Status::PASS, verify(message.sub(/abc\r\n\z/, "abc   ")).status
    assert_equal MailAuth::Status::PASS, verify(message.sub(/abc\r\n\z/, "abc\t")).status
    assert_equal MailAuth::Status::PASS, verify(message.sub(/abc\r\n\z/, "abc \t \t")).status
  end

  # The terminated case has to keep working: it is the one the old rule got
  # right, and every real signature depends on it.
  def test_relaxed_body_still_strips_whitespace_from_a_terminated_final_line
    message = signed(canonicalization: "relaxed/relaxed", body: "abc\r\n")

    assert_equal MailAuth::Status::PASS, verify(message.sub(/abc\r\n\z/, "abc \r\n")).status
    assert_equal MailAuth::Status::PASS, verify(message.sub(/abc\r\n\z/, "abc\t\t\r\n\r\n")).status
  end

  # Nothing but whitespace is nothing at all, terminated or not.
  def test_a_relaxed_body_of_only_whitespace_is_empty
    assert_equal MailAuth::Status::PASS, verify(signed(canonicalization: "relaxed/relaxed", body: "", append: "   ")).status
  end

  def test_simple_body_does_not_survive_the_same_rewrite
    message = signed(canonicalization: "simple/simple", body: "We  lost the game.\r\n")
    relayed = message.sub("We  lost the game.\r\n", "We\tlost the game.   \r\n")

    assert_equal MailAuth::Status::FAIL, verify(relayed).status
    assert_equal "body hash did not verify", verify(relayed).signatures.first.comment
  end

  # The hazard is Ruby's, not DKIM's: read this body as UTF-8 anywhere along
  # the way and its byte count — and so its hash — changes.
  def test_eight_bit_body_verifies
    body = "Dîner: \xE9t\xE9. Ready? \xC3\xA9\xF0\x9F\x8D\x95\r\n".b

    assert_equal Encoding::BINARY, body.encoding
    assert_equal MailAuth::Status::PASS, verify(signed(body:)).status
  end

  def test_body_length_tag_signs_only_a_prefix
    appended = "\r\nAnd here is a footer nobody signed.\r\n".b
    message = signed(body: BODY, body_limit: true, append: appended)

    signature = verify(message).signatures.first
    assert_equal MailAuth::Status::PASS, signature.status
    assert_equal appended.bytesize, signature.under_sized
  end

  # h= is walked bottom-up, so a name listed once covers the *lowest* instance
  # of that header and a name listed twice walks up to the one above it.
  def test_duplicate_header_names_are_taken_from_the_bottom_up
    headers = [ HEADERS.first, "X-Trace: upper", "X-Trace: lower" ]
    message = signed(headers:, signed_names: %w[ from x-trace ])

    assert_equal MailAuth::Status::PASS, verify(message).status
    assert_equal MailAuth::Status::PASS, verify(message.sub("X-Trace: upper", "X-Trace: rewritten")).status
    assert_equal MailAuth::Status::FAIL, verify(message.sub("X-Trace: lower", "X-Trace: rewritten")).status

    both = signed(headers:, signed_names: %w[ from x-trace x-trace ])
    assert_equal MailAuth::Status::PASS, verify(both).status
    assert_equal MailAuth::Status::FAIL, verify(both.sub("X-Trace: upper", "X-Trace: rewritten")).status
  end

  def test_signature_that_does_not_cover_from_is_permerror
    message = signed(headers: HEADERS, signed_names: %w[ to subject ])

    assert_equal MailAuth::Status::PERMERROR, verify(message).status
    assert_equal "From is not signed", verify(message).signatures.first.comment
  end

  def test_unsupported_algorithm_is_permerror
    message = signed.sub("a=rsa-sha256", "a=rsa-md5")

    assert_equal MailAuth::Status::PERMERROR, verify(message).status
    assert_equal "unsupported algorithm rsa-md5", verify(message).signatures.first.comment
  end

  def test_rsa_sha1_is_permerror
    message = signed.sub("a=rsa-sha256", "a=rsa-sha1")

    assert_equal MailAuth::Status::PERMERROR, verify(message).status
    assert_equal "unsupported algorithm rsa-sha1", verify(message).signatures.first.comment
  end

  def test_signature_not_aligned_with_the_from_domain
    message = signed(headers: [ "From: someone@elsewhere.example" ] + HEADERS.drop(1))

    refute verify(message).signatures.first.aligned
  end

  # Every signature past the ceiling is a DNS lookup a sender got for the price
  # of a header, so the count of queries is the thing under test.
  def test_signatures_past_the_ceiling_cost_no_lookups
    resolver = resolver_for(zone_from_fixture)
    message = signed
    crowd = Array.new(12) { |index| message.lines.first.chomp.sub("s=test;", "s=absent#{index};") }

    result = verify(crowd.join(CRLF) + CRLF + message, resolver: resolver)

    assert_equal MailAuth::Dkim::MAXIMUM_SIGNATURES, resolver.queries.length
    assert_equal MailAuth::Dkim::MAXIMUM_SIGNATURES + 1, result.signatures.length
    assert_equal "3 more signatures not evaluated", result.signatures.last.comment
  end

  private
    def verify(raw, resolver: resolver_for(zone_from_fixture), now: SIGNED_AT + 3600)
      MailAuth::Dkim.verify(MailAuth::Message.new(raw), resolver:, now:)
    end

    # dns.json stores TXT records the way DNS does, as lists of character
    # strings; the resolver hands each record over already joined.
    def zone_from_fixture
      JSON.parse(fixture("dns.json")).transform_values do |types|
        types.to_h { |type, records| [ type.downcase.to_sym, records.map(&:join) ] }
      end
    end

    def zone_publishing(record)
      zone_from_fixture.merge("test._domainkey.#{DOMAIN}" => { txt: [ record ] })
    end

    # Written straight from RFC 6376 rather than shared with the code under
    # test, so a mistake in one doesn't excuse itself in the other.
    def signed(headers: HEADERS, body: BODY, canonicalization: "relaxed/relaxed", algorithm: "rsa-sha256",
      selector: "test", signed_names: nil, tags: {}, body_limit: false, append: "")
      header_canonicalization, body_canonicalization = canonicalization.split("/")
      signed_names ||= headers.map { |field| field.split(":", 2).first.downcase }

      canonical_body = canonicalize_body(body, body_canonicalization)
      tags = tags.merge("l" => canonical_body.bytesize) if body_limit

      field = "DKIM-Signature: v=1; a=#{algorithm}; c=#{canonicalization}; d=#{DOMAIN}; s=#{selector}; " \
        "h=#{signed_names.join(":")}; #{tags.map { |name, value| "#{name}=#{value}; " }.join}" \
        "bh=#{[ OpenSSL::Digest::SHA256.digest(canonical_body) ].pack("m0")}; b="

      data = select_headers(headers, signed_names).map { |header| canonicalize_field(header, header_canonicalization) + CRLF }.join +
        canonicalize_field(field, header_canonicalization)

      signature = sign(data.b, algorithm)
      ([ field + [ signature ].pack("m0") ] + headers).join(CRLF) + CRLF + CRLF + body + append
    end

    # From the signer's side: the last instance of each name in h= that
    # hasn't been used yet.
    def select_headers(headers, signed_names)
      remaining = headers.dup

      signed_names.filter_map do |name|
        if index = remaining.rindex { |header| header.split(":", 2).first.downcase == name }
          remaining.delete_at(index)
        end
      end
    end

    def sign(data, algorithm)
      if algorithm.start_with?("ed25519")
        ED25519_KEY.sign(nil, OpenSSL::Digest::SHA256.digest(data))
      else
        RSA_KEY.sign(OpenSSL::Digest::SHA256.new, data)
      end
    end

    def canonicalize_body(body, canonicalization)
      lines = body.b.split(CRLF, -1)
      lines = lines.map { |line| line.gsub(/[ \t]+/n, " ").sub(/ \z/n, "") } if canonicalization == "relaxed"
      lines.pop while lines.last == ""

      if lines.empty?
        canonicalization == "relaxed" ? "".b : CRLF
      else
        lines.join(CRLF) + CRLF
      end
    end

    def canonicalize_field(field, canonicalization)
      if canonicalization == "relaxed"
        name, value = field.split(":", 2)
        "#{name.strip.downcase}:#{value.gsub(/\r\n/n, "").gsub(/[ \t]+/n, " ").strip}"
      else
        field
      end
    end
end
