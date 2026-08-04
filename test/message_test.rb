require "test_helper"

class MailAuth::MessageTest < MailAuth::TestCase
  RAW = "From: Person <a@Example.COM>\nSubject: Hi\n\nBody.\n"

  def test_normalizes_bare_newlines_to_crlf
    assert_equal "From: Person <a@Example.COM>\r\nSubject: Hi\r\n\r\nBody.\r\n", MailAuth::Message.new(RAW).raw
  end

  def test_splits_headers_from_body
    message = MailAuth::Message.new(RAW)
    assert_equal "Body.\r\n", message.body
    assert_equal 2, message.fields.size
  end

  def test_reads_the_from_domain_downcased
    assert_equal "example.com", MailAuth::Message.new(RAW).header_from_domain
  end

  def test_keeps_bytes_binary
    assert_equal Encoding::ASCII_8BIT, MailAuth::Message.new(RAW).raw.encoding
  end

  def test_unfolds_a_folded_header
    message = MailAuth::Message.new("Subject: one\r\n  two\r\nFrom: a@b.com\r\n\r\nx")
    assert_equal 2, message.fields.size
    assert_includes message.fields.first, "two"
  end
end

class MailAuth::HeaderFromTest < MailAuth::TestCase
  # DMARC is measured against this domain, so a quoted display name — which
  # can contain a fake address — must not be able to supply it instead.
  def test_a_quoted_display_name_cannot_supply_the_domain
    assert_equal "example.com", domain_of(%(From: "Foo <evil@attacker.com>" <real@example.com>))
  end

  def test_a_comment_cannot_supply_the_domain
    assert_equal "example.com", domain_of(%(From: Foo (comment@fake.com) <real@example.com>))
  end

  # RFC 7489 §6.6.1: DMARC applies to a single From address. Several is no
  # domain rather than a guess at which one counts.
  def test_several_from_addresses_yield_no_domain
    assert_nil domain_of(%(From: Foo <a@b.com>, Bar <c@d.com>))
  end

  def test_an_ordinary_from_still_reads
    assert_equal "example.com", domain_of("From: Person <a@Example.COM>")
    assert_equal "example.com", domain_of("From: plain@example.com")
  end

  private
    def domain_of(header)
      MailAuth::Message.new("#{header}\r\nSubject: x\r\n\r\nbody").header_from_domain
    end
end

class MailAuth::MultipleFromTest < MailAuth::TestCase
  # DKIM signs the last From (RFC 6376 §5.4.2) and a reader is shown the first,
  # so a second From field lets a signature over the attacker's own domain align
  # against a name nobody sees.
  def test_two_from_fields_yield_no_domain
    raw = "From: CEO <ceo@bank.example>\r\nFrom: attacker@evil.example\r\nSubject: x\r\n\r\nbody"

    assert_nil MailAuth::Message.new(raw).header_from_domain
  end

  def test_one_from_field_still_reads
    raw = "From: CEO <ceo@bank.example>\r\nSubject: x\r\n\r\nbody"

    assert_equal "bank.example", MailAuth::Message.new(raw).header_from_domain
  end
end
