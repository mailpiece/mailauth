require "test_helper"

class MailAuth::DkimCanonicalizationTest < MailAuth::TestCase
  CRLF = "\r\n".b

  def test_relaxed_body_collapses_whitespace_and_strips_line_ends
    assert_equal "We lost the game.\r\n", body("We  lost \t the game. \r\n", "relaxed")
  end

  def test_relaxed_body_drops_trailing_empty_lines
    assert_equal "abc\r\n", body("abc\r\n\r\n\r\n", "relaxed")
  end

  def test_relaxed_body_terminates_an_unterminated_final_line
    assert_equal "abc\r\n", body("abc", "relaxed")
    assert_equal "abc\r\n", body("abc \t ", "relaxed")
  end

  # Errata 1377: nothing but whitespace is nothing at all — not one CRLF.
  def test_relaxed_body_of_only_whitespace_is_empty
    assert_equal "", body("", "relaxed")
    assert_equal "", body("   ", "relaxed")
    assert_equal "", body("\r\n\r\n", "relaxed")
    assert_equal "", body(" \t \r\n \r\n", "relaxed")
  end

  def test_simple_body_reduces_trailing_line_ends_to_one_and_keeps_whitespace
    assert_equal "We  lost \r\n", body("We  lost \r\n\r\n\r\n", "simple")
  end

  # RFC 6376 §3.4.3: a simple empty body is a single CRLF, never nothing.
  def test_simple_body_of_nothing_is_one_line_end
    assert_equal CRLF, body("", "simple")
    assert_equal CRLF, body("\r\n\r\n", "simple")
  end

  def test_bare_line_feeds_canonicalize_as_their_signer_intended_once_normalized
    message = MailAuth::Message.new("From: a@example.com\n\nabc\n\n\n")

    assert_equal "abc\r\n", body(message.body, "relaxed")
  end

  def test_relaxed_field_lowercases_unfolds_and_collapses
    assert_equal "subject:Is dinner ready?", field("SUBJECT \t : Is  dinner\r\n\tready? \r\n", "relaxed")
  end

  def test_simple_field_only_chomps_the_terminator
    assert_equal "SUBJECT : Is  dinner ready? ", field("SUBJECT : Is  dinner ready? \r\n", "simple")
  end

  # The worked example in RFC 6376 §3.4.6, byte for byte.
  def test_the_rfc_worked_example
    assert_equal "a:X", field("A: X\r\n", "relaxed")
    assert_equal "b:Y Z", field("B : Y\t\r\n\tZ  \r\n", "relaxed")
    assert_equal " C\r\nD E\r\n", body(" C \r\nD \t E\r\n\r\n\r\n", "relaxed")

    assert_equal "A: X", field("A: X\r\n", "simple")
    assert_equal "B : Y\t\r\n\tZ  ", field("B : Y\t\r\n\tZ  \r\n", "simple")
    assert_equal " C \r\nD \t E\r\n", body(" C \r\nD \t E\r\n\r\n\r\n", "simple")
  end

  private
    def body(bytes, form)
      MailAuth::Dkim::Canonicalization.body(bytes.b, form)
    end

    def field(text, form)
      MailAuth::Dkim::Canonicalization.field(text.b, form)
    end
end
