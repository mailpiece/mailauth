require "test_helper"

class MailAuth::Arc::MessageSignatureTest < MailAuth::TestCase
  CRLF = "\r\n".b

  def test_body_length_tag_past_the_body_is_permerror
    signature = verify_newest("h=from; l=99999999999999999999999")

    assert_equal MailAuth::Status::PERMERROR, signature.status
    assert_equal "l= exceeds the body length", signature.comment
  end

  private
    def verify_newest(tags)
      raw = [ "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=a.example; s=s; b=x",
        "ARC-Message-Signature: i=1; a=rsa-sha256; d=a.example; s=s; bh=x; b=x; #{tags}",
        "ARC-Authentication-Results: i=1; mx.example; none",
        "From: ceo@bank.example", "", "x", "" ].join(CRLF)

      MailAuth::Arc.verify(MailAuth::Message.new(raw), resolver: resolver_for({})).sets.last.message_signature
    end
end
