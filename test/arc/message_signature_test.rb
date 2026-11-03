require "test_helper"

class MailAuth::Arc::MessageSignatureTest < MailAuth::TestCase
  CRLF = "\r\n".b

  def test_body_length_tag_past_the_body_is_permerror
    signature = verify(message_with("d=a.example; h=from; l=99999999999999999999999")).message_signature

    assert_equal MailAuth::Status::PERMERROR, signature.status
    assert_equal "l= exceeds the body length", signature.comment
  end

  def test_a_signing_domain_that_is_no_host_name_is_permerror
    forged = "bank.example\\.attacker.example"
    message = message_with("d=#{forged}; h=from", seal_domain: forged)

    assert_equal "invalid d= tag", verify(message).message_signature.comment
    assert_equal "invalid d= tag",
      MailAuth::Arc::Seal.new(MailAuth::Arc::Chain.new(message).ordered, resolver: resolver_for({})).result.comment
  end

  private
    def message_with(tags, seal_domain: "a.example")
      MailAuth::Message.new [ "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=#{seal_domain}; s=s; b=x",
        "ARC-Message-Signature: i=1; a=rsa-sha256; s=s; bh=x; b=x; #{tags}",
        "ARC-Authentication-Results: i=1; mx.example; none",
        "From: ceo@bank.example", "", "x", "" ].join(CRLF)
    end

    def verify(message)
      MailAuth::Arc.verify(message, resolver: resolver_for({})).sets.last
    end
end
