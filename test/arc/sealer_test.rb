require "test_helper"

class MailAuth::Arc::SealerTest < MailAuth::TestCase
  KEY = OpenSSL::PKey.read(File.binread(File.expand_path("../fixtures/private-rsa.key", __dir__)))

  # Anyone can put ARC headers on a message, so a full chain is no reason to raise.
  def test_a_full_chain_comes_back_unsealed
    [ 50, 999 ].each do |instance|
      raw = "ARC-Seal: i=#{instance}; a=x\r\nFrom: a@a.example\r\n\r\nhi\r\n"
      sealer = MailAuth::Arc::Sealer.new(raw, authentication_results: "mx.example; none", chain_status: "fail",
        domain: "a.example", selector: "s", key: KEY)

      assert sealer.full?
      assert_equal raw, sealer.sealed_message
    end
  end
end
