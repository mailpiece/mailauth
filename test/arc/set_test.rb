require "test_helper"

class MailAuth::Arc::SetTest < MailAuth::TestCase
  def test_claimed_reads_the_method_opening_each_resinfo
    assert_equal({ "spf" => "pass", "dkim" => "pass", "dmarc" => "fail" },
      claimed("mx.example; spf=pass smtp.mailfrom=a.example; dkim/1=pass header.d=a.example; dmarc = fail"))
  end

  def test_claimed_ignores_comments_quoted_strings_and_properties
    claims = claimed("lists.example.org; iprev=pass (dmarc=pass.attacker.example) policy.iprev=1.2.3.4; " \
      "spf=fail (domain of dmarc=pass@bank.example (nested \\) dmarc=pass) does not designate) " \
      "smtp.mailfrom=\"dmarc=pass; arc=pass\"; dkim=permerror header.a=dmarc=pass; dmarc=fail header.from=bank.example")

    assert_equal({ "iprev" => "pass", "spf" => "fail", "dkim" => "permerror", "dmarc" => "fail" }, claims)
  end

  def test_claimed_skips_the_authserv_id_and_keeps_the_first_of_a_method
    assert_equal({ "dmarc" => "fail" }, claimed("dmarc=pass; dmarc=fail; dmarc=pass"))
  end

  def test_claimed_drops_whatever_follows_an_unclosed_comment
    assert_equal({ "spf" => "fail" }, claimed("mx.example; spf=fail (open; dmarc=pass"))
  end

  private
    def claimed(payload)
      set = MailAuth::Arc::Set.new(1)
      set.add(:authentication_results, "ARC-Authentication-Results: i=1; #{payload}")
      set.claimed
    end
end
