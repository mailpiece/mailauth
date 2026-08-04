require "test_helper"

class MailAuth::DomainTest < MailAuth::TestCase
  def test_leaves_an_ascii_domain_alone_but_for_case_and_trailing_dot
    assert_equal "example.com", MailAuth::Domain.normalize(" Example.COM. ")
  end

  def test_converts_a_u_label_to_its_a_label
    assert_equal "xn--mnchen-3ya.example", MailAuth::Domain.normalize("münchen.example")
  end

  def test_an_a_label_is_already_normal
    assert_equal "xn--mnchen-3ya.example", MailAuth::Domain.normalize("XN--MNCHEN-3YA.example")
  end

  def test_both_spellings_of_one_domain_normalize_alike
    assert_equal MailAuth::Domain.normalize("münchen.example"), MailAuth::Domain.normalize("xn--mnchen-3ya.example")
  end

  def test_a_name_punycode_cannot_encode_survives_rather_than_raising
    assert_kind_of String, MailAuth::Domain.normalize("\xff\xfe.example")
  end

  def test_the_same_domain_aligns_however_it_is_spelled
    assert MailAuth::Dmarc::Alignment.aligned?("münchen.example", "xn--mnchen-3ya.example", strict: true)
    assert MailAuth::Dmarc::Alignment.aligned?("mail.münchen.example", "xn--mnchen-3ya.example", strict: false)
  end

  def test_different_internationalized_domains_still_do_not_align
    refute MailAuth::Dmarc::Alignment.aligned?("münchen.example", "xn--brln-loa.example", strict: true)
  end
end
