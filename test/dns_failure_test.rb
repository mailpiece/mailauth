require "test_helper"
require "mailresolver/testing"

# End-to-end through a real nameserver: FakeResolver can raise ServerFailure on
# request, so call-site tests stay green even when the default resolver never
# would. These cases hold that seam.
class MailAuth::DnsFailureTest < MailAuth::TestCase
  LocalNameserver = MailResolver::Testing::LocalNameserver

  DOMAIN = "football.example.com"
  SENDER = "joe@#{DOMAIN}"
  MTA = "mx.example.net"
  PERMITTED_IP = "213.165.64.12"
  SIGNED_AT = Time.at(1528637909)

  def test_spf_is_temperror_when_the_nameserver_fails
    LocalNameserver.answering(:servfail) do |resolver|
      result = spf(resolver)

      assert_equal MailAuth::Status::TEMPERROR, result.status, result.comment
    end
  end

  # `none` here would assert the domain designates nothing — a claim nobody made.
  def test_spf_never_claims_a_domain_permits_nothing_on_a_failed_lookup
    LocalNameserver.answering(:servfail) do |resolver|
      refute_match(/does not designate/, spf(resolver).comment.to_s)
    end
  end

  def test_spf_is_temperror_when_the_nameserver_refuses
    LocalNameserver.answering(:refused) do |resolver|
      result = spf(resolver)

      assert_equal MailAuth::Status::TEMPERROR, result.status, result.comment
    end
  end

  def test_dmarc_is_temperror_when_the_nameserver_fails
    LocalNameserver.answering(:servfail) do |resolver|
      result = MailAuth::Dmarc.check(header_from: "example.com", spf: nil, dkim: nil, resolver: resolver)

      assert_equal MailAuth::Status::TEMPERROR, result.status
      refute_equal MailAuth::Status::NONE, result.status
    end
  end

  def test_dmarc_is_temperror_when_the_nameserver_refuses
    LocalNameserver.answering(:refused) do |resolver|
      result = MailAuth::Dmarc.check(header_from: "example.com", spf: nil, dkim: nil, resolver: resolver)

      assert_equal MailAuth::Status::TEMPERROR, result.status
    end
  end

  def test_dkim_is_temperror_when_the_nameserver_fails
    LocalNameserver.answering(:servfail) do |resolver|
      result = verify(resolver)

      assert_equal MailAuth::Status::TEMPERROR, result.status
      refute_equal MailAuth::Status::PERMERROR, result.status
    end
  end

  def test_authenticate_carries_the_failure_through_every_check
    LocalNameserver.answering(:servfail) do |resolver|
      result = authenticate(resolver)

      assert_equal MailAuth::Status::TEMPERROR, result.iprev.status
      assert_equal MailAuth::Status::TEMPERROR, result.spf.status
      assert_equal MailAuth::Status::TEMPERROR, result.dkim.status
      assert_equal MailAuth::Status::TEMPERROR, result.dmarc.status
    end
  end

  def test_a_name_that_does_not_exist_is_still_absence
    LocalNameserver.answering(:nxdomain) do |resolver|
      assert_equal MailAuth::Status::NONE, spf(resolver).status
      assert_equal MailAuth::Status::NONE, MailAuth::Dmarc.check(header_from: "example.com", spf: nil, dkim: nil, resolver: resolver).status
      assert_equal MailAuth::Status::PERMERROR, verify(resolver).status
    end
  end

  # NOERROR with an empty answer (NODATA) is absence, like NXDOMAIN.
  def test_a_name_with_no_record_of_that_type_is_still_absence
    LocalNameserver.answering(:noerror) do |resolver|
      assert_equal MailAuth::Status::NONE, spf(resolver).status
      assert_equal MailAuth::Status::NONE, MailAuth::Dmarc.check(header_from: "example.com", spf: nil, dkim: nil, resolver: resolver).status
    end
  end

  private
    def spf(resolver)
      MailAuth::Spf.check(ip: "192.0.2.1", helo: "mail.example.net",
        mail_from: "sender@example.com", resolver: resolver)
    end

    def verify(resolver)
      MailAuth::Dkim.verify(MailAuth::Message.new(fixture("signed.eml")), resolver: resolver, now: SIGNED_AT + 3600)
    end

    def authenticate(resolver)
      MailAuth.authenticate(fixture("signed.eml"), ip: PERMITTED_IP, helo: MTA,
        mail_from: SENDER, mta: MTA, resolver: resolver, now: SIGNED_AT + 3600)
    end
end
