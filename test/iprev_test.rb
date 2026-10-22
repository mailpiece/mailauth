require "test_helper"

class MailAuth::IprevTest < MailAuth::TestCase
  IP = "203.0.113.5"

  def test_a_name_that_resolves_back_passes
    result = check("mail.example.com" => { a: [ IP ] })

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal "mail.example.com", result.name
  end

  def test_the_name_is_reported_as_the_zone_wrote_it_less_the_root
    result = check(IP => { ptr: [ "Mail.Example.COM." ] }, "mail.example.com" => { a: [ IP ] })

    assert_equal "mail.example.com", result.name
  end

  # Whoever runs the reverse zone can write any name in it; only the forward
  # lookup proves they run the name too.
  def test_a_name_that_resolves_elsewhere_fails
    result = check("mail.example.com" => { a: [ "198.51.100.7" ] })

    assert_equal MailAuth::Status::FAIL, result.status
    assert_nil result.name
    assert_includes result.comment, "mail.example.com does not resolve to #{IP}"
  end

  def test_a_name_that_does_not_exist_fails
    result = check

    assert_equal MailAuth::Status::FAIL, result.status
  end

  def test_a_name_with_no_address_fails
    result = check("mail.example.com" => { txt: [ "v=spf1 -all" ] })

    assert_equal MailAuth::Status::FAIL, result.status
  end

  def test_one_confirmed_name_among_several_passes
    result = check(IP => { ptr: [ "wrong.example.com", "mail.example.com" ] },
      "wrong.example.com" => { a: [ "198.51.100.7" ] }, "mail.example.com" => { a: [ IP ] })

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal "mail.example.com", result.name
  end

  def test_an_ipv6_address_is_confirmed_over_aaaa
    result = check(ip: "2001:db8::25", "2001:db8::25" => { ptr: [ "mail.example.com" ] },
      "mail.example.com" => { aaaa: [ "2001:DB8:0:0:0:0:0:25" ] })

    assert_equal MailAuth::Status::PASS, result.status
  end

  # A dual-stack socket reports an IPv4 peer as ::ffff:a.b.c.d; its name lives
  # under in-addr.arpa all the same.
  def test_an_ipv4_mapped_address_is_resolved_as_ipv4
    result = check(ip: "::ffff:#{IP}", "mail.example.com" => { a: [ IP ] })

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal "mail.example.com", result.name
  end

  # RFC 8601 §2.7.3 files an address nobody named under permerror, not fail.
  def test_an_address_with_no_ptr_is_permerror
    result = check(IP => {})

    assert_equal MailAuth::Status::PERMERROR, result.status
    assert_includes result.comment, "no PTR record for #{IP}"
  end

  def test_an_address_the_reverse_zone_never_mentions_is_permerror
    assert_equal MailAuth::Status::PERMERROR, MailAuth::Iprev.check(ip: IP, resolver: resolver_for({})).status
  end

  def test_a_failing_reverse_lookup_is_temperror
    assert_equal MailAuth::Status::TEMPERROR, check(IP => { ptr: :servfail }).status
  end

  def test_a_failing_forward_lookup_is_temperror
    result = check("mail.example.com" => { a: :timeout, aaaa: [] })

    assert_equal MailAuth::Status::TEMPERROR, result.status
  end

  def test_a_failing_forward_lookup_after_a_confirmed_name_is_never_reached
    result = check(IP => { ptr: [ "mail.example.com", "down.example.com" ] },
      "mail.example.com" => { a: [ IP ] }, "down.example.com" => { a: :servfail })

    assert_equal MailAuth::Status::PASS, result.status
  end

  # A zone that never answers would otherwise hold us for every name it
  # offers, so the first failure ends the check even with a good name behind it.
  def test_a_failing_forward_lookup_ends_the_check
    resolver = resolver_for(IP => { ptr: [ "down.example.com", "mail.example.com" ] },
      "down.example.com" => { a: :servfail }, "mail.example.com" => { a: [ IP ] })

    result = MailAuth::Iprev.check(ip: IP, resolver: resolver)

    assert_equal MailAuth::Status::TEMPERROR, result.status
    refute_includes resolver.queries, [ "mail.example.com", :a ]
  end

  # Past ten names a stranger's zone is choosing how much work we do.
  def test_only_the_first_ten_names_are_looked_up
    names = (1..12).map { |n| "host#{n}.example.com" }
    zone = names.to_h { |name| [ name, { a: [ "198.51.100.7" ] } ] }.merge(IP => { ptr: names })
    resolver = resolver_for(zone)

    MailAuth::Iprev.check(ip: IP, resolver: resolver)

    assert_equal 10, resolver.queries.count { |_, type| type == :a }
  end

  def test_an_invalid_address_raises
    assert_raises(IPAddr::InvalidAddressError) { MailAuth::Iprev.check(ip: "not an address", resolver: resolver_for({})) }
  end

  private
    # The address is named in reverse unless the zone says otherwise.
    def check(ip: IP, **zone)
      zone = { IP => { ptr: [ "mail.example.com" ] } }.merge(zone) unless zone.key?(ip)
      MailAuth::Iprev.check(ip: ip, resolver: resolver_for(zone))
    end
end
