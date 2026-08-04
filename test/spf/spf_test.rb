require "test_helper"

class MailAuth::SpfTest < MailAuth::TestCase
  def test_ip4_mechanism_matches_the_client_address
    assert_status MailAuth::Status::PASS, spf("v=spf1 ip4:192.0.2.1 -all")
  end

  def test_ip4_mechanism_matches_a_prefix
    assert_status MailAuth::Status::PASS, spf("v=spf1 ip4:192.0.2.0/24 -all")
    assert_status MailAuth::Status::FAIL, spf("v=spf1 ip4:192.0.2.128/25 -all")
  end

  def test_ip4_mechanism_never_matches_an_ipv6_client
    assert_status MailAuth::Status::NEUTRAL, spf("v=spf1 ip4:0.0.0.0/0", ip: "2001:db8::1")
  end

  def test_ip6_mechanism_matches_the_client_address
    assert_status MailAuth::Status::PASS, spf("v=spf1 ip6:2001:db8::/32 -all", ip: "2001:db8::1")
    assert_status MailAuth::Status::FAIL, spf("v=spf1 ip6:2001:db9::/32 -all", ip: "2001:db8::1")
  end

  def test_an_ipv4_client_arriving_as_an_ipv4_mapped_ipv6_address_is_still_ipv4
    assert_status MailAuth::Status::PASS, spf("v=spf1 ip4:192.0.2.1 -all", ip: "::ffff:192.0.2.1")
    assert_status MailAuth::Status::FAIL, spf("v=spf1 ip6:::ffff:192.0.2.1 -all", ip: "::ffff:192.0.2.1")
  end

  def test_a_mechanism_resolves_the_current_domain_by_default
    assert_status MailAuth::Status::PASS, spf("v=spf1 a -all", zone: { "example.com" => { a: [ "192.0.2.1" ] } })
    assert_status MailAuth::Status::FAIL, spf("v=spf1 a -all", zone: { "example.com" => { a: [ "198.51.100.1" ] } })
  end

  def test_a_mechanism_takes_a_domain_and_a_dual_prefix_length
    zone = { "hosts.example.com" => { a: [ "192.0.2.129" ], aaaa: [ "2001:db8:1::1" ] } }

    assert_status MailAuth::Status::PASS, spf("v=spf1 a:hosts.example.com/24 -all", zone: zone)
    assert_status MailAuth::Status::FAIL, spf("v=spf1 a:hosts.example.com/25 -all", zone: zone)
    assert_status MailAuth::Status::PASS, spf("v=spf1 a:hosts.example.com//32 -all", ip: "2001:db8:1::2", zone: zone)
  end

  def test_a_prefix_length_past_the_end_of_the_address_is_a_permanent_error
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 a/33 -all")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 a//129 -all")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 ip4:192.0.2.0/033 -all")
  end

  def test_mx_mechanism_matches_an_exchange_s_addresses
    zone = {
      "example.com" => { mx: [ "mail1.example.com", "mail2.example.com" ] },
      "mail1.example.com" => { a: [ "198.51.100.1" ] },
      "mail2.example.com" => { a: [ "192.0.2.1" ] }
    }

    assert_status MailAuth::Status::PASS, spf("v=spf1 mx -all", zone: zone)
  end

  def test_mx_addresses_are_resolved_outside_the_ten_lookups_the_record_is_spending
    exchanges = (1..9).map { |number| "mail#{number}.example.com" }
    zone = { "example.com" => { mx: exchanges } }
    exchanges.each { |exchange| zone[exchange] = { a: [ "192.0.2.9" ] } }

    # Nine exchanges plus nine lookups of our own is eighteen queries, and
    # still only ten against the limit.
    result = spf("v=spf1 a a a a a a a a a mx -all", zone: zone.merge("example.com" =>
      { a: [ "198.51.100.1" ], mx: exchanges }))

    assert_equal MailAuth::Status::FAIL, result.status
    assert_equal 10, result.lookups
  end

  def test_more_than_ten_mx_exchanges_is_a_permanent_error
    exchanges = (1..11).map { |number| "mail#{number}.example.com" }
    zone = { "example.com" => { mx: exchanges } }

    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 mx -all", zone: zone)
  end

  def test_exists_mechanism_asks_for_an_a_record_whatever_the_client_s_family
    zone = { "probe.example.com" => { a: [ "127.0.0.2" ] } }

    assert_status MailAuth::Status::PASS, spf("v=spf1 exists:probe.example.com -all", ip: "2001:db8::1", zone: zone)
    assert_status MailAuth::Status::FAIL, spf("v=spf1 exists:probe.example.com -all",
      zone: { "probe.example.com" => { aaaa: [ "2001:db8::1" ] } })
  end

  def test_ptr_mechanism_matches_a_forward_confirmed_name_under_the_target
    zone = {
      "192.0.2.1" => { ptr: [ "mail.example.com" ] },
      "mail.example.com" => { a: [ "192.0.2.1" ] }
    }

    assert_status MailAuth::Status::PASS, spf("v=spf1 ptr -all", zone: zone)
  end

  def test_ptr_mechanism_ignores_a_name_whose_addresses_don_t_point_back
    zone = {
      "192.0.2.1" => { ptr: [ "liar.example.com" ] },
      "liar.example.com" => { a: [ "198.51.100.1" ] }
    }

    assert_status MailAuth::Status::FAIL, spf("v=spf1 ptr -all", zone: zone)
  end

  def test_ptr_mechanism_matches_a_subdomain_of_its_target
    zone = {
      "192.0.2.1" => { ptr: [ "mail.corp.example.com" ] },
      "mail.corp.example.com" => { a: [ "192.0.2.1" ] }
    }

    assert_status MailAuth::Status::PASS, spf("v=spf1 ptr:example.com -all", zone: zone)
    assert_status MailAuth::Status::FAIL, spf("v=spf1 ptr:corp.example.net -all", zone: zone)
  end

  def test_ptr_mechanism_stops_after_ten_names
    names = (1..11).map { |number| "host#{number}.example.com" }
    zone = { "192.0.2.1" => { ptr: names } }
    # Only the eleventh confirms, and we never get to it.
    zone[names.last] = { a: [ "192.0.2.1" ] }
    names.first(10).each { |name| zone[name] = { a: [ "198.51.100.1" ] } }

    assert_status MailAuth::Status::FAIL, spf("v=spf1 ptr -all", zone: zone)
  end

  def test_qualifiers_decide_what_a_match_means
    assert_status MailAuth::Status::PASS, spf("v=spf1 +ip4:192.0.2.1")
    assert_status MailAuth::Status::FAIL, spf("v=spf1 -ip4:192.0.2.1")
    assert_status MailAuth::Status::SOFTFAIL, spf("v=spf1 ~ip4:192.0.2.1")
    assert_status MailAuth::Status::NEUTRAL, spf("v=spf1 ?ip4:192.0.2.1")
  end

  def test_a_record_that_matches_nothing_is_neutral
    assert_status MailAuth::Status::NEUTRAL, spf("v=spf1 ip4:198.51.100.1")
  end

  def test_include_matches_only_on_a_pass
    assert_status MailAuth::Status::PASS, spf("v=spf1 include:sub.example.com -all",
      zone: spf_zone("sub.example.com", "v=spf1 ip4:192.0.2.1 -all"))
    assert_status MailAuth::Status::FAIL, spf("v=spf1 include:sub.example.com -all",
      zone: spf_zone("sub.example.com", "v=spf1 -all"))
    assert_status MailAuth::Status::FAIL, spf("v=spf1 include:sub.example.com -all",
      zone: spf_zone("sub.example.com", "v=spf1 ?all"))
  end

  def test_include_of_a_domain_with_no_record_is_a_permanent_error
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 include:sub.example.com -all")
  end

  def test_include_recurses
    zone = spf_zone("one.example.com", "v=spf1 include:two.example.com -all").
      merge(spf_zone("two.example.com", "v=spf1 ip4:192.0.2.1 -all"))

    assert_status MailAuth::Status::PASS, spf("v=spf1 include:one.example.com -all", zone: zone)
  end

  def test_include_reports_the_sender_s_domain_rather_than_the_included_one
    result = spf("v=spf1 include:sub.example.com -all",
      zone: spf_zone("sub.example.com", "v=spf1 ip4:192.0.2.1 -all"))

    assert_equal "example.com", result.domain
    assert_equal 1, result.lookups
  end

  def test_redirect_hands_the_whole_verdict_to_another_domain
    assert_status MailAuth::Status::PASS, spf("v=spf1 redirect=sub.example.com",
      zone: spf_zone("sub.example.com", "v=spf1 ip4:192.0.2.1 -all"))
    assert_status MailAuth::Status::FAIL, spf("v=spf1 redirect=sub.example.com",
      zone: spf_zone("sub.example.com", "v=spf1 -all"))
  end

  # "=" is a legal macro delimiter and a legal macro literal (RFC 7208 §7.1),
  # so a modifier's name ends at the first one. Read up to the last, the value
  # is swallowed into the name and the whole record is rejected.
  def test_a_modifier_value_may_contain_an_equals_sign
    assert_status MailAuth::Status::PASS, spf("v=spf1 redirect=%{s=}.example.com",
      zone: spf_zone("sender@example.com.example.com", "v=spf1 ip4:192.0.2.1 -all"))
  end

  # An unknown modifier does nothing whatever, but "foo=a" isn't a modifier
  # name and rejecting it would take the record down with it.
  def test_an_unknown_modifier_whose_value_contains_an_equals_sign_is_ignored
    assert_status MailAuth::Status::FAIL, spf("v=spf1 foo=a=b -all")
  end

  # The same "=" inside a mechanism's argument was never a modifier: the ":"
  # comes first.
  def test_a_mechanism_argument_may_contain_an_equals_sign
    assert_status MailAuth::Status::PASS, spf("v=spf1 a:%{s=}.example.com -all",
      zone: { "sender@example.com.example.com" => { a: [ "192.0.2.1" ] } })
  end

  def test_redirect_to_a_domain_with_no_record_is_a_permanent_error
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 redirect=sub.example.com")
  end

  def test_redirect_is_unreachable_once_the_record_states_an_all
    assert_status MailAuth::Status::SOFTFAIL, spf("v=spf1 ~all redirect=nowhere.example.com")
  end

  def test_no_spf_record_at_all_is_none
    assert_status MailAuth::Status::NONE, spf(nil)
    assert_status MailAuth::Status::NONE, spf("some other TXT record entirely")
  end

  def test_two_spf_records_are_a_permanent_error
    resolver = resolver_for("example.com" => { txt: [ "v=spf1 -all", "v=spf1 +all" ] })

    assert_status MailAuth::Status::PERMERROR, MailAuth::Spf.check(ip: "192.0.2.1", mail_from: "sender@example.com", resolver: resolver)
  end

  def test_a_dns_failure_anywhere_is_a_temporary_error
    assert_status MailAuth::Status::TEMPERROR, spf("v=spf1 a -all", zone: { "example.com" => { a: :timeout } })
    assert_status MailAuth::Status::TEMPERROR, spf("v=spf1 a -all", zone: { "example.com" => { a: :servfail } })
    assert_status MailAuth::Status::TEMPERROR, spf(nil, zone: { "example.com" => { txt: :timeout } })
  end

  def test_syntax_the_rfc_doesn_t_allow_is_a_permanent_error
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 ip4:192.0.2.1 -all moo")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 -all/8")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 a:")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 ip4:192.0.2.256")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 redirect=e.example.com redirect=f.example.com")
  end

  def test_an_error_is_detected_even_where_evaluation_would_never_reach_it
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 +all ip6:not-an-address")
  end

  def test_ten_dns_querying_mechanisms_are_allowed_and_an_eleventh_is_not
    zone = { "example.com" => { a: [ "198.51.100.1" ] } }

    assert_status MailAuth::Status::FAIL, spf("v=spf1 #{"a " * 10}-all", zone: zone)
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 #{"a " * 11}-all", zone: zone)
  end

  def test_the_record_s_own_lookup_is_not_charged
    result = spf("v=spf1 a a -all", zone: { "example.com" => { a: [ "198.51.100.1" ] } })

    assert_equal 2, result.lookups
  end

  def test_two_void_lookups_are_allowed_and_a_third_is_not
    assert_status MailAuth::Status::NEUTRAL, spf("v=spf1 a:one.example.com a:two.example.com")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 a:one.example.com a:two.example.com a:three.example.com")
  end

  # Five mx terms, none within the record's own ten-lookup budget or any one
  # term's ten-exchange budget, but their branch lookups add up: 5 mx queries
  # plus 5 * 8 exchange addresses is 45, past Budget::MAX_TOTAL_LOOKUPS (40).
  def test_the_aggregate_total_across_several_mx_terms_own_budgets_is_capped
    domains = (1..5).map { |number| "mx#{number}.example.com" }
    zone = domains.each_with_object({}) do |domain, entries|
      exchanges = (1..8).map { |number| "#{domain.split(".").first}-ex#{number}.example.com" }
      entries[domain] = { mx: exchanges }
      exchanges.each { |exchange| entries[exchange] = { a: [ "203.0.113.1" ] } } # never the client
    end

    record = "v=spf1 #{domains.map { |domain| "mx:#{domain}" }.join(" ")} -all"

    assert_status MailAuth::Status::PERMERROR, spf(record, zone: zone)
  end

  # The same shape at a realistic size — a couple of mx terms and a ptr term,
  # each with a handful of exchanges or names — stays far under the aggregate
  # cap and evaluates normally.
  def test_a_normal_number_of_mx_and_ptr_terms_stays_under_the_aggregate_cap
    zone = {
      "mx1.example.com" => { mx: [ "mx1-ex1.example.com", "mx1-ex2.example.com", "mx1-ex3.example.com" ] },
      "mx1-ex1.example.com" => { a: [ "203.0.113.1" ] },
      "mx1-ex2.example.com" => { a: [ "203.0.113.2" ] },
      "mx1-ex3.example.com" => { a: [ "203.0.113.3" ] },
      "mx2.example.com" => { mx: [ "mx2-ex1.example.com", "mx2-ex2.example.com", "mx2-ex3.example.com" ] },
      "mx2-ex1.example.com" => { a: [ "203.0.113.4" ] },
      "mx2-ex2.example.com" => { a: [ "203.0.113.5" ] },
      "mx2-ex3.example.com" => { a: [ "203.0.113.6" ] },
      "192.0.2.1" => { ptr: [ "host1.example.net", "host2.example.net" ] },
      "host1.example.net" => { a: [ "203.0.113.7" ] },
      "host2.example.net" => { a: [ "203.0.113.8" ] }
    }

    assert_status MailAuth::Status::FAIL, spf("v=spf1 mx:mx1.example.com mx:mx2.example.com ptr -all", zone: zone)
  end

  # RFC 7208 §7.3: a name a macro expanded past 253 octets loses whole labels
  # from the left until it fits and is then asked for. Refusing to ask would
  # spend a void lookup on a question nobody put.
  def test_a_macro_expansion_past_253_octets_is_truncated_from_the_left_and_queried
    local = Array.new(24) { "a" * 9 }.join(".")
    truncated = "#{local.split(".", 2).last}.probe.example.com"

    result = spf("v=spf1 exists:%{l}.probe.example.com -all", mail_from: "#{local}@example.com",
      zone: { truncated => { a: [ "127.0.0.2" ] } })

    assert_equal 257, "#{local}.probe.example.com".length
    assert_status MailAuth::Status::PASS, result
    assert_equal 1, result.lookups
  end

  # A label no name can carry is a different matter: nothing could answer for
  # it, so it stays the void lookup RFC 7208 §4.3 makes it.
  def test_an_expansion_with_an_unusable_label_is_still_a_void_lookup
    over_long_label = "a" * 64

    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 exists:#{over_long_label}.a.example.com " \
      "exists:#{over_long_label}.b.example.com exists:#{over_long_label}.c.example.com -all")
  end

  def test_macros_expand_from_the_message_being_checked
    assert_expansion "sender@example.com", "%{s}"
    assert_expansion "sender", "%{l}"
    assert_expansion "example.com", "%{o}"
    assert_expansion "example.com", "%{d}"
    assert_expansion "192.0.2.1", "%{i}"
    assert_expansion "in-addr", "%{v}"
    assert_expansion "mail.example.net", "%{h}"
  end

  def test_macro_transformers_reverse_truncate_and_split
    assert_expansion "1.2.0.192", "%{ir}"
    assert_expansion "0.192", "%{i2r}"
    assert_expansion "com.example", "%{dr}"
    assert_expansion "example.com", "%{d2}"
    assert_expansion "last.first", "%{lr-}", sender: "first-last@example.com"
  end

  def test_macros_expand_an_ipv6_client_one_nibble_per_label
    assert_expansion "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1", "%{i}", ip: "2001:db8::1"
    assert_expansion "ip6", "%{v}", ip: "2001:db8::1"
  end

  def test_macros_escape_the_literals_the_rfc_gives_them
    assert_expansion "a%b c d%20e", "a%%b%_c%_d%-e"
  end

  def test_an_uppercase_macro_letter_url_escapes_its_expansion
    assert_expansion "jack%26jill", "%{L}", sender: "jack&jill@example.com"
  end

  def test_a_lone_percent_or_an_unknown_macro_letter_is_a_permanent_error
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 exists:100%.example.com")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 exists:%{z}.example.com")
    assert_status MailAuth::Status::PERMERROR, spf("v=spf1 exists:%{t}.example.com")
  end

  def test_an_empty_envelope_sender_is_checked_as_postmaster_at_the_helo_domain
    resolver = resolver_for(spf_zone("mail.example.net", "v=spf1 ip4:192.0.2.1 -all"))
    result = MailAuth::Spf.check(ip: "192.0.2.1", helo: "mail.example.net", mail_from: "", resolver: resolver)

    assert_equal MailAuth::Status::PASS, result.status
    assert_equal "mail.example.net", result.domain
    assert_includes result.comment, "postmaster@mail.example.net"
  end

  def test_an_envelope_sender_with_no_local_part_is_checked_as_postmaster
    result = spf("v=spf1 exists:%{l}.example.com -all", mail_from: "@example.com",
      zone: { "postmaster.example.com" => { a: [ "127.0.0.2" ] } })

    assert_equal MailAuth::Status::PASS, result.status
  end

  def test_the_comment_says_what_happened
    assert_includes spf("v=spf1 +all").comment, "designates 192.0.2.1 as permitted sender"
    assert_includes spf("v=spf1 -all").comment, "does not designate"
    assert_includes spf(nil).comment, "does not designate permitted sender hosts"
    assert_includes spf("v=spf1 moo").comment, "permanent error"
  end

  private
    # The domain under test is always example.com, so a record is all a case
    # usually has to say.
    def spf(record, ip: "192.0.2.1", helo: "mail.example.net", mail_from: "sender@example.com", zone: {})
      zone = spf_zone("example.com", record).merge(zone) { |_name, spf, given| spf.merge(given) }

      MailAuth::Spf.check(ip: ip, helo: helo, mail_from: mail_from, resolver: resolver_for(zone))
    end

    def spf_zone(domain, record)
      record ? { domain => { txt: [ record ] } } : {}
    end

    def assert_status(expected, result)
      assert_equal expected, result.status, result.comment
    end

    # Macros are only observable through the names they build, so we watch one
    # go past on an `exists` lookup.
    def assert_expansion(expected, macro, sender: "sender@example.com", ip: "192.0.2.1")
      resolver = resolver_for(spf_zone("example.com", "v=spf1 exists:#{macro}.probe.example.com -all"))
      MailAuth::Spf.check(ip: ip, helo: "mail.example.net", mail_from: sender, resolver: resolver)

      assert_equal "#{expected.downcase}.probe.example.com", resolver.queries.last.first
    end
end
