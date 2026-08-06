require "test_helper"
require "openssl"
require "yaml"

# The signing half of the ValiMail ARC test suite: the only outside authority on
# the fields we write, stated down to the signature bytes.
#
# Messages carry bare LF where signatures were computed over CRLF (`Message#normalize`
# puts it back); tag order and folding are ours, so fields compare tag by tag, b= exact.
class MailAuth::ArcSigningSuiteTest < MailAuth::TestCase
  SUITE = File.expand_path("../fixtures/arc-sign-tests.yml", __dir__)
  DOCUMENTS = YAML.load_stream(File.read(SUITE)).freeze

  cases = 0

  DOCUMENTS.each_with_index do |document, index|
    document.fetch("tests").each do |name, testcase|
      cases += 1

      define_method "test_#{index}_#{name}" do
        if testcase["AS"].to_s.strip.empty?
          assert_chain_is_closed document, testcase
        else
          assert_seals document, testcase
        end
      end
    end
  end

  def test_every_case_the_suite_publishes_is_driven
    assert_equal 2, DOCUMENTS.length
    assert_equal 17, DOCUMENTS.sum { |document| document.fetch("tests").length }

    each_case do |_document, name, testcase|
      assert testcase.values_at("message", "t", "sig-headers", "srv-id").all?, name
    end
  end

  # Each document signs with its own key and publishes the matching record, and
  # a mismatch would fail all seventeen cases with nothing to say about why.
  def test_each_document_signs_with_the_key_it_publishes
    DOCUMENTS.each do |document|
      published = MailAuth::Dkim::PublicKey.retrieve(selector: document["sel"], domain: document["domain"],
        algorithm: "rsa", resolver: resolver_for(zone_for(document)))

      assert_equal published.to_der, key_for(document).public_to_der, document["description"]
    end
  end

  # The suite's "AR Consolidation" rule: every Authentication-Results field bearing
  # our own authserv-id becomes one AAR, in order; another ADMD's is left alone.
  def test_authentication_results_are_consolidated_by_authserv_id
    merged = "lists.example.org; arc=none; spf=pass smtp.mfrom=jqd@d1.example; " \
      "dkim=pass (1024-bit key) header.i=@d1.example; dmarc=pass"

    assert_equal merged, folded(results_for(case_named("ar_merged1")))
    assert_equal merged, folded(results_for(case_named("ar_merged2")))
  end

  # cv reports the chain we received, not the verdict on the message: i1_base_fail
  # passes spf, dkim, and dmarc and still seals cv=fail.
  def test_chain_status_is_derived_from_the_incoming_chain
    each_case do |document, name, testcase|
      if expected = testcase["AS"].to_s[/cv=(\w+)/, 1]
        assert_equal expected, chain_status_for(document, message_for(testcase)), name
      end
    end
  end

  # Only a real field proves the comparison, and the suite's chaining leaves two
  # lying around — folded and padded as a hop wrote them.
  def test_the_fields_the_suite_itself_wrote_satisfy_the_comparison
    signed, sealed = case_named("i0_base"), case_named("i1_base")
    signature = message_for(sealed).fields_named("arc-message-signature").first
    results = message_for(case_named("i2_base")).fields_named("arc-authentication-results").first

    assert_tags signed["AMS"], signature, "ARC-Message-Signature", signed
    assert_value sealed["AAR"], results, "ARC-Authentication-Results", sealed
    assert_raises(Minitest::Assertion) { assert_tags signed["AMS"].sub("b=X", "b=Y"), signature, "ARC-Message-Signature", signed }
  end

  # The cases above read the three fields one at a time; what `Arc.seal` hands a
  # caller is the message with all three on it, as `Dkim.sign` does.
  def test_seal_returns_the_message_carrying_the_three_new_fields
    document = DOCUMENTS.first
    testcase = document.fetch("tests").fetch("message_body_eol_wsp")
    message = message_for(testcase)
    sealer = sealer_for(document, testcase, message)

    assert_equal sealer.seal_field + sealer.message_signature_field + sealer.authentication_results_field, sealer.fields
    assert_equal sealer.fields + message.raw, sealer.sealed_message
    assert_equal sealer.sealed_message, MailAuth::Arc.seal(message, **seal_options(document, testcase, message))
  end

  # A chain we just wrote has to be one we would accept: field order, h=, and the
  # seal's own coverage all read back at once.
  def test_a_freshly_sealed_message_verifies
    document = DOCUMENTS.last

    %w[ i0_base i1_base ].each do |name|
      testcase = document.fetch("tests").fetch(name)
      message = message_for(testcase)
      sealed = MailAuth::Message.new(MailAuth::Arc.seal(message, **seal_options(document, testcase, message)))

      assert_equal MailAuth::Status::PASS,
        MailAuth::Arc.verify(sealed, resolver: resolver_for(zone_for(document))).status, name
    end
  end

  scenarios = DOCUMENTS.length
  Minitest.after_run { puts "ARC signing suite: #{cases} cases across #{scenarios} scenarios" }

  private
    def assert_seals(document, testcase)
      message = message_for(testcase)
      sealer = sealer_for(document, testcase, message)

      assert_tags testcase["AS"], sealer.seal_field, "ARC-Seal", testcase
      assert_tags testcase["AMS"], sealer.message_signature_field, "ARC-Message-Signature", testcase
      assert_value testcase["AAR"], sealer.authentication_results_field, "ARC-Authentication-Results", testcase
    end

    # §5.1.3: a chain already sealed cv=fail is closed, and `no_additional_sig`
    # expects no fields. Sealing can't answer "declined", so assert what a caller reads.
    def assert_chain_is_closed(document, testcase)
      chain = MailAuth::Arc.verify(message_for(testcase), resolver: resolver_for(zone_for(document)))

      assert_equal MailAuth::Status::FAIL, chain.status, testcase["description"]
      assert_equal MailAuth::Status::FAIL, chain.newest.chain_status, testcase["description"]
    end

    def sealer_for(document, testcase, message)
      MailAuth::Arc::Sealer.new(message, **seal_options(document, testcase, message))
    end

    # h= has to come out as exactly the case's sig-headers, so nothing rides
    # along oversigned, and t= only reproduces from the instant the case names.
    def seal_options(document, testcase, message)
      { authentication_results: results_for(testcase, message),
        chain_status: chain_status_for(document, message),
        domain: document["domain"], selector: document["sel"], key: key_for(document),
        headers: testcase["sig-headers"].split(":"), oversign: [], now: Time.at(testcase["t"]) }
    end

    def message_for(testcase)
      MailAuth::Message.new(testcase["message"])
    end

    # The value the AAR will carry, without the i= the sealer prefixes: the
    # results this hop already found, never a fresh authentication of its own.
    def results_for(testcase, message = message_for(testcase))
      authserv_id = testcase["srv-id"]

      ours = message.fields_named("authentication-results").filter_map do |field|
        id, verdicts = MailAuth::Arc.value_of(field).to_s.split(";", 2)
        verdicts.to_s.strip if id.to_s.strip.casecmp?(authserv_id) && !verdicts.to_s.strip.empty?
      end

      [ authserv_id, *ours ].join("; ")
    end

    def chain_status_for(document, message)
      MailAuth::Arc.verify(message, resolver: resolver_for(zone_for(document))).status
    end

    def zone_for(document)
      document.fetch("txt-records").to_h { |name, record| [ name.to_s.downcase, { txt: [ record ] } ] }
    end

    def key_for(document)
      OpenSSL::PKey.read(document.fetch("privatekey"))
    end

    def assert_tags(expected, field, name, testcase)
      assert_match(/\A#{name}:/i, field, description(name, testcase))
      tags = squeezed(MailAuth::Arc.tags_in(field))

      assert tags, "#{name} did not parse: #{field}"
      assert_equal squeezed(MailAuth::Dkim.parse_tags(expected)), tags, description(name, testcase)
    end

    # The AAR is a payload rather than a tag list, and whitespace inside it is
    # the sender's — only the folding the suite happens to have chosen is ours.
    def assert_value(expected, field, name, testcase)
      assert_match(/\A#{name}:/i, field, description(name, testcase))
      assert_equal folded(expected), folded(MailAuth::Arc.value_of(field)), description(name, testcase)
    end

    # None of a=, b=, bh=, c=, cv=, d=, h=, i=, s=, or t= carries meaningful
    # whitespace, and every one of them may be folded anywhere.
    def squeezed(tags)
      tags&.transform_values { |value| value.gsub(/\s+/, "") }
    end

    def folded(value)
      value.to_s.gsub(/\s+/, " ").strip
    end

    def each_case
      DOCUMENTS.each do |document|
        document.fetch("tests").each { |name, testcase| yield document, name, testcase }
      end
    end

    def case_named(name)
      DOCUMENTS.filter_map { |document| document.fetch("tests")[name] }.first
    end

    def description(name, testcase)
      "#{name} for #{testcase["spec"]}: #{testcase["description"]}"
    end
end
