require "test_helper"
require "yaml"

# The openspf.org test suite for RFC 7208, run against our own evaluator.
# `zonedata` maps a name to its records, with "TIMEOUT" and "NONE" values
# standing in for a resolver that misbehaves; the suite predates RFC 7208
# dropping the SPF RR type, so a TXT query falls back to `SPF:` records.
class MailAuth::RfcSuiteTest < MailAuth::TestCase
  SUITE = File.expand_path("../fixtures/rfc7208-tests.yml", __dir__)

  # Cases we knowingly don't answer — a scope decision, not a bug. We do run
  # `exp=` cases; we just don't assert the suite's `explanation` field,
  # since this library reports a verdict rather than writing bounce messages.
  SKIPPED = {
    /\Ap-macro-multiple\z/ => "%{p} expands to \"unknown\" rather than doing the PTR forward-confirmation of §5.5"
  }.freeze

  def self.skip_reason(name)
    SKIPPED.find { |pattern, _reason| pattern.match?(name) }&.last
  end

  # Turns one document's `zonedata` into the hash FakeResolver takes.
  class Zone
    def self.build(zonedata)
      new(zonedata || {}).to_h
    end

    def initialize(zonedata)
      @zonedata = zonedata
    end

    def to_h
      @zonedata.each_with_object({}) do |(name, entries), zone|
        entries = Array(entries)

        zone[name.to_s.downcase] = present({
          txt: text_records(entries), a: records(entries, "A"), aaaa: records(entries, "AAAA"),
          mx: exchanges(entries)
        })

        if reverse = address_for(name.to_s.downcase)
          zone[reverse] = present(ptr: records(entries, "PTR"))
        end
      end
    end

    private
      # FakeResolver reads a missing key as "no such record", which is what
      # :absent means here.
      def present(records)
        records.reject { |_type, value| value == :absent || value == :none }
      end

      # RFC 7208 dropped the SPF RR type, so a policy published as one is
      # simply where this fixture keeps its TXT records.
      def text_records(entries)
        case txt = records(entries, "TXT")
        when :absent then records(entries, "SPF")
        else txt
        end
      end

      # Three answers, not two: :absent means no record of this type exists;
      # :none is the fixture insisting the query come back empty even though
      # another type is present. Only :absent falls back to SPF.
      def records(entries, type)
        values = entries.grep(Hash).select { |entry| entry.key?(type) }.map { |entry| entry[type] }

        if values.empty?
          entries.grep(String).include?("TIMEOUT") ? :timeout : :absent
        elsif values.include?("TIMEOUT") || (values.include?("NONE") && entries.last == "TIMEOUT")
          :timeout
        elsif values.include?("NONE")
          :none
        else
          values.map { |value| unescape(Array(value).join) }
        end
      end

      # Preference order, with ties left in the order the fixture wrote them.
      def exchanges(entries)
        case mx = records(entries, "MX")
        when :timeout, :absent, :none then mx
        else entries.grep(Hash).filter_map { |entry| entry["MX"] }.each_with_index.
          sort_by { |(preference, _exchange), index| [ preference, index ] }.
          map { |(_preference, exchange), _index| unescape(exchange.to_s) }
        end
      end

      # Our resolver takes the client address and works out the reverse name
      # itself, so the fixture's reverse zones are keyed back to addresses.
      def address_for(name)
        case name
        when /\A(?<nibbles>.+)\.ip6\.arpa\z/
          IPAddr.new($~[:nibbles].split(".").reverse.join.scan(/.{4}/).join(":")).to_s
        when /\A(?<quads>.+)\.in-addr\.arpa\z/
          IPAddr.new($~[:quads].split(".").reverse.join(".")).to_s
        end
      end

      def unescape(value)
        value.gsub(/\\x([0-9A-Fa-f]{2})/) { $1.hex.chr }
      end
  end

  # `host: ::1` in the fixture is a YAML scalar starting with a colon,
  # which Psych hands back as a Symbol with the leading colon eaten.
  def scalar(value)
    value.is_a?(Symbol) ? ":#{value}" : value
  end

  documents = YAML.load_stream(File.read(SUITE))
  cases = 0

  documents.each_with_index do |document, index|
    zone = Zone.build(document["zonedata"])

    document.fetch("tests").each do |name, testcase|
      cases += 1

      define_method "test_#{index}_#{name}" do
        skip "#{name}: #{self.class.skip_reason(name)}" if self.class.skip_reason(name)

        result = MailAuth::Spf.check(ip: scalar(testcase["host"]), helo: scalar(testcase["helo"]),
          mail_from: scalar(testcase["mailfrom"]), resolver: resolver_for(zone))

        assert_includes Array(testcase["result"]), result.status,
          "#{document["description"]} / #{name} (#{testcase["spec"]}): #{result.comment}"
      end
    end
  end

  scenarios = documents.length
  Minitest.after_run { puts "RFC 7208 suite: #{cases} cases across #{scenarios} scenarios" }
end
