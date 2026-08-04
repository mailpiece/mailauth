require "test_helper"
require "yaml"

# The ValiMail ARC test suite, run against our own validator. RFC 8617 publishes
# no reproducible signatures of its own, so these 171 cases are the only outside
# authority available on the chain algorithm.
#
# Each document carries its own `txt-records` — the whole suite turns on seven
# of them — and each case states the Chain Validation Status it expects and
# nothing else. Messages are stored with bare LF where the signatures were
# computed over CRLF; `Message#normalize` puts that back, and a regression there
# would fail nearly every case at once.
class MailAuth::ArcSuiteTest < MailAuth::TestCase
  SUITE = File.expand_path("../fixtures/arc-validation-tests.yml", __dir__)

  # Three cases state an empty status where RFC 8617 gives a definite one: a
  # newest seal carrying cv=fail is a failed chain by §5.2 step 2, and an
  # earlier one is by step 3.3. The fixture is left as it was published.
  EMPTY_STATUS_IS = MailAuth::Status::FAIL

  documents = YAML.load_stream(File.read(SUITE))
  cases = 0

  documents.each_with_index do |document, index|
    zone = (document["txt-records"] || {}).to_h { |name, record| [ name.to_s.downcase, { txt: [ record ] } ] }

    document.fetch("tests").each do |name, testcase|
      cases += 1

      define_method "test_#{index}_#{name}" do
        expected = testcase["cv"].to_s.strip.empty? ? EMPTY_STATUS_IS : testcase["cv"].downcase
        result = MailAuth::Arc.verify(MailAuth::Message.new(testcase["message"].to_s), resolver: resolver_for(zone))

        assert_equal expected, result.status,
          "#{document["description"]} / #{name} (#{testcase["spec"]}): #{testcase["description"]} — #{result.comment}"
      end
    end
  end

  scenarios = documents.length
  Minitest.after_run { puts "ARC suite: #{cases} cases across #{scenarios} scenarios" }
end
