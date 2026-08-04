require "test_helper"
require "yaml"

# `ArcResult#oldest_pass` is a second DNS pass over the chain, on top of the
# one `Arc.verify` already pays to reach a verdict — worth paying only when a
# caller actually reads it.
class MailAuth::Arc::OldestPassTest < MailAuth::TestCase
  SUITE = File.expand_path("../fixtures/arc-validation-tests.yml", __dir__)

  # The suite's five-hop passing chain: enough sets that a second DNS pass is
  # visibly more queries than the first, not just one more.
  def setup
    document = YAML.load_stream(File.read(SUITE)).first
    zone = document["txt-records"].to_h { |name, record| [ name.to_s.downcase, { txt: [ record ] } ] }
    @message = MailAuth::Message.new(document.fetch("tests").fetch("cv_pass_i5_1").fetch("message"))
    @resolver = resolver_for(zone)
  end

  def test_oldest_pass_is_not_computed_until_read
    result = MailAuth::Arc.verify(@message, resolver: @resolver)
    assert_equal MailAuth::Status::PASS, result.status
    queries_from_verifying = @resolver.queries.length

    assert_equal 0, result.oldest_pass
    assert_operator @resolver.queries.length, :>, queries_from_verifying
  end

  def test_oldest_pass_is_memoized_after_the_first_read
    result = MailAuth::Arc.verify(@message, resolver: @resolver)
    result.oldest_pass
    queries_after_first_read = @resolver.queries.length

    assert_equal 0, result.oldest_pass
    assert_equal queries_after_first_read, @resolver.queries.length
  end
end
