$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "mailauth"
require "mailresolver/testing"

module MailAuth
  class TestCase < Minitest::Test
    FIXTURES = File.expand_path("fixtures", __dir__)

    private
      # Always binary: canonicalization and body hashing count bytes, and a
      # message that arrives as UTF-8 hashes differently from the same bytes
      # read as binary.
      def fixture(name)
        File.binread(File.join(FIXTURES, name))
      end

      def resolver_for(zone)
        MailResolver::Testing::FakeResolver.new(zone)
      end
  end
end
