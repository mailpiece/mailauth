require "public_suffix"

require "mailauth/domain"

module MailAuth
  module Dmarc
    # The registrable domain — "bar.co.uk" for "foo.bar.co.uk", never "co.uk".
    # Only the Public Suffix List can answer this; counting labels would put
    # bank.co.uk and attacker.co.uk in the same organization.
    module OrganizationalDomain
      def self.of(name)
        domain = Domain.normalize(name)

        # Private suffixes are boundaries too: two tenants of one host
        # (user1.blogspot.com, user2.blogspot.com) are separate organizations.
        PublicSuffix.domain(domain, ignore_private: false) || domain
      rescue PublicSuffix::Error
        domain # under no known suffix, a name can only align with itself
      end
    end
  end
end
