require "ipaddr"

module MailAuth
  # RFC 8601 §2.7.3 — does the connecting address have a name, and does that
  # name resolve back to it? Whoever controls the reverse zone can write any
  # name there; only the forward lookup proves they also control the name.
  module Iprev
    # The reverse zone is a stranger's: past ten names it is choosing how much
    # work we do.
    MAX_NAMES = 10

    # Raises IPAddr::InvalidAddressError on a bad `ip` rather than guessing,
    # which would risk vouching for the wrong host.
    def self.check(ip:, resolver: MailResolver::Resolver.new)
      Check.new(ip: ip, resolver: resolver).run
    end

    class Check
      def initialize(ip:, resolver:)
        @ip = client_address(ip)
        @resolver = resolver
      end

      def run
        confirm names.first(MAX_NAMES)
      rescue MailResolver::NotFound
        # RFC 8601 §2.7.3 files an address nobody named under permerror: there
        # is nothing to evaluate, and asking again won't change that.
        IprevResult.new(status: Status::PERMERROR, comment: "no PTR record for #{@ip}")
      rescue MailResolver::Error => error
        # The first lookup that fails ends the check: a zone that never answers
        # would otherwise hold us for every name it offers.
        IprevResult.new(status: Status::TEMPERROR, comment: error.message)
      end

      private
        # A dual-stack socket reports an IPv4 peer as ::ffff:a.b.c.d, whose
        # reverse zone is in-addr.arpa, not ip6.arpa.
        def client_address(ip)
          address = IPAddr.new(ip.to_s)
          address.ipv4_mapped? ? address.native : address
        end

        def names
          @resolver.ptr(@ip.to_s).map { |name| name.downcase.chomp(".") }
        end

        # One name resolving back is enough.
        def confirm(names)
          if name = names.find { |name| confirmed?(name) }
            IprevResult.new(status: Status::PASS, name: name)
          else
            IprevResult.new(status: Status::FAIL, comment: "#{names.join(", ")} does not resolve to #{@ip}")
          end
        end

        def confirmed?(name)
          @resolver.addresses(name).any? { |address| IPAddr.new(address) == @ip }
        rescue MailResolver::NotFound
          false
        end
    end
  end
end
