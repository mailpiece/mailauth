require "ipaddr"
require "socket"

require "mailauth/spf/budget"
require "mailauth/spf/macro"
require "mailauth/spf/record"

module MailAuth
  # RFC 7208 — was this IP allowed to send for the envelope domain? A `pass`
  # says little: sender and domain are self-declared, and `+all` passes everyone.
  module Spf
    # An `mx` may resolve ten exchanges and a `ptr` ten names — past that a
    # stranger's zone is choosing how much work we do.
    MAX_MX_EXCHANGES = 10
    MAX_PTR_NAMES = 10

    QUALIFIERS = {
      "+" => Status::PASS, "-" => Status::FAIL, "~" => Status::SOFTFAIL, "?" => Status::NEUTRAL
    }.freeze

    # Results check_host() reaches without any mechanism matching. Travel as
    # exceptions because they can happen several `include`s deep and end the
    # whole evaluation, not just the record where they were found.
    class Error < StandardError
      def status
        Status::TEMPERROR
      end
    end

    # The DNS didn't answer; the same message may pass later.
    class TempError < Error; end

    # Broken, or asking more work than it's allowed. Retrying changes nothing.
    class PermError < Error
      def status
        Status::PERMERROR
      end
    end

    # Not a failure: the domain publishes no policy at all.
    class NoRecord < Error
      def status
        Status::NONE
      end
    end

    # What a macro can expand to. `domain` is whose record we're reading now,
    # which an `include` or `redirect` moves away from the sender's.
    Context = Data.define(:ip, :sender, :helo, :domain) do
      def local
        sender.split("@", 2).first
      end

      def sender_domain
        sender.split("@", 2).last
      end

      def for_domain(domain)
        with(domain: domain)
      end
    end

    # Raises IPAddr::InvalidAddressError on a bad `ip` rather than guessing,
    # which would risk authenticating the wrong host.
    def self.check(ip:, helo: nil, mail_from: nil, resolver: MailResolver::Resolver.new)
      Evaluation.new(ip: ip, helo: helo, mail_from: mail_from, resolver: resolver).run
    end

    # One run of RFC 7208's check_host(), plus every recursion an `include` or
    # `redirect` drags in. Single use: it carries the shared lookup budget.
    class Evaluation
      LABEL = /[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?/i
      DOMAIN = /\A(?:#{LABEL}\.)+#{Macro::TOPLABEL}\z/o

      def initialize(ip:, helo:, mail_from:, resolver:)
        @ip = client_address(ip)
        @helo = helo
        @sender = identity(mail_from)
        @domain = @sender.split("@", 2).last.downcase
        @context = Context.new(ip: @ip, sender: @sender, helo: @helo, domain: @domain)
        @budget = Budget.new(resolver, charging: false)
      end

      def run
        if checkable?(@domain)
          result check(@domain)
        else
          result Status::NONE
        end
      rescue Error => error
        result error.status, error.message
      end

      private
        # An IPv4 sender that arrived over IPv6 is still IPv4, and matches
        # only `ip4:` mechanisms.
        def client_address(ip)
          address = IPAddr.new(ip.to_s)
          address.ipv4_mapped? ? address.native : address
        end

        # A bounce has no envelope sender, so there is no domain to check but
        # the one the client announced itself as.
        def identity(mail_from)
          case mail_from.to_s
          when ""    then "postmaster@#{@helo}"
          when /\A@/ then "postmaster#{mail_from}"
          when /@/   then mail_from.to_s
          else "postmaster@#{mail_from}"
          end
        end

        # A HELO of "OEMCOMPUTER", a domain literal, anything no record could
        # be published under — answers `none` rather than feigning a check.
        def checkable?(domain)
          domain.length <= Budget::MAX_NAME_LENGTH && domain.match?(DOMAIN)
        end

        # check_host() itself. First match decides; `redirect` is consulted only
        # if none matched, which is why any `all` stops a record redirecting.
        def check(domain)
          record = Record.fetch(domain, budget: @budget, context: @context.for_domain(domain))

          if matched = record.terms.find { |term| matches?(term) }
            QUALIFIERS.fetch(matched.qualifier)
          elsif record.redirect
            redirected(record.redirect)
          else
            Status::NEUTRAL
          end
        end

        def matches?(term)
          case term.mechanism
          when :all       then true
          when :ip4, :ip6 then matching_network?(term.network)
          when :a         then matching_address?(term.target, term, @budget)
          when :mx        then matching_exchange?(term)
          when :exists    then exists?(term.target)
          when :include   then included?(term.target)
          when :ptr       then matching_ptr?(term.target)
          end
        end

        def matching_network?(network)
          network.family == @ip.family && network.include?(@ip)
        end

        def matching_address?(name, term, budget)
          addresses(name, budget).any? { |address| address.mask(prefix_for(term)).include?(@ip) }
        end

        # Only the client's own address family is worth asking about: an IPv6
        # client can never match an A record.
        def addresses(name, budget)
          records = @ip.ipv4? ? budget.a(name) : budget.aaaa(name)

          records.filter_map { |record| client_family_address(record) }
        end

        def client_family_address(record)
          address = IPAddr.new(record.to_s)
          address if address.family == @ip.family
        rescue IPAddr::Error
          nil # a resolver handing back something that isn't an address tells us nothing
        end

        def prefix_for(term)
          @ip.ipv4? ? term.cidr4 || 32 : term.cidr6 || 128
        end

        def matching_exchange?(term)
          exchanges = @budget.mx(term.target).reject { |exchange| exchange.to_s.chomp(".").empty? }

          if exchanges.length > MAX_MX_EXCHANGES
            raise PermError, "more than #{MAX_MX_EXCHANGES} MX hosts for #{term.target}"
          else
            addresses = @budget.branch
            exchanges.any? { |exchange| matching_address?(exchange, term, addresses) }
          end
        end

        # Always an A query, never AAAA, regardless of how the client connected.
        def exists?(name)
          @budget.a(name).any?
        end

        # Only `pass` in the included record counts — `include` borrows
        # another domain's permissions, not its refusals. Its `none` is our
        # permerror.
        def included?(domain)
          check(domain) == Status::PASS
        rescue NoRecord
          raise PermError, "include target #{domain} publishes no SPF record"
        end

        def redirected(domain)
          check(domain)
        rescue NoRecord
          raise PermError, "redirect target #{domain} publishes no SPF record"
        end

        # Counts only once the name's own address records point back at the
        # client — the reverse zone belongs to whoever holds the address.
        def matching_ptr?(target)
          names = @budget.ptr(@ip.to_s)
          addresses = @budget.branch

          names.first(MAX_PTR_NAMES).any? { |name| confirmed?(name, addresses) && under?(name, target) }
        end

        def confirmed?(name, budget)
          addresses(name, budget).include?(@ip)
        rescue Error
          # A name whose address lookup fails is skipped; the search moves on.
          false
        end

        def under?(name, target)
          name = name.downcase.chomp(".")

          name == target || name.end_with?(".#{target}")
        end

        def result(status, detail = nil)
          SpfResult.new(status: status, domain: @domain, comment: comment(status, detail), lookups: @budget.lookups)
        end

        def comment(status, detail)
          case status
          when Status::PASS      then "domain of #{@sender} designates #{@ip} as permitted sender"
          when Status::FAIL      then "domain of #{@sender} does not designate #{@ip} as permitted sender"
          when Status::SOFTFAIL  then "domain of transitioning #{@sender} does not designate #{@ip} as permitted sender"
          when Status::NEUTRAL   then "#{@ip} is neither permitted nor denied by domain of #{@sender}"
          when Status::NONE      then "#{@domain} does not designate permitted sender hosts"
          when Status::PERMERROR then "permanent error in processing #{@domain}: #{detail}"
          when Status::TEMPERROR then "temporary error in processing #{@domain}: #{detail}"
          end
        end
    end
  end
end
