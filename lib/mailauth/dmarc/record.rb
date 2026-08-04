require "mailauth/dmarc/organizational_domain"

module MailAuth
  module Dmarc
    # The policy a domain publishes at _dmarc.<domain>, plus the one thing the
    # text itself doesn't say: whether we had to walk up to the organizational
    # domain to find it, which is what decides between `p` and `sp`.
    class Record
      DMARC1 = /\Av=DMARC1\b/i
      TAGS = %w[ v p sp adkim aspf pct rua ruf fo rf ri ].freeze
      POLICIES = %w[ none quarantine reject ].freeze
      STRICT = "s".freeze
      DEFAULT_PCT = 100

      class << self
        # DNS failures are raised rather than swallowed: "we couldn't ask" is
        # a different answer from "there is nothing there".
        def find(domain, resolver:)
          at(domain, resolver: resolver) || at_organizational_domain(domain, resolver: resolver)
        end

        private
          def at(domain, resolver:, organizational: false)
            texts = resolver.txt("_dmarc.#{domain}").map(&:strip).grep(DMARC1)

            # Two policies are as good as none: RFC 7489 §6.6.3 would rather
            # apply nothing than guess which one the domain meant.
            if texts.one? && (record = new(texts.first, organizational: organizational)).usable?
              record
            end
          rescue MailResolver::NotFound
            nil
          end

          # A subdomain with no record of its own — or one too broken to apply —
          # falls back to its parent, which is how a single record at the
          # organizational domain covers a whole tree of hostnames.
          def at_organizational_domain(domain, resolver:)
            organizational = OrganizationalDomain.of(domain)

            at(organizational, resolver: resolver, organizational: true) unless organizational == domain
          end
      end

      attr_reader :tags

      def initialize(text, organizational: false)
        @text, @organizational = text, organizational
        @tags = parse(text)
      end

      # `p` is the one required tag beyond the version; without it the record
      # may as well not exist.
      def usable?
        !requested_policy.nil?
      end

      # RFC 7489 §6.6.3: mail from a subdomain answers to the parent's `sp`,
      # deliberately not the parent's own `p` — an organization can reject
      # forgeries of unused hostnames while still easing its own mail through
      # under p=none.
      def policy
        if organizational? && subdomain_policy
          subdomain_policy
        else
          requested_policy
        end
      end

      # Surfaced, never applied: rolling the `pct` dice here would make the
      # same message pass and fail at random, which an authentication result
      # must never do.
      def pct
        Integer(tags["pct"], exception: false)&.clamp(0, 100) || DEFAULT_PCT
      end

      # Both alignment tags default to relaxed, so only an explicit "s" is strict.
      def strict_dkim?
        tags["adkim"]&.downcase == STRICT
      end

      def strict_spf?
        tags["aspf"]&.downcase == STRICT
      end

      def organizational?
        @organizational
      end

      def to_s
        @text
      end

      private
        # Unknown tags are dropped rather than treated as an error, so a
        # record using a tag from a later extension still governs the mail it
        # was published for.
        def parse(text)
          text.to_s.split(";").filter_map { |tag|
            name, value = tag.split("=", 2)
            name = name.to_s.strip.downcase

            [ name, value.strip ] if value && TAGS.include?(name)
          }.to_h
        end

        def requested_policy
          validated(tags["p"])
        end

        def subdomain_policy
          validated(tags["sp"])
        end

        def validated(policy)
          policy&.downcase&.then { |value| value if POLICIES.include?(value) }
        end
    end
  end
end
