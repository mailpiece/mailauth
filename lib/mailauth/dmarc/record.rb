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
        #
        # Only a sole record answers, whatever it says: none or several send
        # us to the organizational domain, and the same there is no DMARC.
        def find(domain, resolver:)
          sole(texts_at(domain, resolver), organizational: false) || at_organizational_domain(domain, resolver: resolver)
        end

        private
          def texts_at(domain, resolver)
            resolver.txt("_dmarc.#{domain}").map(&:strip).grep(DMARC1)
          rescue MailResolver::NotFound
            []
          end

          def sole(texts, organizational:)
            new(texts.first, organizational: organizational) if texts.one?
          end

          # A subdomain without a sole record of its own falls back to its
          # parent, which is how a single record at the organizational domain
          # covers a whole tree of hostnames.
          def at_organizational_domain(domain, resolver:)
            organizational = OrganizationalDomain.of(domain)

            sole(texts_at(organizational, resolver), organizational: true) unless organizational == domain
          end
      end

      attr_reader :tags

      def initialize(text, organizational: false)
        @text, @organizational = text, organizational
        @tags = parse(text)
      end

      # RFC 7489 §6.6.3: mail from a subdomain answers to the parent's `sp`,
      # deliberately not the parent's own `p` — an organization can reject
      # forgeries of unused hostnames while still easing its own mail through
      # under p=none. A missing or misspelled policy is never enforced.
      def policy
        requested = organizational? && !tags["sp"].to_s.empty? ? tags["sp"] : tags["p"]

        requested.to_s.downcase.then { |value| POLICIES.include?(value) ? value : "none" }
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
    end
  end
end
