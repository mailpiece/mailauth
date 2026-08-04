require "mailauth/dmarc/alignment"
require "mailauth/dmarc/record"

module MailAuth
  # RFC 7489. Do the SPF or DKIM results line up with the From: domain a reader
  # sees, and what does that domain ask us to do when they don't?
  module Dmarc
    class << self
      # Takes the already-computed SPF and DKIM results — alignment is a
      # comparison, not a check of its own. None or several From: domains is
      # `permerror`, not `none`: the message is malformed, not simply
      # unpolicied.
      def check(header_from:, spf:, dkim:, resolver: MailResolver::Resolver.new)
        if domain = sole_domain(header_from)
          evaluate(domain, spf: spf, dkim: dkim, resolver: resolver)
        else
          DmarcResult.new(status: Status::PERMERROR)
        end
      end

      private
        def sole_domain(header_from)
          domains = Array(header_from).map { |domain| domain.to_s.strip.downcase.chomp(".") }.reject(&:empty?)

          domains.first if domains.one?
        end

        def evaluate(domain, spf:, dkim:, resolver:)
          if record = Record.find(domain, resolver: resolver)
            verdict(domain, record, spf: spf, dkim: dkim)
          else
            DmarcResult.new(status: Status::NONE)
          end
        rescue MailResolver::Timeout, MailResolver::ServerFailure
          # Calling this `none` would hand a spoofer a free pass every time a
          # nameserver hiccups.
          DmarcResult.new(status: Status::TEMPERROR)
        end

        def verdict(domain, record, spf:, dkim:)
          alignment = { dkim: dkim_aligned?(domain, dkim, record), spf: spf_aligned?(domain, spf, record) }

          DmarcResult.new \
            status: alignment.values.any? ? Status::PASS : Status::FAIL,
            policy: record.policy,
            pct: record.pct,
            alignment: alignment,
            record: record.to_s
        end

        # .any? because a forwarder's own valid signature can sit happily
        # beside the author's — one aligned pass is enough.
        def dkim_aligned?(domain, dkim, record)
          Array(dkim&.passing_domains).any? do |signing_domain|
            Alignment.aligned?(domain, signing_domain, strict: record.strict_dkim?)
          end
        end

        def spf_aligned?(domain, spf, record)
          spf&.status == Status::PASS && Alignment.aligned?(domain, spf.domain, strict: record.strict_spf?)
        end
    end
  end
end
