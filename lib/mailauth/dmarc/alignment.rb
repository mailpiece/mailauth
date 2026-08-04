require "mailauth/domain"
require "mailauth/dmarc/organizational_domain"

module MailAuth
  # RFC 7489 §3.1. Does a domain that SPF or DKIM authenticated stand for the
  # same organization as the From: domain a reader sees?
  module Dmarc
    module Alignment
      class << self
        # Strict and relaxed are separate rules, not a fallback pair — falling
        # back to relaxed after a strict miss would make `adkim=s`/`aspf=s`
        # decorative.
        def aligned?(from, candidate, strict:)
          from, candidate = normalize(from), normalize(candidate)

          if from.empty? || candidate.empty?
            false
          elsif strict
            from == candidate
          else
            OrganizationalDomain.of(from) == OrganizationalDomain.of(candidate)
          end
        end

        private
          def normalize(domain)
            Domain.normalize(domain)
          end
      end
    end
  end
end
