require "mailauth/dkim"
require "mailauth/arc/chain"
require "mailauth/arc/message_signature"
require "mailauth/arc/seal"

module MailAuth
  # RFC 8617. Records what each hop concluded before forwarding broke SPF/DKIM,
  # sealed so later edits show. A valid chain proves only that each hop sealed
  # what it sealed — trusting any sealer is the caller's decision, not answered here.
  module Arc
    CRLF = "\r\n".b

    # §4.2.1. The ceiling is enforced before any key is fetched: each set
    # otherwise costs a lookup, and a long chain is cheap to write.
    MAXIMUM_SETS = 50

    CHAIN_STATUSES = %w[ none fail pass ].freeze
    CANONICALIZATIONS = Dkim::CANONICALIZATIONS

    HASHES = %w[ sha256 ].freeze
    SIGNING_ALGORITHMS = Dkim::SIGNING_ALGORITHMS

    # §4.1.1 puts the instance ahead of the payload an AAR carries, where the
    # other two hold it among their tags.
    INSTANCE_PREFIX = /\A[ \t\r\n]*i[ \t\r\n]*=[ \t\r\n]*(\d+)[ \t\r\n]*;/n

    # `now` is taken for symmetry with the other checks and not consulted: ARC
    # gives a chain no lifetime, and a message can sit in a queue for days
    # without that saying anything about the hops it already crossed.
    def self.verify(message, resolver: MailResolver::Resolver.new, now: Time.now)
      Validation.new(message, resolver: resolver).result
    end

    def self.value_of(field)
      field&.split(":", 2)&.last
    end

    def self.tags_in(field)
      Dkim.parse_tags(value_of(field).to_s)
    end

    # RFC 8617 never registered sha1; DKIM's list matches only since retiring it.
    def self.signing_algorithm?(algorithm)
      SIGNING_ALGORITHMS.include?(signing_algorithm(algorithm)) && HASHES.include?(hash_algorithm(algorithm))
    end

    def self.signing_algorithm(algorithm)
      algorithm.to_s.split("-").first.to_s.downcase
    end

    def self.hash_algorithm(algorithm)
      algorithm.to_s.split("-").last.to_s.downcase
    end

    # The validator of §5.2, in its order. Every failure is permanent, DNS
    # included (§5.2.1), so a chain is only ever pass, fail, or none — the
    # reason a hop failed survives on that set rather than in the status.
    class Validation
      def initialize(message, resolver:)
        @message, @resolver = message, resolver
        @chain = Chain.new(message)
        @seals = {}
        @signatures = {}
      end

      def result
        if @chain.empty?
          result_of Status::NONE, comment: "no ARC sets"
        elsif @chain.oversized?
          result_of Status::FAIL, comment: "more than #{MAXIMUM_SETS} ARC sets"
        elsif sealed_as_failed?
          result_of Status::FAIL, comment: "sealed cv=fail at i=#{@chain.newest.instance}"
        elsif error = @chain.structural_error
          result_of Status::FAIL, comment: error
        elsif !newest_signature_verifies?
          result_of Status::FAIL, comment: "ARC-Message-Signature i=#{@chain.newest.instance} did not verify"
        elsif broken = broken_seal
          result_of Status::FAIL, comment: "ARC-Seal i=#{broken.instance} did not verify"
        else
          result_of Status::PASS
        end
      end

      private
        # Step 2, ahead of the structural checks: a chain the newest hop has
        # already declared broken is broken whatever else it looks like.
        def sealed_as_failed?
          @chain.newest&.complete? && @chain.newest.chain_status == "fail"
        end

        # Step 4. Only the newest, and deliberately: an intermediary that
        # rewrites a subject line invalidates the hop before it, which is the
        # very situation ARC exists to carry a message through.
        def newest_signature_verifies?
          signature_for(@chain.newest).status == Status::PASS
        end

        def signature_for(set)
          @signatures[set.instance] ||=
            MessageSignature.new(@message, set.message_signature, set.message_signature_tags, resolver: @resolver).result
        end

        # Step 6, newest first, each seal over the chain as it stood when that
        # hop sealed it.
        def broken_seal
          @chain.ordered.reverse.find { |set| seal_for(set).status != Status::PASS }
        end

        def seal_for(set)
          @seals[set.instance] ||= Seal.new(@chain.through(set.instance), resolver: @resolver).result
        end

        def result_of(status, comment: nil)
          ArcResult.new(status: status, sets: reported_sets, comment: comment,
            oldest_pass: (method(:oldest_pass) if status == Status::PASS))
        end

        # A chain that never got as far as verifying anything still reports the
        # hops it found, so a reader can see who sealed what.
        def reported_sets
          @chain.ordered.map do |set|
            ArcSet.new(instance: set.instance, chain_status: set.chain_status,
              seal: @seals[set.instance], message_signature: @signatures[set.instance],
              authentication_results: set.authentication_results_payload, claimed: set.claimed)
          end
        end

        # Step 5, optional: the oldest hop whose signature still verifies, which
        # says how far back the message is unmodified without bearing on whether
        # the chain is valid.
        def oldest_pass
          broken = @chain.ordered[0..-2].reverse.find { |set| signature_for(set).status != Status::PASS }

          broken ? broken.instance + 1 : 0
        end
    end
  end
end
