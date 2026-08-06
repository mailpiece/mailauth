require "openssl"

require "mailauth/message"
require "mailauth/domain"

module MailAuth
  module Arc
    # Adds one ARC set to a message (RFC 8617 §5.1). Sealing looks nothing up: a
    # hop writes down what it already concluded rather than concluding it twice.
    class Sealer
      def initialize(message, authentication_results:, chain_status:, domain:, selector:, key:,
        headers: nil, oversign: [], now: Time.now)
        @message = message.is_a?(Message) ? message : Message.new(message)
        @authentication_results = authentication_results
        @chain_status = chain_status.to_s.strip.downcase
        @domain, @selector, @key = Domain.normalize(domain), Domain.normalize(selector), key
        @headers, @oversign, @now = headers, oversign, now
        @chain = Chain.new(@message)

        validate
      end

      def sealed_message
        fields + @message.raw
      end

      # Seal first, so prepending the three leaves the newest set on top.
      def fields
        seal_field + message_signature_field + authentication_results_field
      end

      # §4.1.3, and signed last of the three: it covers the two below it, which
      # therefore have to exist before it can be computed.
      def seal_field
        @seal_field ||= sealed_with(sign(sealed_chain))
      end

      def message_signature_field
        @message_signature_field ||= Dkim::Signer.new(@message.raw, domain: @domain, selector: @selector,
          key: @key, headers: @headers, oversign: @oversign, now: @now,
          field_name: "ARC-Message-Signature", instance: instance).field
      end

      # §4.1.1: an Authentication-Results value behind the instance it belongs to.
      def authentication_results_field
        @authentication_results_field ||=
          "ARC-Authentication-Results: i=#{instance}; " + results_value + CRLF
      end

      private
        def validate
          raise ArgumentError, "unknown chain status #{@chain_status}" unless CHAIN_STATUSES.include?(@chain_status)

          # §4.1.2: an AMS naming an ARC header would leave the seal signing a
          # signature that signs it back.
          raise ArgumentError, "h= must not cover ARC header fields" if arc_named?

          # A 51st set is one every validator has to fail (§4.2.1), so it never
          # gets written in the first place.
          raise ArgumentError, "chain already carries #{MAXIMUM_SETS} sets" if instance > MAXIMUM_SETS
        end

        def arc_named?
          (@headers.to_a + @oversign).any? { |name| name.to_s.downcase.start_with?("arc-") }
        end

        # §5.1 step 3: one above the highest instance already on the message,
        # which for an intact chain is one above its length.
        def instance
          @instance ||= (@chain.ordered.last&.instance || 0) + 1
        end

        # On one line like the signature below it, for the same reason: the next
        # hop's seal signs this field as it stands.
        def sealed_with(signature)
          unsigned_seal.sub(/(?<=[;:\s]b=)/n, [ signature ].pack("m0")) + CRLF
        end

        # §5.1.1: every set from instance 1 up gives its AAR, AMS, then seal, ours
        # last with b= empty. §5.1.2 narrows that to our own set on a broken chain.
        def sealed_chain
          preceding = @chain_status == "fail" ? [] : @chain.ordered.flat_map { |set| fields_of(set) }

          (preceding + [ authentication_results_field, message_signature_field, unsigned_seal ]).
            map { |field| Dkim::Canonicalization.field(field, "relaxed") }.join(CRLF)
        end

        def fields_of(set)
          [ set.authentication_results, set.message_signature, set.seal ]
        end

        # §4.1.3: no h= and no body hash, since a seal covers the chain rather
        # than the message. Alphabetical like the AMS, which puts b= second.
        def unsigned_seal
          @unsigned_seal ||= "ARC-Seal: a=#{algorithm}; b=;\r\n\tcv=#{@chain_status}; d=#{@domain};" \
            "\r\n\ti=#{instance}; s=#{@selector}; t=#{@now.to_i}"
        end

        def algorithm
          "#{Dkim::KEY_TYPES.fetch(@key.oid)}-sha256"
        end

        def sign(data)
          Dkim::Algorithm.sign(data, key: @key)
        end

        # A line break arriving without folding whitespace behind it would end
        # the field and start another (RFC 5322 §2.2.3).
        def results_value
          @authentication_results.to_s.b.gsub(/\r?\n(?![ \t])/n, "\r\n ").strip
        end
    end
  end
end
