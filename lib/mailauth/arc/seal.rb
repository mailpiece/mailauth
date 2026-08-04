require "openssl"

module MailAuth
  module Arc
    # An ARC-Seal (RFC 8617 §4.1.3), which signs the chain rather than the
    # message: no body, no h= naming what it covers — its scope is fixed by
    # §5.1.1 — and relaxed header canonicalization only.
    class Seal
      REQUIRED_TAGS = %w[ i a b d s cv ].freeze

      def initialize(sets, resolver:)
        @sets, @resolver = sets, resolver
        @set = sets.last
        @tags = @set.seal_tags
      end

      def result
        validate

        verified? ? seal(Status::PASS) : seal(Status::FAIL, comment: "bad signature")
      rescue Dkim::Malformed => error
        seal Status::PERMERROR, comment: error.message
      rescue MailResolver::NotFound
        seal Status::PERMERROR, comment: "no key for #{key_name}"
      rescue MailResolver::Timeout, MailResolver::ServerFailure
        seal Status::TEMPERROR, comment: "DNS failure resolving #{key_name}"
      end

      private
        def validate
          raise Dkim::Malformed, "invalid tag list" if @tags.nil?

          # §4.1.3: a seal names no headers, and one that tries is fatal to the
          # chain rather than merely ignored.
          raise Dkim::Malformed, "h= is not allowed on an ARC-Seal" if @tags.key?("h")

          if missing = REQUIRED_TAGS.find { |tag| @tags[tag].to_s.empty? }
            raise Dkim::Malformed, "missing #{missing}= tag"
          end

          raise Dkim::Malformed, "unsupported algorithm #{@tags["a"]}" unless Arc.signing_algorithm?(@tags["a"])
          raise Dkim::Malformed, "invalid cv= tag" unless CHAIN_STATUSES.include?(@tags["cv"].downcase)
          raise Dkim::Malformed, "invalid t= tag" if @tags["t"] && !@tags["t"].match?(/\A\d+\z/n)
        end

        def verified?
          Dkim::Algorithm.verified?(signed_headers, key: public_key, digest: digest,
            signature: unfolded("b").unpack1("m"))
        end

        # §5.1.1: every set from instance 1 upward, each contributing its AAR,
        # then its AMS, then its seal — this one's with b= emptied, and nothing
        # terminating the last line.
        def signed_headers
          @sets.flat_map { |set| headers_of(set) }.join(CRLF)
        end

        def headers_of(set)
          [ canonicalize(set.authentication_results), canonicalize(set.message_signature), canonical_seal(set) ]
        end

        def canonical_seal(set)
          if set.equal?(@set)
            canonicalize(set.seal).sub(/([;:\s]+b=)[^;]*/n, '\1')
          else
            canonicalize(set.seal)
          end
        end

        def canonicalize(field)
          Dkim::Canonicalization.field(field, "relaxed")
        end

        def public_key
          Dkim::PublicKey.retrieve(selector: @tags["s"], domain: @tags["d"],
            algorithm: Arc.signing_algorithm(@tags["a"]), resolver: @resolver)
        end

        def key_name
          Dkim::PublicKey.name_for(selector: @tags["s"], domain: @tags["d"])
        end

        def digest
          Dkim::HASHES.fetch(Arc.hash_algorithm(@tags["a"]))
        end

        def unfolded(tag)
          @tags[tag]&.gsub(/[ \t\r\n]+/n, "")
        end

        def seal(status, comment: nil)
          ArcSeal.new(status: status, domain: @tags&.[]("d")&.downcase, selector: @tags&.[]("s"),
            algorithm: @tags&.[]("a"), comment: comment)
        end
    end
  end
end
