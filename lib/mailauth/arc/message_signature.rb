require "openssl"

module MailAuth
  module Arc
    # An ARC-Message-Signature (RFC 8617 §4.1.2): a DKIM signature over the
    # message in all but name, differing in carrying no version tag, in taking
    # i= as the instance rather than an identity, and in leaving From free —
    # what it covers is the hop's business, not ours.
    class MessageSignature
      REQUIRED_TAGS = %w[ a b bh d h s ].freeze

      # §4.1.2 gives the AMS DKIM's syntax and semantics bar three named
      # differences, none of them canonicalization, which would leave an absent
      # c= meaning simple/simple (RFC 6376 §3.5). Signers read it the other way
      # and the conformance suite requires relaxed, so relaxed it is: simple
      # canonicalization survives no intermediary, which is the one thing every
      # message carrying this header has crossed.
      DEFAULT_CANONICALIZATION = "relaxed/relaxed".freeze

      def initialize(message, field, tags, resolver:)
        @message, @field, @tags, @resolver = message, field, tags, resolver
      end

      def result
        validate

        if body_hash_matches?
          verified? ? signature(Status::PASS) : failed("bad signature")
        else
          failed("body hash did not verify")
        end
      rescue Dkim::Malformed => error
        signature Status::PERMERROR, comment: error.message
      rescue MailResolver::NotFound
        signature Status::PERMERROR, comment: "no key for #{key_name}"
      rescue MailResolver::Timeout, MailResolver::ServerFailure
        signature Status::TEMPERROR, comment: "DNS failure resolving #{key_name}"
      end

      private
        def validate
          raise Dkim::Malformed, "invalid tag list" if @tags.nil?

          if missing = REQUIRED_TAGS.find { |tag| !@tags.key?(tag) }
            raise Dkim::Malformed, "missing #{missing}= tag"
          end

          raise Dkim::Malformed, "empty #{empty_tag}= tag" if empty_tag
          raise Dkim::Malformed, "empty c= tag" if @tags.key?("c") && @tags["c"].strip.empty?
          raise Dkim::Malformed, "unsupported algorithm #{@tags["a"]}" unless Arc.signing_algorithm?(@tags["a"])

          # §4.1.2 bars an AMS from covering ARC header fields. The seal is the
          # one that bites: it signs this signature, so a signature signing it
          # back leaves each waiting on the other.
          raise Dkim::Malformed, "h= covers the ARC-Seal" if signed_names.include?("arc-seal")

          unless CANONICALIZATIONS.include?(header_canonicalization) && CANONICALIZATIONS.include?(body_canonicalization)
            raise Dkim::Malformed, "unsupported canonicalization #{canonicalization}"
          end

          raise Dkim::Malformed, "invalid t= tag" if @tags["t"] && !@tags["t"].match?(/\A\d+\z/n)
          raise Dkim::Malformed, "invalid l= tag" if @tags["l"] && !@tags["l"].match?(/\A\d+\z/n)
        end

        # h= may name nothing at all, but the tags carrying an identity or the
        # maths cannot be present and blank.
        def empty_tag
          (REQUIRED_TAGS - %w[ h ]).find { |tag| @tags[tag].to_s.empty? }
        end

        def body_hash_matches?
          digest.digest(signed_body) == unfolded("bh").unpack1("m")
        end

        def signed_body
          body_limit ? canonical_body.byteslice(0, body_limit) : canonical_body
        end

        def body_limit
          @tags["l"].to_i if @tags["l"]&.match?(/\A\d+\z/n)
        end

        def canonical_body
          @canonical_body ||= Dkim::Canonicalization.body(@message.body, body_canonicalization)
        end

        def verified?
          Dkim::Algorithm.verified?(canonical_headers, key: public_key, digest: digest,
            signature: unfolded("b").unpack1("m"))
        end

        def public_key
          Dkim::PublicKey.retrieve(selector: @tags["s"], domain: @tags["d"],
            algorithm: Arc.signing_algorithm(@tags["a"]), resolver: @resolver)
        end

        def key_name
          Dkim::PublicKey.name_for(selector: @tags["s"], domain: @tags["d"])
        end

        # The signature's own field closes the input with its b= emptied and no
        # terminator, exactly as a DKIM signature does (RFC 6376 §3.7).
        def canonical_headers
          signed_fields.map { |field| canonicalize(field) + CRLF }.join +
            canonicalize(@field).sub(/([;:\s]+b=)[^;]*/n, '\1')
        end

        # The last unused instance of each name, walking upward through
        # duplicates (RFC 6376 §5.4.2).
        def signed_fields
          remaining = @message.fields.dup

          signed_names.filter_map do |name|
            if index = remaining.rindex { |field| @message.field_name(field) == name }
              remaining.delete_at(index)
            end
          end
        end

        def signed_names
          unfolded("h").to_s.downcase.split(":").reject(&:empty?)
        end

        def canonicalize(field)
          Dkim::Canonicalization.field(field, header_canonicalization)
        end

        def digest
          Dkim::HASHES.fetch(Arc.hash_algorithm(@tags["a"]))
        end

        def header_canonicalization
          canonicalization.split("/").first
        end

        def body_canonicalization
          canonicalization.split("/")[1] || "simple"
        end

        def canonicalization
          @tags["c"].to_s.downcase.strip.empty? ? DEFAULT_CANONICALIZATION : @tags["c"].downcase.strip
        end

        def unfolded(tag)
          @tags[tag]&.gsub(/[ \t\r\n]+/n, "")
        end

        def failed(comment)
          signature(Status::FAIL, comment: comment)
        end

        def signature(status, comment: nil)
          ArcSignature.new(status: status, domain: @tags&.[]("d")&.downcase, selector: @tags&.[]("s"),
            algorithm: @tags&.[]("a"), comment: comment)
        end
    end
  end
end
