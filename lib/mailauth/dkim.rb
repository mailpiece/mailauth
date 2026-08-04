require "openssl"

require "mailauth/dmarc/alignment"
require "mailauth/dkim/canonicalization"
require "mailauth/dkim/algorithm"
require "mailauth/dkim/public_key"
require "mailauth/dkim/signer"

module MailAuth
  # RFC 6376. Verifies the DKIM-Signature headers on a message against the
  # public keys their domains publish, and signs outgoing messages with the
  # private ones.
  module Dkim
    CRLF = "\r\n".b

    # Always maps to permerror: retrying changes nothing when a tag is missing,
    # the algorithm is unsupported, or the key is unreadable.
    class Malformed < StandardError; end

    # RFC 8301 §3.1 retired rsa-sha1: a verifier must not consider one valid.
    HASHES = { "sha256" => OpenSSL::Digest::SHA256 }.freeze
    SIGNING_ALGORITHMS = %w[ rsa ed25519 ].freeze

    # What OpenSSL calls a key, mapped to what a= calls it.
    KEY_TYPES = { "rsaEncryption" => "rsa", "ED25519" => "ed25519" }.freeze

    CANONICALIZATIONS = %w[ simple relaxed ].freeze
    REQUIRED_TAGS = %w[ v a b bh d h s ].freeze

    # RFC 6376 §3.2: ALPHA *ALNUMPUNC.
    TAG_NAME = /\A[a-zA-Z][a-zA-Z0-9_]*\z/n

    # RFC 6376 §8.4. Each signature costs a lookup for a key its sender named,
    # and headers are cheap to write, so only the first so many are answered.
    MAXIMUM_SIGNATURES = 10

    # Shorter RSA keys are factorable cheaply enough to prove nothing.
    MINIMUM_RSA_BITS = 1024

    # ed25519 keys travel as 32 raw bytes (RFC 8463 §3), so we put back the
    # SubjectPublicKeyInfo wrapper OpenSSL insists on before reading one.
    ED25519_SPKI_PREFIX = [ "302a300506032b6570032100" ].pack("H*")

    def self.verify(message, resolver: MailResolver::Resolver.new, now: Time.now)
      fields = message.fields_named("dkim-signature")

      signatures = fields.first(MAXIMUM_SIGNATURES).map do |field|
        Verification.new(message, field, resolver:, now:).result
      end

      # The ones left over are reported rather than dropped: a verifier that
      # quietly ignores a signature says a message carried fewer than it did.
      if fields.empty?
        signatures << Signature.new(status: Status::NONE, comment: "message not signed")
      elsif fields.length > MAXIMUM_SIGNATURES
        signatures << Signature.new(status: Status::PERMERROR,
          comment: "#{fields.length - MAXIMUM_SIGNATURES} more signatures not evaluated")
      end

      DkimResult.new(signatures:)
    end

    def self.sign(raw, domain:, selector:, key:, headers: nil, oversign: Signer::OVERSIGNED_HEADERS, expires_in: nil, now: Time.now)
      Signer.new(raw, domain:, selector:, key:, headers:, oversign:, expires_in:, now:).signed_message
    end

    # RFC 6376 §3.2: a malformed, repeated, or empty tag invalidates the whole
    # list, not just itself — reading the rest would treat a forged tag as
    # legitimate beside the dropped one. Values fold across lines; callers strip
    # whitespace themselves where it matters.
    def self.parse_tags(text)
      specs = text.split(";", -1)
      specs.pop if specs.last&.strip&.empty?   # the tag-list's optional trailing ";"

      specs.each_with_object({}) do |spec, tags|
        name, value = spec.split("=", 2)
        name = name.to_s.strip

        return nil unless value && name.match?(TAG_NAME) && !tags.key?(name)

        tags[name] = value.strip
      end
    end

    # One DKIM-Signature header, taken from its tags to a verdict.
    class Verification
      def initialize(message, field, resolver:, now:)
        @message, @field, @resolver, @now = message, field, resolver, now
        tags = Dkim.parse_tags(field.split(":", 2).last.to_s)
        @well_formed = !tags.nil?
        @tags = tags || {}
      end

      def result
        validate

        if expired?
          failed("signature expired")
        elsif postdated?
          failed("signature timestamp in the future")
        elsif body_hash_matches?
          verified? ? signature(Status::PASS) : failed("bad signature")
        else
          # Some verifiers call this neutral. We call it failure: the signer
          # said what the body would hash to, and it hashes to something else.
          failed("body hash did not verify")
        end
      rescue Malformed => error
        signature(Status::PERMERROR, comment: error.message)
      rescue MailResolver::NotFound
        signature(Status::PERMERROR, comment: "no key for #{key_name}")
      rescue MailResolver::Timeout, MailResolver::ServerFailure
        signature(Status::TEMPERROR, comment: "DNS failure resolving #{key_name}")
      end

      private
        def validate
          raise Malformed, "invalid tag list" unless @well_formed
          raise Malformed, "unsupported signature version" unless @tags["v"] == "1"

          if missing = REQUIRED_TAGS.find { |tag| @tags[tag].to_s.empty? }
            raise Malformed, "missing #{missing}= tag"
          end

          unless SIGNING_ALGORITHMS.include?(signing_algorithm) && HASHES.key?(hash_algorithm)
            raise Malformed, "unsupported algorithm #{@tags["a"]}"
          end

          unless CANONICALIZATIONS.include?(header_canonicalization) && CANONICALIZATIONS.include?(body_canonicalization)
            raise Malformed, "unsupported canonicalization #{canonicalization}"
          end

          # A signature that leaves From unsigned says nothing about who the
          # message claims to be from, which is the only question here.
          raise Malformed, "From is not signed" unless signed_header_names.include?("from")

          raise Malformed, "invalid l= tag" if @tags["l"] && !@tags["l"].match?(/\A\d+\z/n)
        end

        def expired?
          expires_at && expires_at < @now
        end

        def expires_at
          Time.at(@tags["x"].to_i) if @tags["x"]&.match?(/\A\d+\z/n)
        end

        def postdated?
          signed_at && signed_at > @now
        end

        def signed_at
          Time.at(@tags["t"].to_i) if @tags["t"]&.match?(/\A\d+\z/n)
        end

        def body_hash_matches?
          digest.digest(signed_body) == unfolded("bh").unpack1("m")
        end

        # l= counts canonicalized bytes, not the bytes that arrived — the tag
        # signs a prefix of the canonical body, not of the message on the wire.
        def signed_body
          if body_limit
            canonical_body.byteslice(0, body_limit)
          else
            canonical_body
          end
        end

        def body_limit
          @tags["l"].to_i if @tags["l"]&.match?(/\A\d+\z/n)
        end

        def canonical_body
          @canonical_body ||= Canonicalization.body(@message.body, body_canonicalization)
        end

        def verified?
          Algorithm.verified?(canonical_headers, key: public_key, digest: digest,
            signature: unfolded("b").unpack1("m"))
        end

        def public_key
          PublicKey.retrieve(selector: @tags["s"], domain: @tags["d"],
            algorithm: signing_algorithm, resolver: @resolver)
        end

        def key_name
          PublicKey.name_for(selector: @tags["s"], domain: @tags["d"])
        end

        # No trailing CRLF after the signature field: the bytes after b= are
        # what the signature covers.
        def canonical_headers
          signed_fields.map { |field| canonicalize_field(field) + CRLF }.join + canonical_signature_field
        end

        # Takes the last unused instance of each named header, walking upward
        # through duplicates. Naming a header that isn't present (oversigning)
        # contributes nothing but forbids one being added later.
        def signed_fields
          remaining = @message.fields.dup

          signed_header_names.filter_map do |name|
            if index = remaining.rindex { |field| @message.field_name(field) == name }
              remaining.delete_at(index)
            end
          end
        end

        def signed_header_names
          unfolded("h").to_s.downcase.split(":").reject(&:empty?)
        end

        def canonical_signature_field
          canonicalize_field(@field).sub(/([;:\s]+b=)[^;]*/n, '\1')
        end

        def canonicalize_field(field)
          Canonicalization.field(field, header_canonicalization)
        end

        def digest
          HASHES.fetch(hash_algorithm)
        end

        def signing_algorithm
          @tags["a"].to_s.split("-").first.to_s.downcase
        end

        def hash_algorithm
          @tags["a"].to_s.split("-").last.to_s.downcase
        end

        def header_canonicalization
          canonicalization.split("/").first
        end

        def body_canonicalization
          canonicalization.split("/")[1] || "simple"
        end

        def canonicalization
          @tags["c"].to_s.downcase.strip.empty? ? "simple/simple" : @tags["c"].downcase.strip
        end

        # Tags whose value is base64 or a colon-separated list carry folding
        # whitespace that was never part of the value.
        def unfolded(tag)
          @tags[tag]&.gsub(/[ \t\r\n]+/n, "")
        end

        def failed(comment)
          signature(Status::FAIL, comment:)
        end

        def signature(status, comment: nil)
          Signature.new(status:, domain: @tags["d"]&.downcase, selector: @tags["s"], algorithm: @tags["a"],
            canonicalization: canonicalization, comment:, aligned: aligned?, under_sized: under_sized)
        end

        # Relaxed DMARC alignment: the From: domain and the signing domain need
        # only share an organizational domain, not match exactly.
        def aligned?
          from, signing_domain = @message.header_from_domain, @tags["d"]&.downcase

          if from && signing_domain
            Dmarc::Alignment.aligned?(from, signing_domain, strict: false)
          else
            false
          end
        end

        # In canonicalized bytes — the tail a signature says nothing about,
        # and where content gets smuggled.
        def under_sized
          if body_limit && CANONICALIZATIONS.include?(body_canonicalization)
            uncovered = canonical_body.bytesize - body_limit
            uncovered if uncovered.positive?
          end
        end
    end
  end
end
