require "openssl"

require "mailauth/message"
require "mailauth/domain"

module MailAuth
  module Dkim
    # Signs a message per RFC 6376 §5, relaxed/relaxed.
    class Signer
      # The RFC 6376 §5.4.1 example set: what a reader's client renders or threads on.
      DEFAULT_SIGNED_HEADERS = %w[
        from sender reply-to subject date message-id to cc
        mime-version content-type content-transfer-encoding
        in-reply-to references list-id list-help list-owner
        list-unsubscribe list-unsubscribe-post list-subscribe list-post
      ].freeze

      # Named in h= once more than they occur — a name past its count matches
      # nothing (§5.4.2), so an instance added after signing breaks the signature.
      OVERSIGNED_HEADERS = %w[ from to cc subject date reply-to message-id ].freeze

      def initialize(raw, domain:, selector:, key:, headers: nil, oversign: OVERSIGNED_HEADERS, expires_in: nil, now: Time.now)
        @message = Message.new(raw)
        @domain = Domain.normalize(domain)
        @selector = Domain.normalize(selector)
        @key = key
        @requested = (headers || DEFAULT_SIGNED_HEADERS).map(&:downcase)
        @oversign = oversign.map(&:downcase)
        @expires_in = expires_in
        @now = now
      end

      def signed_message
        field + @message.raw
      end

      def field
        @field ||= begin
          validate
          unsigned_field + [ signature ].pack("m0").scan(/.{1,72}/).join("\r\n\t") + CRLF
        end
      end

      private
        def validate
          raise ArgumentError, "unsupported key type #{@key.oid}" unless KEY_TYPES.key?(@key.oid)
          raise ArgumentError, "rsa key shorter than #{MINIMUM_RSA_BITS} bits" if undersized_rsa?
          raise ArgumentError, "From is not signed" unless signed_names.include?("from")
        end

        # Held to the same floor the verifier enforces, so no signature leaves
        # here that the other side is required to reject.
        def undersized_rsa?
          KEY_TYPES.fetch(@key.oid) == "rsa" && @key.n.num_bits < MINIMUM_RSA_BITS
        end

        # Ends with b=, where the signature lands — in the signed bytes and the
        # emitted field alike.
        def unsigned_field
          "DKIM-Signature: v=1; " + properties.join("\r\n\t")
        end

        def properties
          [
            "a=#{algorithm}; c=relaxed/relaxed;",
            "d=#{@domain};",
            "s=#{@selector}; t=#{@now.to_i};",
            expiration,
            "bh=#{body_hash};",
            "h=#{signed_names.join(":")};",
            "b="
          ].compact
        end

        def algorithm
          "#{KEY_TYPES.fetch(@key.oid)}-sha256"
        end

        def expiration
          "x=#{@now.to_i + @expires_in.to_i};" if @expires_in
        end

        def body_hash
          [ OpenSSL::Digest::SHA256.digest(Canonicalization.body(@message.body, "relaxed")) ].pack("m0")
        end

        def signed_names
          @signed_names ||= present_names + @oversign
        end

        def present_names
          @message.fields.map { |field| @message.field_name(field) }.select { |name| @requested.include?(name) }
        end

        def signature
          sign(signable)
        end

        # The emitted field itself is canonicalized and signed, unterminated —
        # no room to sign one thing and send another.
        def signable
          signed_fields.map { |field| Canonicalization.field(field, "relaxed") + CRLF }.join +
            Canonicalization.field(unsigned_field, "relaxed")
        end

        # Duplicates are taken bottom-up, the order a verifier takes them (§5.4.2).
        def signed_fields
          remaining = @message.fields.dup

          signed_names.filter_map do |name|
            if index = remaining.rindex { |field| @message.field_name(field) == name }
              remaining.delete_at(index)
            end
          end
        end

        def sign(data)
          Algorithm.sign(data, key: @key)
        end
    end
  end
end
