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

      def initialize(raw, domain:, selector:, key:, headers: nil, oversign: OVERSIGNED_HEADERS, expires_in: nil,
        now: Time.now, field_name: "DKIM-Signature", instance: nil)
        @message = Message.new(raw)
        @domain = Domain.normalize(domain)
        @selector = Domain.normalize(selector)
        @key = key
        @requested = (headers || DEFAULT_SIGNED_HEADERS).map(&:downcase)
        @oversign = oversign.map(&:downcase)
        @expires_in = expires_in
        @now = now
        @field_name, @instance = field_name, instance
      end

      def signed_message
        field + @message.raw
      end

      def field
        @field ||= begin
          validate
          signed_field + CRLF
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

        # The signature lands where b= already stood in the bytes that were
        # signed, leaving no room to sign one layout and send another.
        def signed_field
          unsigned_field.sub(/(?<=[;:\s]b=)/n, encoded(signature))
        end

        # An ARC signature stays on one line where DKIM's folds: the seal signs
        # this field, and relaxed canonicalization turns a fold in b= into space.
        def encoded(signature)
          base64 = [ signature ].pack("m0")

          arc? ? base64 : base64.scan(/.{1,72}/).join("\r\n\t")
        end

        # An instance number is what makes this an ARC-Message-Signature: DKIM
        # has no i= of this kind, and ARC has no signature without one.
        def arc?
          !@instance.nil?
        end

        def unsigned_field
          "#{@field_name}: " + properties.join("\r\n\t")
        end

        # §4.1.2 makes an AMS this signature under another name: no v=, an i=, and
        # alphabetical tags — which is where the ARC signing vectors put b=.
        def properties
          arc? ? arc_properties : dkim_properties
        end

        def dkim_properties
          [
            "v=1; a=#{algorithm}; c=relaxed/relaxed;",
            "d=#{@domain};",
            "s=#{@selector}; t=#{@now.to_i};",
            expiration,
            "bh=#{body_hash};",
            "h=#{signed_names.join(":")};",
            "b="
          ].compact
        end

        def arc_properties
          [
            "a=#{algorithm}; b=;",
            "bh=#{body_hash}; c=relaxed/relaxed;",
            "d=#{@domain}; h=#{signed_names.join(":")};",
            "i=#{@instance}; s=#{@selector}; t=#{@now.to_i}"
          ]
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
