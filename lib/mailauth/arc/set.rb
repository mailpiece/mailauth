module MailAuth
  module Arc
    # The three header fields sharing one instance value (RFC 8617 §4.2). Each
    # is held as the list of fields claiming this instance, so a set that
    # carries two of anything can say so rather than quietly keeping one.
    class Set
      attr_reader :instance

      def initialize(instance)
        @instance = instance
        @fields = { authentication_results: [], message_signature: [], seal: [] }
      end

      def add(kind, field)
        @fields.fetch(kind) << field
      end

      def complete?
        @fields.each_value.all?(&:one?)
      end

      # A tag list that doesn't parse leaves nothing to verify against, and no
      # reading of the rest can rescue it (RFC 6376 §3.2).
      def readable?
        !seal_tags.nil? && !message_signature_tags.nil?
      end

      def authentication_results
        @fields[:authentication_results].first
      end

      def message_signature
        @fields[:message_signature].first
      end

      def seal
        @fields[:seal].first
      end

      # The status this hop stamped, which §5.2 step 3.3 holds to "none" at
      # instance 1 and "pass" above it.
      def chain_status
        seal_tags.to_h["cv"].to_s.downcase
      end

      def seal_tags
        return @seal_tags if defined?(@seal_tags)

        @seal_tags = Arc.tags_in(seal)
      end

      def message_signature_tags
        return @message_signature_tags if defined?(@message_signature_tags)

        @message_signature_tags = Arc.tags_in(message_signature)
      end

      # The payload an Authentication-Results header would carry, with the
      # instance tag that prefixes it here (§4.1.1) taken off.
      def authentication_results_payload
        Arc.value_of(authentication_results).to_s.sub(INSTANCE_PREFIX, "").strip
      end

      # Best effort, and never load-bearing: the chain's validity is a question
      # about signatures, so an unreadable assertion must not fail it. A name
      # carrying a dot is one of RFC 8601's properties (`smtp.mailfrom`), not a
      # method, and says nothing about a verdict.
      def claimed
        authentication_results_payload.scan(/(?<![\w.-])([a-z][a-z0-9-]*)[ \t]*=[ \t]*([a-z]+)/i).
          each_with_object({}) { |(method, result), claims| claims[method.downcase] ||= result.downcase }
      end
    end
  end
end
