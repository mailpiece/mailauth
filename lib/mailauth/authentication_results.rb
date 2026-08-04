module MailAuth
  # RFC 8601. States the verdicts in an Authentication-Results header for a
  # downstream MTA to read.
  class AuthenticationResults
    LINE_WIDTH = 78                                       # RFC 5322 §2.1.1
    INDENT = " ".freeze
    FOLD = "\r\n#{INDENT}".freeze

    # RFC 8601 §2.2 requires an authserv-id. Without one we say so out loud
    # rather than emitting a header that appears to be signed by nobody.
    UNKNOWN_AUTHSERV_ID = "unknown".freeze
    NO_RESULTS = "none".freeze

    # A pvalue may be an RFC 2045 token or a bare addr-spec, so "@" and "." ride
    # along unquoted; everything else has to become a quoted-string.
    TOKEN = /\A[!#-'*+\-.0-9@-Z^-~]+\z/

    # `header_from` is optional: a DmarcResult carries a verdict, not an
    # identity; pass the From: domain to have it reported as `header.from`.
    def initialize(spf:, dkim:, dmarc:, arc: nil, mta: nil, header_from: nil)
      @spf, @dkim, @dmarc, @arc, @mta, @header_from = spf, dkim, dmarc, arc, mta, header_from
    end

    # The value alone — everything after "Authentication-Results:" — so the
    # caller writes the field name itself.
    def to_s
      fold segments
    end

    private
      def segments
        clauses = [ [ authserv_id ], *method_clauses ]

        clauses.each_with_index.map do |tokens, index|
          index == clauses.length - 1 ? tokens : terminated(tokens)
        end
      end

      def authserv_id
        escape(@mta.to_s.strip.empty? ? UNKNOWN_AUTHSERV_ID : @mta)
      end

      def method_clauses
        clauses = [ spf_clause, *dkim_clauses, dmarc_clause, arc_clause ].compact

        # A header with nothing to report still has to report that.
        clauses.any? ? clauses : [ [ NO_RESULTS ] ]
      end

      def spf_clause
        if @spf
          [ "spf=#{@spf.status}", comment(@spf.comment), property("smtp.mailfrom", @spf.domain) ].compact
        end
      end

      # Three signatures make three dkim= results: collapsing them would lose
      # which domain the passing one belonged to.
      def dkim_clauses
        @dkim&.signatures&.map do |signature|
          [ "dkim=#{signature.status}",
            comment(signature.comment),
            comment(undersized(signature)),
            property("header.d", signature.domain),
            property("header.s", signature.selector),
            property("header.a", signature.algorithm) ].compact
        end
      end

      # Tells the header's reader when l= left part of the body unsigned.
      def undersized(signature)
        "undersized signature: #{signature.under_sized} bytes unsigned" if signature.under_sized
      end

      def dmarc_clause
        if @dmarc
          [ "dmarc=#{@dmarc.status}", comment(policy_comment), property("header.from", @header_from) ].compact
        end
      end

      # The result says whether the message aligned; the comment says what
      # the domain asked us to do about it.
      def policy_comment
        "p=#{@dmarc.policy.upcase}" if @dmarc.policy
      end

      # RFC 8617 §5.2 registers pass, fail, and none and nothing else, so the
      # sealer rides along as a comment rather than as a property, and a chain
      # that passed never touches the dmarc= clause above it.
      def arc_clause
        if @arc
          [ "arc=#{@arc.status}", comment(newest_sealer) ].compact
        end
      end

      def newest_sealer
        if @arc.newest&.seal&.domain
          "i=#{@arc.newest.instance} d=#{@arc.newest.seal.domain}"
        end
      end

      def property(name, value)
        value = sanitize(value)

        if value.empty?
          nil
        else
          "#{name}=#{escape(value)}"
        end
      end

      def comment(text)
        text = sanitize(text)

        if text.empty?
          nil
        else
          "(#{escape_comment(text)})"
        end
      end

      def escape(value)
        value = sanitize(value)

        if value.match?(TOKEN)
          value
        else
          %("#{value.gsub(/["\\]/) { |char| "\\#{char}" }}")
        end
      end

      # Parentheses have to balance and a backslash quotes whatever follows it,
      # so both — and the "(" that would open a comment we never meant to start —
      # are escaped.
      def escape_comment(text)
        text.gsub(/[()\\]/) { |char| "\\#{char}" }
      end

      # Everything here can come from a remote party — a surviving CR or LF
      # would let them forge headers of their own.
      def sanitize(value)
        value.to_s.gsub(/[\x00-\x1f\x7f]+/, " ").squeeze(" ").strip
      end

      def terminated(tokens)
        tokens[..-2] + [ "#{tokens.last};" ]
      end

      # Folds at token boundaries only: a quoted string or comment can carry a
      # space, and breaking one across lines would change what it says.
      def fold(segments)
        segments.flat_map { |tokens| lines(tokens) }.join(FOLD)
      end

      def lines(tokens)
        tokens.each_with_object([]) do |token, lines|
          if lines.any? && lines.last.length + INDENT.length + token.length < LINE_WIDTH
            lines.last << " " << token
          else
            lines << token.dup
          end
        end
      end
  end
end
