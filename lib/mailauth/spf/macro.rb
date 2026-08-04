module MailAuth
  module Spf
    # RFC 7208 §7. The little templating language a record uses to build a name
    # out of the message in front of it — `exists:%{ir}.%{d}` asks a question
    # about this particular client rather than about the domain in general.
    module Macro
      # Whatever a transformer splits on, the pieces are rejoined with dots —
      # the result is going into a domain name.
      DELIMITERS = ".-+,/_="

      # The expansion form, plus the three escapes, ordered so a lone `%` only
      # matches once nothing legal does — exactly when it's a syntax error.
      EXPANSION = /%\{([^}]*)\}|%%|%_|%-|%/

      # macro-letter transformers *delimiter
      BODY = /\A([a-z])(\d*)([r]?)([#{Regexp.escape(DELIMITERS)}]*)\z/i

      # RFC 3986's unreserved set. An uppercase macro letter expands the same as
      # its lowercase twin and then URL-escapes everything outside this.
      RESERVED = /[^A-Za-z0-9\-._~]/

      # toplabel = ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
      TOPLABEL = /(?:[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9\-]*[a-z0-9])/i

      # The tail of a domain-spec must be a real label rather than something a
      # macro happened to produce, or a macro expansion standing alone.
      DOMAIN_END = /\.#{TOPLABEL}\.?\z/o

      class << self
        # Raises PermError on anything the ABNF doesn't allow: a record that
        # can't be parsed can't be obeyed.
        def expand(string, context)
          string.to_s.gsub(EXPANSION) do |match|
            case match
            when "%%" then "%"
            when "%_" then " "
            when "%-" then "%20"
            when "%"  then raise PermError, "stray % in #{string}"
            else expansion(Regexp.last_match(1), context)
            end
          end
        end

        # Checked before expansion, not after — a macro may expand into
        # something no resolver will answer for, but that fails the
        # mechanism, not the record.
        def domain_spec(string, context)
          if string.to_s.empty?
            raise PermError, "empty domain-spec"
          elsif !ends_well?(string)
            raise PermError, "domain-spec #{string} does not end in a macro or a top-level label"
          else
            expand(string, context).downcase.chomp(".")
          end
        end

        private
          def ends_well?(string)
            literal_tail = string.sub(/\A.*(?:%\{[^}]*\}|%%|%_|%-)/m, "")
            literal_tail.empty? || literal_tail.match?(DOMAIN_END)
          end

          def expansion(body, context)
            letter, digits, reverse, delimiters = body.match(BODY)&.captures

            if letter
              value = transform(value_for(letter.downcase, context), digits, !reverse.empty?, delimiters)
              letter == letter.upcase ? escape(value) : value
            else
              raise PermError, "invalid macro %{#{body}}"
            end
          end

          def value_for(letter, context)
            case letter
            when "s" then context.sender
            when "l" then context.local
            when "o" then context.sender_domain
            when "d" then context.domain
            when "i" then dotted(context.ip)
            when "v" then context.ip.ipv4? ? "in-addr" : "ip6"
            when "h" then context.helo.to_s
            # %{p} needs the PTR lookup and forward confirmation of §5.5, which
            # §7.2 discourages anyone from relying on and we don't do. "unknown"
            # is what §7.2 prescribes when no name validates, and it matches
            # nothing — where a real domain here would let `exists:%{p}.…` hit
            # by accident.
            when "p" then "unknown"
            # c, r and t are legal in an explanation string and nowhere else,
            # and we don't produce explanations.
            else raise PermError, "macro letter %{#{letter}} is not allowed here"
            end
          end

          # Dotted-quad for IPv4; one hex nibble per label for IPv6.
          def dotted(ip)
            if ip.ipv4?
              ip.to_s
            else
              ip.to_string.delete(":").chars.join(".")
            end
          end

          def transform(value, digits, reverse, delimiters)
            if digits.empty? && !reverse && (delimiters.empty? || delimiters == ".")
              value
            else
              parts = value.split(/[#{Regexp.escape(delimiters.empty? ? "." : delimiters)}]/)
              parts = parts.reverse if reverse
              parts = parts.last(digits.to_i) if digits.to_i > 0
              parts.join(".")
            end
          end

          def escape(value)
            value.gsub(RESERVED) { |char| char.bytes.map { |byte| format("%%%02X", byte) }.join }
          end
      end
    end
  end
end
