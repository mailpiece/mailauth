require "mailauth/domain"

module MailAuth
  # A received message, split once into the parts every check needs. Binary
  # throughout: DKIM hashes bytes, so transcoding changes the answer.
  class Message
    HEADER_SEPARATOR = "\r\n\r\n".b

    attr_reader :raw, :headers, :body

    def initialize(raw)
      @raw = normalize(raw)
      @headers, @body = @raw.split(HEADER_SEPARATOR, 2)
      @headers = @headers.to_s
      @body = @body.to_s
    end

    # Order is load-bearing: DKIM walks duplicate headers from the bottom up.
    def fields
      @fields ||= headers.lines.each_with_object([]) do |line, fields|
        if fields.any? && line.start_with?(" ", "\t")
          fields.last << line
        else
          fields << line
        end
      end
    end

    def fields_named(name)
      fields.select { |field| field_name(field) == name.downcase }
    end

    def field_name(field)
      field.split(":", 2).first.to_s.strip.downcase
    end

    # The fields an h= list names, each name taking the lowest instance not
    # yet taken and walking upward through duplicates (RFC 6376 §5.4.2). A
    # name past its count takes nothing. Indexed once, so a long h= costs a
    # lookup per name rather than a pass over every field.
    def fields_signed_by(names)
      taken = Hash.new(0)

      names.filter_map do |name|
        instances = fields_by_name.fetch(name, [])
        taken[name] += 1

        instances[-taken[name]] if taken[name] <= instances.length
      end
    end

    # What DMARC alignment is measured against — quoted display names are
    # stripped first, since `From: "Foo <evil@attacker.example>" <real@bank.example>`
    # must render as bank.example, not the attacker's domain. Several From
    # addresses (legal per RFC 5322, not DMARC) is no domain rather than a guess.
    def header_from_domain
      addresses = from_addresses

      if addresses.one?
        Domain.normalize(addresses.first)
      end
    end

    private
      def fields_by_name
        @fields_by_name ||= fields.group_by { |field| field_name(field) }
      end

      # Bare LF becomes CRLF so a message that took a lossy path still
      # canonicalizes as its signer intended; a lone CR is left alone.
      def normalize(raw)
        raw.to_s.b.gsub(/\r?\n/n, "\r\n")
      end

      # RFC 5322 §3.6 permits exactly one From field, and a second one is how a
      # message says two different things at once: DKIM signs the last From
      # (§5.4.2) while a reader is shown the first, so a signature over an
      # attacker's own domain would align against a name nobody sees. Anything
      # but one field carrying one address is no domain at all.
      def from_addresses
        fields = fields_named("from")

        if fields.one?
          unquoted(fields.first.split(":", 2).last.to_s).scan(/@([^\s>,;()]+)/).flatten
        else
          []
        end
      end

      # Quoted strings and comments can hold anything, including something that
      # reads as an address; neither is one. A comment goes without a trace, as
      # in ceo@(c)bank.example, which is bank.example.
      def unquoted(value)
        value.gsub(/"(?:\\.|[^"\\])*"/n, " ").gsub(/\((?:\\.|[^()\\])*\)/n, "")
      end
  end
end
