require "simpleidn"

module MailAuth
  # One spelling for a domain name, so two of them can be compared. An
  # internationalized domain travels both as the U-label a person reads
  # (münchen.example) and the A-label DNS and DKIM's d= carry
  # (xn--mnchen-3ya.example); comparing those byte-wise fails DMARC alignment
  # on perfectly good mail.
  module Domain
    class << self
      def normalize(name)
        name = utf8(name).strip.chomp(".")

        ascii(name).downcase
      end

      private
        # Header bytes arrive as BINARY, which SimpleIDN can't read, so they
        # are read as the UTF-8 RFC 6532 makes them. Bytes that aren't UTF-8
        # stay as they are: scrubbing ban\xffk would make it bank.
        def utf8(name)
          name = name.to_s.dup.force_encoding(Encoding::UTF_8)
          name.valid_encoding? ? name : name.b
        end

        def ascii(name)
          name.ascii_only? || name.encoding == Encoding::BINARY ? name : SimpleIDN.to_ascii(name)
        rescue StandardError
          # A name punycode can't encode can't be looked up either, so let it
          # fail to match rather than raising here.
          name
        end
    end
  end
end
