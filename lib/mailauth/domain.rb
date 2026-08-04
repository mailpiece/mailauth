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
        name = printable(name).strip.chomp(".")

        ascii(name).downcase
      end

      private
        # These names come from headers and DNS records, so they can hold any
        # bytes at all — and invalid UTF-8 raises on the first thing done to it.
        def printable(name)
          name = name.to_s
          name.valid_encoding? ? name : name.scrub("")
        end

        def ascii(name)
          name.ascii_only? ? name : SimpleIDN.to_ascii(name)
        rescue StandardError
          # A name punycode can't encode can't be looked up either, so let it
          # fail to match rather than raising here.
          name
        end
    end
  end
end
