require "openssl"

module MailAuth
  module Dkim
    # The key a signing domain publishes, per RFC 6376 §3.6.1. ARC keys live in
    # the same records under the same names, so both protocols read them here.
    module PublicKey
      class << self
        def retrieve(selector:, domain:, algorithm:, resolver:)
          read record_for(name_for(selector: selector, domain: domain), resolver), algorithm
        end

        def name_for(selector:, domain:)
          "#{selector}._domainkey.#{domain}"
        end

        private
          def record_for(name, resolver)
            tags = Dkim.parse_tags(resolver.txt(name).first.to_s)

            if tags.nil?
              raise Malformed, "invalid key record for #{name}"
            elsif tags["v"] && tags["v"].downcase != "dkim1"
              raise Malformed, "unknown key version #{tags["v"]}"
            elsif tags["p"].to_s.empty?
              raise Malformed, "key revoked"
            else
              tags["p"].gsub(/[ \t\r\n]+/n, "").unpack1("m")
            end
          end

          def read(material, algorithm)
            key = OpenSSL::PKey.read(wrapped(material))

            if KEY_TYPES[key.oid] != algorithm
              raise Malformed, "key is not #{algorithm}"
            elsif algorithm == "rsa" && key.n.num_bits < MINIMUM_RSA_BITS
              raise Malformed, "rsa key shorter than #{MINIMUM_RSA_BITS} bits"
            else
              key
            end
          rescue OpenSSL::PKey::PKeyError
            raise Malformed, "unreadable public key"
          end

          def wrapped(material)
            material.bytesize == 32 ? ED25519_SPKI_PREFIX + material : material
          end
      end
    end
  end
end
