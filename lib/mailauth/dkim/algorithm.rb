require "openssl"

module MailAuth
  module Dkim
    # Both directions of the same maths, in one place: RFC 8463 §3 has EdDSA
    # sign the hash of the canonicalized headers where RSA signs the headers
    # themselves, and a signer and a verifier that disagree about that produce
    # signatures nobody can check.
    module Algorithm
      def self.sign(data, key:, digest: OpenSSL::Digest::SHA256)
        case KEY_TYPES.fetch(key.oid)
        when "rsa"     then key.sign(digest.new, data)
        when "ed25519" then key.sign(nil, digest.digest(data))
        end
      end

      def self.verified?(data, key:, signature:, digest: OpenSSL::Digest::SHA256)
        case KEY_TYPES.fetch(key.oid)
        when "rsa"     then key.verify(digest.new, signature, data)
        when "ed25519" then key.verify(nil, signature, digest.digest(data))
        end
      rescue OpenSSL::PKey::PKeyError
        # A signature of the wrong length for the key never reaches the maths.
        false
      end
    end
  end
end
