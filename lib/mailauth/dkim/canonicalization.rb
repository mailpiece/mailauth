module MailAuth
  module Dkim
    # RFC 6376 §3.4: the bytes a signature covers. One implementation, so
    # signing and verifying can't reduce a message differently.
    module Canonicalization
      class << self
        def body(bytes, form)
          case form
          when "relaxed" then relaxed_body(bytes)
          when "simple"  then simple_body(bytes)
          end
        end

        def field(field, form)
          case form
          when "relaxed" then relaxed_field(field)
          when "simple"  then field.chomp(CRLF)
          end
        end

        private
          # An unterminated final line is still a line (§3.4.4 a.1): its trailing
          # whitespace goes too, and the CRLF it lacks is put back.
          def relaxed_body(bytes)
            body = bytes.gsub(/[ \t]+/n, " ").gsub(/ (?=\r\n|\z)/n, "").sub(/(?:\r\n)*\z/n, "")
            body.empty? ? body : body + CRLF
          end

          def simple_body(bytes)
            bytes.sub(/(?:\r\n)*\z/n, CRLF)
          end

          def relaxed_field(field)
            name, value = field.split(":", 2)
            "#{name.strip.downcase}:#{value.to_s.gsub(/\r\n/n, "").gsub(/[ \t]+/n, " ").strip}"
          end
      end
    end
  end
end
