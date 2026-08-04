module MailAuth
  module Spf
    # `target` is already macro-expanded at parse time, so a broken macro is
    # caught even when the mechanism it sits in is never reached.
    Term = Data.define(:qualifier, :mechanism, :target, :network, :cidr4, :cidr6) do
      def initialize(qualifier:, mechanism:, target: nil, network: nil, cidr4: nil, cidr6: nil)
        super
      end
    end

    # A `v=spf1` record, read and taken apart. Parsing is complete before
    # evaluation begins, so `v=spf1 -all ip6` is a broken record — not a fail
    # — even though nothing after `-all` can ever be evaluated.
    class Record
      VERSION = "v=spf1"

      # A modifier is a name and "=" reached before any ":" or "/", so
      # `redirect:example.com` is actually the mechanism "redirect" (a typo), not
      # a modifier. The name stops at the first "="; every "=" after that belongs
      # to the macro-string, where it's a legal literal too.
      MODIFIER = /\A(?<name>[^:\/=]*)=(?<value>.*)\z/
      MODIFIER_NAME = /\A[a-z][a-z0-9\-_.]*\z/i

      MECHANISM = /\A(?<qualifier>[+\-~?])?(?<name>[a-z0-9_.\-]+)(?<argument>[:\/].*)?\z/i

      # domain-spec followed by an optional dual-cidr-length. The domain is
      # matched lazily so that a trailing "/24" is read as a prefix length,
      # while the slashes a domain-spec is allowed to contain stay in the name.
      ARGUMENT = /\A(?<spec>.*?)(?:\/(?<cidr4>\d+))?(?:\/\/(?<cidr6>\d+))?\z/
      DUAL_CIDR = /\A(?:\/(?<cidr4>\d+))?(?:\/\/(?<cidr6>\d+))?\z/
      ADDRESS = /\A(?<address>.*?)(?:\/(?<length>\d+))?\z/

      # SPF is defined over 7-bit ASCII, and a record carrying anything else has
      # been mangled somewhere between its author and us.
      PRINTABLE = /\A[\x20-\x7e]*\z/

      # Zero is not an error but an answer — the domain publishes no policy.
      # Two is: nothing chooses between them.
      def self.fetch(domain, budget:, context:)
        records = budget.txt(domain).select { |record| record.strip.split(/\s+/).first&.downcase == VERSION }

        case records.length
        when 0 then raise NoRecord, "no SPF record for #{domain}"
        when 1 then new(records.first, context)
        else raise PermError, "#{records.length} SPF records for #{domain}"
        end
      end

      attr_reader :terms, :redirect

      def initialize(text, context)
        @text = text
        @context = context
        @terms = []
        @modifiers = {}

        parse
      end

      private
        def parse
          raise PermError, "non-ASCII characters in record" unless @text.match?(PRINTABLE)

          @text.strip.split(/\s+/).drop(1).each do |term|
            if modifier = term.match(MODIFIER)
              parse_modifier(modifier[:name], modifier[:value])
            else
              @terms << parse_mechanism(term)
            end
          end

          @redirect = @modifiers["redirect"]
        end

        def parse_modifier(name, value)
          raise PermError, "invalid modifier name #{name}" unless name.match?(MODIFIER_NAME)

          case name.downcase
          when "redirect", "exp"
            if @modifiers.key?(name.downcase)
              raise PermError, "#{name} given more than once"
            else
              @modifiers[name.downcase] = Macro.domain_spec(value, @context)
            end
          else
            # An unknown modifier does nothing, but its value is still a
            # macro-string, and a record that can't state it correctly is
            # broken however little we care about the answer.
            Macro.expand(value, @context)
          end
        end

        def parse_mechanism(term)
          mechanism = term.match(MECHANISM)
          raise PermError, "invalid term #{term}" unless mechanism

          qualifier = mechanism[:qualifier] || "+"
          argument = mechanism[:argument]

          case name = mechanism[:name].downcase
          when "all"                then all_term(qualifier, argument)
          when "include", "exists"  then named_term(qualifier, name.to_sym, argument)
          when "ptr"                then ptr_term(qualifier, argument)
          when "a", "mx"            then address_term(qualifier, name.to_sym, argument)
          when "ip4", "ip6"         then ip_term(qualifier, name.to_sym, argument)
          else raise PermError, "unknown mechanism #{name}"
          end
        end

        def all_term(qualifier, argument)
          if argument
            raise PermError, "all takes no argument"
          else
            Term.new(qualifier: qualifier, mechanism: :all)
          end
        end

        def named_term(qualifier, mechanism, argument)
          if argument&.start_with?(":")
            Term.new(qualifier: qualifier, mechanism: mechanism, target: Macro.domain_spec(argument[1..], @context))
          else
            raise PermError, "#{mechanism} needs a domain"
          end
        end

        # A bare `ptr` asks about the domain the record was found at.
        def ptr_term(qualifier, argument)
          if argument.nil?
            Term.new(qualifier: qualifier, mechanism: :ptr, target: @context.domain)
          elsif argument.start_with?(":")
            Term.new(qualifier: qualifier, mechanism: :ptr, target: Macro.domain_spec(argument[1..], @context))
          else
            raise PermError, "ptr takes no prefix length"
          end
        end

        def address_term(qualifier, mechanism, argument)
          if argument.nil?
            Term.new(qualifier: qualifier, mechanism: mechanism, target: @context.domain)
          elsif argument.start_with?(":")
            parsed = argument[1..].match(ARGUMENT)

            Term.new(qualifier: qualifier, mechanism: mechanism, target: Macro.domain_spec(parsed[:spec], @context),
              cidr4: prefix(parsed[:cidr4], 32), cidr6: prefix(parsed[:cidr6], 128))
          else
            parsed = argument.match(DUAL_CIDR) or raise PermError, "invalid prefix length #{argument}"

            Term.new(qualifier: qualifier, mechanism: mechanism, target: @context.domain,
              cidr4: prefix(parsed[:cidr4], 32), cidr6: prefix(parsed[:cidr6], 128))
          end
        end

        def ip_term(qualifier, mechanism, argument)
          raise PermError, "#{mechanism} needs an address" unless argument&.start_with?(":")

          parsed = argument[1..].match(ADDRESS)
          bits = mechanism == :ip4 ? 32 : 128
          # We have taken the prefix length off ourselves; IPAddr would happily
          # read a second one, and `ip4:1.2.3.4//32` is not a subtlety, it's a
          # mistake.
          raise PermError, "#{parsed[:address]} is not an address" if parsed[:address].include?("/")

          network = IPAddr.new(parsed[:address])
          raise PermError, "#{parsed[:address]} is not an #{mechanism} address" unless network.family == family(mechanism)

          Term.new(qualifier: qualifier, mechanism: mechanism, network: network.mask(prefix(parsed[:length], bits) || bits))
        rescue IPAddr::Error
          raise PermError, "#{parsed[:address]} is not an address"
        end

        def family(mechanism)
          mechanism == :ip4 ? Socket::AF_INET : Socket::AF_INET6
        end

        # Leading zeros and prefix lengths past the end of the address are
        # both rejected.
        def prefix(digits, limit)
          if digits
            raise PermError, "prefix length /#{digits} has a leading zero" if digits.length > 1 && digits.start_with?("0")
            raise PermError, "prefix length /#{digits} is out of range" if digits.to_i > limit

            digits.to_i
          end
        end
    end
  end
end
