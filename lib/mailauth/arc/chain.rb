require "mailauth/arc/set"

module MailAuth
  module Arc
    # Every ARC header on a message, grouped into the sets they claim to belong
    # to, and held to the structure RFC 8617 §5.2 step 3 requires of them.
    class Chain
      KINDS = {
        "arc-authentication-results" => :authentication_results,
        "arc-message-signature" => :message_signature,
        "arc-seal" => :seal
      }.freeze

      def initialize(message)
        @message = message
      end

      def empty?
        sets.empty?
      end

      # Instance values run 1..50 (§4.2.1), so a chain longer than that is over
      # the ceiling however its instances are numbered.
      def oversized?
        sets.size > MAXIMUM_SETS
      end

      def sets
        @sets ||= collect
      end

      def ordered
        sets.values.sort_by(&:instance)
      end

      def newest
        ordered.last
      end

      # Everything up to and including one instance — what that instance's seal
      # signs (§5.1.1).
      def through(instance)
        ordered.take_while { |set| set.instance <= instance }
      end

      def structural_error
        if incomplete = ordered.find { |set| !set.complete? }
          "ARC set i=#{incomplete.instance} does not carry exactly one of each header"
        elsif unreadable = ordered.find { |set| !set.readable? }
          "ARC set i=#{unreadable.instance} carries an invalid tag list"
        elsif ordered.map(&:instance) != (1..sets.size).to_a
          "ARC instances are not a continuous sequence"
        else
          chain_status_error
        end
      end

      private
        # A header whose instance can't be read joins no set at all, which
        # leaves the set it was meant for incomplete — the failure it deserves,
        # without a rule of its own.
        def collect
          @message.fields.each_with_object({}) do |field, sets|
            kind = KINDS[@message.field_name(field)]
            instance = kind && instance_of(kind, field)

            (sets[instance] ||= Set.new(instance)).add(kind, field) if instance
          end
        end

        # Read before it is parsed: an instance runs to MAXIMUM_SETS, so a longer
        # run of digits is no instance at all, and turning one into an integer to
        # discover that is arbitrary work for whoever sent it.
        INSTANCE = /\A0*[1-9]\d{0,2}\z/n

        def instance_of(kind, field)
          position = if kind == :authentication_results
            Arc.value_of(field).to_s[INSTANCE_PREFIX, 1]
          else
            Arc.tags_in(field).to_h["i"]
          end

          Integer(position, 10) if position&.match?(INSTANCE)
        end

        # §5.2 step 3.3: instance 1 opens a chain and every hop above it says
        # the chain was intact when it arrived. "fail" is caught earlier, at
        # step 2, when the newest hop is the one saying it.
        def chain_status_error
          if wrong = ordered.find { |set| set.chain_status != expected_chain_status(set) }
            "ARC set i=#{wrong.instance} reports cv=#{wrong.chain_status.inspect}"
          end
        end

        def expected_chain_status(set)
          set.instance == 1 ? "none" : "pass"
        end
    end
  end
end
