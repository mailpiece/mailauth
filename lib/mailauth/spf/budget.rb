module MailAuth
  module Spf
    # RFC 7208 §4.6.4's allowance per evaluation, spent one query at a time.
    # Ten lookups caps a stranger's record chaining `include`s forever; two
    # voids catches a record whose targets mostly don't exist.
    class Budget
      MAX_LOOKUPS = 10
      MAX_VOID_LOOKUPS = 2
      MAX_NAME_LENGTH = 253
      MAX_LABEL_LENGTH = 63

      # Each mx/ptr term's address resolution gets its own fresh MAX_LOOKUPS
      # allowance (see #branch), so a record with several such terms — still
      # legal under the top-level 10-term cap — can legitimately rack up
      # over a hundred queries for one message. Ten top-level terms all
      # `mx`/`ptr`, each maxed out at MAX_MX_EXCHANGES/MAX_PTR_NAMES targets,
      # is 10 * (1 + 10) = 110 queries. Forty caps that well below its worst
      # case while still leaving room for several such terms at once (a
      # handful of mx/ptr mechanisms with normal exchange/name counts stays
      # far under it) — this is defense in depth, not a limit the RFC asks for.
      MAX_TOTAL_LOOKUPS = 40

      # Shared by a Budget and every branch spawned from it via #branch, so
      # their independent per-mechanism ceilings still add up to one bounded
      # total for the whole SPF evaluation.
      class Total
        def initialize
          @lookups = 0
        end

        def spend
          @lookups += 1
          raise PermError, "more than #{MAX_TOTAL_LOOKUPS} total DNS lookups" if @lookups > MAX_TOTAL_LOOKUPS
        end
      end

      attr_reader :lookups

      # `charging: false` lets the opening record fetch through free: it belongs
      # to no mechanism, so nobody is billed for it. `total` is the aggregate
      # counter shared with every branch spawned from this budget (see #branch);
      # left unset, a fresh evaluation gets a counter of its own.
      def initialize(resolver, charging: true, total: Total.new)
        @resolver = resolver
        @charging = charging
        @lookups = 0
        @voids = 0
        @total = total
      end

      def txt(name)
        query(:txt, name)
      end

      def a(name)
        query(:a, name)
      end

      def aaaa(name)
        query(:aaaa, name)
      end

      def mx(name)
        query(:mx, name)
      end

      # Takes the client address, not a name: the reverse zone is the
      # resolver's business.
      def ptr(address)
        resolve(:ptr, address)
      end

      # `mx` and `ptr` fan out into an address lookup per name. RFC 7208 bounds
      # that separately, so it gets its own MAX_LOOKUPS allowance — but it
      # still spends against the aggregate MAX_TOTAL_LOOKUPS shared with the
      # budget it branched from.
      def branch
        Budget.new(@resolver, total: @total)
      end

      private
        # A name that can't be put on the wire isn't an error — treated as a
        # name that simply isn't there. Length alone doesn't make one: an
        # over-long name is shortened and then asked for.
        def query(type, name)
          name = truncate(name)

          if queryable?(name)
            resolve(type, name)
          else
            spend
            void
          end
        end

        # RFC 7208 §7.3: a macro expansion past 253 octets loses whole labels
        # from the left until it fits. The query is still made, so this costs a
        # lookup and never a void.
        def truncate(name)
          name = name.to_s
          name = name.split(".", 2).last while name.length > MAX_NAME_LENGTH && name.include?(".")
          name
        end

        def resolve(type, name)
          spend
          @resolver.public_send(type, name)
        rescue MailResolver::NotFound
          void
        rescue MailResolver::Timeout, MailResolver::ServerFailure => error
          raise TempError, error.message
        end

        def spend
          if @charging
            @lookups += 1
            raise PermError, "more than #{MAX_LOOKUPS} DNS lookups" if @lookups > MAX_LOOKUPS

            @total.spend
          else
            @charging = true
          end
        end

        def void
          @voids += 1

          if @voids > MAX_VOID_LOOKUPS
            raise PermError, "more than #{MAX_VOID_LOOKUPS} void DNS lookups"
          else
            []
          end
        end

        def queryable?(name)
          labels = name.to_s.chomp(".").split(".", -1)

          name.to_s.length <= MAX_NAME_LENGTH && !labels.empty? &&
            labels.all? { |label| (1..MAX_LABEL_LENGTH).cover?(label.length) }
        end
    end
  end
end
