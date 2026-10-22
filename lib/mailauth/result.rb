module MailAuth
  # The vocabulary, matching what RFC 8601 registers so a verdict travels
  # without translation.
  module Status
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
  end

  # `fail` says the check failed; `policy` says what the domain asked us to do
  # about it. Folding those together is a consumer's decision, not ours.
  DmarcResult = Data.define(:status, :policy, :pct, :alignment, :record) do
    def initialize(status:, policy: nil, pct: nil, alignment: nil, record: nil)
      super
    end
  end

  SpfResult = Data.define(:status, :domain, :comment, :lookups) do
    def initialize(status:, domain: nil, comment: nil, lookups: 0)
      super
    end
  end

  # One per DKIM-Signature header, whatever each one's fate.
  Signature = Data.define(:status, :domain, :selector, :algorithm, :canonicalization, :comment, :aligned, :under_sized) do
    def initialize(status:, domain: nil, selector: nil, algorithm: nil, canonicalization: nil, comment: nil, aligned: false, under_sized: nil)
      super
    end
  end

  DkimResult = Data.define(:signatures) do
    # Precedence, not position: one good signature vindicates a message however
    # many broken ones travel beside it.
    PRECEDENCE = [ Status::PASS, Status::FAIL, Status::TEMPERROR, Status::PERMERROR, Status::NEUTRAL, Status::NONE ].freeze

    def status
      PRECEDENCE.find { |status| signatures.any? { |signature| signature.status == status } } || Status::NONE
    end

    def passing_domains
      signatures.select { |signature| signature.status == Status::PASS }.map(&:domain).compact
    end
  end

  # One ARC-Seal and one ARC-Message-Signature, reported apart because RFC 8617
  # places no requirement that a set sign both with the same domain or selector.
  ArcSeal = Data.define(:status, :domain, :selector, :algorithm, :comment) do
    def initialize(status:, domain: nil, selector: nil, algorithm: nil, comment: nil)
      super
    end
  end

  ArcSignature = Data.define(:status, :domain, :selector, :algorithm, :comment) do
    def initialize(status:, domain: nil, selector: nil, algorithm: nil, comment: nil)
      super
    end
  end

  # One ARC Set (RFC 8617 §4.2): what one hop sealed, and what it asserted about
  # the message when it did. `claimed` is that hop's own account of the message's
  # authentication, which a valid chain proves unmodified since sealing and
  # proves nothing else about.
  ArcSet = Data.define(:instance, :chain_status, :seal, :message_signature, :authentication_results, :claimed) do
    def initialize(instance:, chain_status: nil, seal: nil, message_signature: nil, authentication_results: nil, claimed: {})
      super
    end
  end

  # Whether the chain holds, and who sealed it — never whether any of them is to
  # be believed. A chain is cheap to forge over a message of one's own, so trust
  # is the caller's decision and deliberately has no answer here.
  #
  # `oldest_pass` is a second DNS pass over the chain nobody asked for unless
  # they read it, so it accepts a callable and only calls it on first access.
  # `Data` freezes right after `initialize` returns, but freezing is shallow, so
  # the memo hash set up here can still be mutated afterward — just not replaced.
  ArcResult = Data.define(:status, :sets, :oldest_pass, :comment) do
    def initialize(status:, sets: [], oldest_pass: nil, comment: nil)
      lazy = oldest_pass.respond_to?(:call)
      @oldest_pass_memo = lazy ? { thunk: oldest_pass } : { value: oldest_pass }
      super(status: status, sets: sets, comment: comment, oldest_pass: (oldest_pass unless lazy))
    end

    def oldest_pass
      @oldest_pass_memo.fetch(:value) { @oldest_pass_memo[:value] = @oldest_pass_memo.fetch(:thunk).call }
    end

    def newest
      sets.max_by(&:instance)
    end

    # Oldest hop first, the order they sealed in.
    def sealers
      sets.sort_by(&:instance).filter_map { |set| set.seal&.domain }
    end

    def intact?
      status == Status::PASS
    end
  end

  # `name` is the one that resolved back, so it is only ever set on a pass:
  # a name the reverse zone offered and the forward zone disowned is not a name.
  IprevResult = Data.define(:status, :name, :comment) do
    def initialize(status:, name: nil, comment: nil)
      super
    end
  end

  Result = Data.define(:spf, :dkim, :dmarc, :arc, :iprev, :authentication_results) do
    def initialize(spf:, dkim:, dmarc:, authentication_results:, arc: nil, iprev: nil)
      super
    end
  end
end
