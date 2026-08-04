require_relative "lib/mailauth/version"

Gem::Specification.new do |spec|
  spec.name = "mailauth"
  spec.version = MailAuth::VERSION
  spec.platform = Gem::Platform::RUBY
  spec.required_ruby_version = ">= 3.4"
  spec.authors = [ "Simon Lev" ]

  spec.summary = "Email authentication for Ruby."
  spec.description = "Email authentication for Ruby. Verify SPF, DKIM, DMARC, and ARC on received mail, and sign outgoing mail with DKIM."

  spec.homepage = "https://github.com/mailpiece/mailauth"
  spec.license = "MIT"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*.rb",
    "CHANGELOG.md",
    "README.md",
    "LICENSE",
    "mailauth.gemspec"
  ]
  spec.require_paths = [ "lib" ]

  spec.add_dependency "mailresolver"
  spec.add_dependency "public_suffix"
  spec.add_dependency "simpleidn"
end
