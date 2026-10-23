# frozen_string_literal: true

require_relative "lib/kampe/telegram_two_factor/version"

Gem::Specification.new do |spec|
  spec.name = "kampe-telegram_2fa"
  spec.version = Kampe::TelegramTwoFactor::VERSION
  spec.authors = ["Joseph Uruetse"]
  spec.email = ["support@getkampe.com"]

  spec.summary = "Telegram as a second authentication factor."
  spec.description = <<~TEXT
    Telegram as a second authentication factor: enrollment, challenge issuance,
    single-use code verification and webhook handling, with no gem
    dependencies. The protocol is specified in SPEC.md and implemented
    identically in PHP, Node, Python, Go and Ruby, so all of them interoperate
    against one bot and one store.
  TEXT
  spec.homepage = "https://github.com/getkampe/telegram-2fa"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => "#{spec.homepage}/tree/main/packages/ruby",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }

  # Relative to this directory only: a path outside it cannot be packaged, so
  # the licence travels as spec.license rather than as a bundled copy.
  spec.files = Dir["lib/**/*.rb"] + ["README.md"]
  spec.require_paths = ["lib"]
end
