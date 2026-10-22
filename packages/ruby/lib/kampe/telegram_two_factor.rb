# frozen_string_literal: true

# Telegram as a second authentication factor.
#
# Zero gem dependencies. The protocol is specified in SPEC.md at the root of
# the repository, and the other packages there implement the same one, so all
# of them interoperate against one bot and one store.
#
#   config = Kampe::TelegramTwoFactor::Config.from_env
#   tfa = Kampe::TelegramTwoFactor::Service.new(
#     config: config,
#     store: my_redis_store,
#     identities: my_identity_store,
#     telegram: Kampe::TelegramTwoFactor::TelegramClient.new(config.bot_token),
#     messages: Kampe::TelegramTwoFactor::DefaultMessages.new
#   )
require_relative "telegram_two_factor/version"
require_relative "telegram_two_factor/errors"
require_relative "telegram_two_factor/identity"
require_relative "telegram_two_factor/codes"
require_relative "telegram_two_factor/config"
require_relative "telegram_two_factor/results"
require_relative "telegram_two_factor/messages"
require_relative "telegram_two_factor/service"
require_relative "telegram_two_factor/stores/memory"
require_relative "telegram_two_factor/stores/redis"
require_relative "telegram_two_factor/telegram_client"
require_relative "telegram_two_factor/webhook"
