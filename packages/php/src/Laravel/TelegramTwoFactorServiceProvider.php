<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Kampe\TelegramTwoFactor\Config;
use Kampe\TelegramTwoFactor\Contracts\CodeStore;
use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\Contracts\Logger;
use Kampe\TelegramTwoFactor\Contracts\Messages;
use Kampe\TelegramTwoFactor\Contracts\TelegramClient;
use Kampe\TelegramTwoFactor\Laravel\Console\SetWebhookCommand;
use Kampe\TelegramTwoFactor\Laravel\Console\TelegramStatusCommand;
use Kampe\TelegramTwoFactor\Support\PsrLogger;
use Kampe\TelegramTwoFactor\Telegram\DefaultMessages;
use Kampe\TelegramTwoFactor\Telegram\HttpTelegramClient;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;
use Kampe\TelegramTwoFactor\Webhook\UpdateHandler;
use Kampe\TelegramTwoFactor\Webhook\WebhookVerifier;

final class TelegramTwoFactorServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/telegram-2fa.php', 'telegram-2fa');

        // Config is validated in its constructor and will throw on a bad or
        // incomplete environment. It is registered as a singleton resolved
        // lazily, so an application that does not use the package does not
        // fail to boot because of it.
        $this->app->singleton(Config::class, function ($app): Config {
            return Config::fromArray($app['config']->get('telegram-2fa.protocol', []) + [
                'bot_token' => $app['config']->get('telegram-2fa.bot_token', ''),
                'bot_username' => $app['config']->get('telegram-2fa.bot_username'),
                'webhook_secret' => $app['config']->get('telegram-2fa.webhook_secret', ''),
                'app_name' => $app['config']->get('telegram-2fa.app_name')
                    ?: $app['config']->get('app.name', 'Kampe'),
            ]);
        });

        $this->app->singleton(Logger::class, fn ($app) => new PsrLogger(
            $app['log']->channel($app['config']->get('telegram-2fa.log_channel') ?: null)
        ));

        $this->app->singleton(CodeStore::class, fn ($app) => new CacheCodeStore(
            $app->make(CacheFactory::class)->store(
                $app['config']->get('telegram-2fa.cache_store') ?: null
            ),
            permitLocalStore: (bool) $app['config']->get('telegram-2fa.permit_local_cache_store', false),
        ));

        $this->app->singleton(IdentityStore::class, fn ($app) => new EloquentIdentityStore(
            $app['config']->get('telegram-2fa.user_model'),
            $app['config']->get('telegram-2fa.columns.chat_id', 'telegram_chat_id'),
            $app['config']->get('telegram-2fa.columns.linked_at', 'telegram_linked_at'),
            $app['config']->get('telegram-2fa.columns.enrollment', 'telegram_enrollment'),
        ));

        $this->app->singleton(TelegramClient::class, fn ($app) => new HttpTelegramClient(
            $app->make(Config::class)->botToken,
            (int) $app['config']->get('telegram-2fa.timeout', 10),
            $app->make(Logger::class),
        ));

        $this->app->singleton(Messages::class, fn () => new DefaultMessages());

        $this->app->singleton(TelegramTwoFactor::class, fn ($app) => new TelegramTwoFactor(
            $app->make(Config::class),
            $app->make(CodeStore::class),
            $app->make(IdentityStore::class),
            $app->make(TelegramClient::class),
            $app->make(Messages::class),
            logger: $app->make(Logger::class),
        ));

        $this->app->singleton(WebhookVerifier::class, fn ($app) => new WebhookVerifier(
            $app->make(Config::class)
        ));

        $this->app->singleton(UpdateHandler::class, fn ($app) => new UpdateHandler(
            $app->make(TelegramTwoFactor::class),
            $app->make(Config::class),
            $app->make(CodeStore::class),
            $app->make(TelegramClient::class),
            $app->make(Messages::class),
            $app->make(Logger::class),
        ));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/telegram-2fa.php' => $this->app->configPath('telegram-2fa.php'),
            ], 'telegram-2fa-config');

            $this->publishes([
                __DIR__ . '/../../database/migrations/add_telegram_two_factor_columns.php.stub' => $this->migrationPath(),
            ], 'telegram-2fa-migrations');

            $this->commands([
                SetWebhookCommand::class,
                TelegramStatusCommand::class,
            ]);
        }

        if ($this->app['config']->get('telegram-2fa.register_webhook_route', true)) {
            $this->registerWebhookRoute();
        }
    }

    private function registerWebhookRoute(): void
    {
        $path = $this->app['config']->get('telegram-2fa.webhook_path', 'telegram/webhook');

        Route::post($path, WebhookController::class)
            ->middleware([VerifyTelegramWebhook::class])
            ->withoutMiddleware(['web'])
            ->name('telegram-2fa.webhook');
    }

    private function migrationPath(): string
    {
        return $this->app->databasePath(
            'migrations/' . date('Y_m_d_His') . '_add_telegram_two_factor_columns.php'
        );
    }
}
