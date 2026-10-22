<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Exceptions\ConfigurationError;

/**
 * A configuration that cannot be secure is refused at construction, not warned
 * about at runtime. These are the cases that would otherwise ship.
 */
final class ConfigTest extends TestCase
{
    public function test_a_missing_webhook_secret_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches('/webhook secret/');

        $this->config(['webhook_secret' => '']);
    }

    public function test_a_short_webhook_secret_is_refused(): void
    {
        // Telegram itself accepts a single character here, which would satisfy
        // the API and defeat the purpose entirely.
        $this->expectException(ConfigurationError::class);

        $this->config(['webhook_secret' => 'x']);
    }

    public function test_a_webhook_secret_with_illegal_characters_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->config(['webhook_secret' => str_repeat('!', 48)]);
    }

    public function test_a_missing_bot_token_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches('/bot token/');

        $this->config(['bot_token' => '']);
    }

    public function test_a_malformed_bot_token_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->config(['bot_token' => 'not-a-token']);
    }

    public function test_a_bot_username_with_an_at_sign_is_refused(): void
    {
        // Left in, it produces t.me/@bot?start=... which silently does not work.
        $this->expectException(ConfigurationError::class);

        $this->config(['bot_username' => '@kampe_test_bot']);
    }

    public function test_unlimited_attempts_are_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->config(['max_attempts' => 0]);
    }

    public function test_an_absurd_attempt_budget_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->config(['max_attempts' => 1000]);
    }

    public function test_a_code_that_outlives_its_purpose_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->config(['code_ttl' => 86400]);
    }

    public function test_a_missing_cooldown_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->config(['cooldown' => 0]);
    }

    public function test_a_short_link_code_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches('/linkCodeLength/');

        $this->config(['link_code_length' => 6]);
    }

    public function test_an_unknown_hash_algorithm_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->config(['hash_algorithm' => 'rot13']);
    }

    public function test_defaults_are_the_recommended_values(): void
    {
        $config = $this->config();

        $this->assertSame(6, $config->codeLength);
        $this->assertSame(300, $config->codeTtl);
        $this->assertSame(120, $config->cooldown);
        $this->assertSame(5, $config->maxAttempts);
        $this->assertSame(8, $config->linkCodeLength);
        $this->assertSame(600, $config->linkTtl);
        $this->assertTrue($config->dedupeUpdates);
    }

    public function test_keys_are_namespaced(): void
    {
        $this->assertSame('tg2fa:code:user-1', $this->config->key('code', 'user-1'));
    }

    public function test_snake_case_and_camel_case_input_are_both_accepted(): void
    {
        $snake = $this->config(['code_ttl' => 120]);
        $camel = $this->config(['codeTtl' => 120]);

        $this->assertSame(120, $snake->codeTtl);
        $this->assertSame(120, $camel->codeTtl);
    }

    public function test_a_user_id_is_treated_as_an_opaque_string(): void
    {
        // UUID primary keys are common, so nothing may assume an integer.
        $uuid = '9b7c2f0e-4d5a-4c21-8f3b-1a2b3c4d5e6f';
        $this->identities->link($uuid, '555000111');

        $this->assertTrue($this->tfa->push($uuid)->ok);
        $this->assertTrue($this->tfa->verify($uuid, $this->lastCode())->ok);
    }
}
