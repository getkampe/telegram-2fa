<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\Exceptions\ChatAlreadyLinked;
use Kampe\TelegramTwoFactor\Laravel\EloquentIdentityStore;
use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * The production identity store, against a real database.
 *
 * The in-memory store models the rules; this checks that the SQL actually
 * enforces them — that the compare-and-set is in the WHERE clause and counted
 * by affected rows, that a NULL expectation is matched NULL-safely rather than
 * by `= NULL` (which is never true and would make the first link impossible),
 * and that the unique index rejects a second claim on a chat.
 *
 * SQLite in memory, so it runs everywhere without a service. It is a real SQL
 * engine with real constraints; what it cannot prove is MySQL and PostgreSQL
 * error codes, which is why isUniqueViolation checks both SQLSTATE classes.
 */
final class EloquentIdentityStoreTest extends BaseTestCase
{
    private Capsule $capsule;

    private EloquentIdentityStore $store;

    protected function setUp(): void
    {
        parent::setUp();

        $this->capsule = new Capsule();
        $this->capsule->addConnection([
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $this->capsule->setAsGlobal();
        $this->capsule->bootEloquent();

        $schema = $this->capsule->schema();

        $schema->create('users', function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('telegram_chat_id', 64)->nullable();
            $table->timestamp('telegram_linked_at')->nullable();
            $table->string('telegram_enrollment', 64)->nullable();
            $table->unique('telegram_chat_id');
        });

        foreach (['user-1', 'user-2'] as $id) {
            $this->capsule->table('users')->insert(['id' => $id]);
        }

        $this->store = new EloquentIdentityStore(IdentityStoreTestUser::class);
    }

    protected function tearDown(): void
    {
        $this->capsule->schema()->drop('users');

        parent::tearDown();
    }

    public function test_a_first_link_expects_a_null_generation(): void
    {
        // `WHERE generation = NULL` is never true in SQL, so an implementation
        // that does not special-case this can never perform a first link.
        $identity = $this->store->transition('user-1', '555000111', null, 'gen-a');

        $this->assertNotNull($identity);
        $this->assertSame('555000111', $identity->chatId);
        $this->assertSame('gen-a', $identity->generation);
        $this->assertTrue($identity->isVerified());
    }

    public function test_a_transition_with_a_stale_expectation_writes_nothing(): void
    {
        $this->store->transition('user-1', '555000111', null, 'gen-a');

        $this->assertNull(
            $this->store->transition('user-1', '777000222', 'gen-wrong', 'gen-b'),
            'the compare-and-set must decline'
        );

        $identity = $this->store->findByUserId('user-1');
        $this->assertSame('555000111', $identity?->chatId);
        $this->assertSame('gen-a', $identity?->generation);
    }

    public function test_a_transition_with_the_current_expectation_applies(): void
    {
        $this->store->transition('user-1', '555000111', null, 'gen-a');

        $identity = $this->store->transition('user-1', '777000222', 'gen-a', 'gen-b');

        $this->assertNotNull($identity);
        $this->assertSame('777000222', $identity->chatId);
        $this->assertSame('gen-b', $identity->generation);
    }

    public function test_any_generation_skips_the_check(): void
    {
        $this->store->transition('user-1', '555000111', null, 'gen-a');

        $identity = $this->store->transition(
            'user-1',
            null,
            IdentityStore::ANY_GENERATION,
            'gen-recovered',
        );

        $this->assertNotNull($identity);
        $this->assertNull($identity->chatId);
        $this->assertFalse($identity->isVerified());
        $this->assertSame('gen-recovered', $identity->generation);
    }

    public function test_the_generation_survives_unlinking(): void
    {
        $this->store->transition('user-1', '555000111', null, 'gen-a');
        $this->store->transition('user-1', null, 'gen-a', 'gen-b');

        $identity = $this->store->findByUserId('user-1');

        // The row must still be found, carrying the new generation and no chat:
        // revocation has to outlive the binding it revoked.
        $this->assertNotNull($identity);
        $this->assertNull($identity->chatId);
        $this->assertSame('gen-b', $identity->generation);
    }

    public function test_the_unique_index_refuses_a_second_claim_on_a_chat(): void
    {
        $this->store->transition('user-1', '555000111', null, 'gen-a');

        $this->expectException(ChatAlreadyLinked::class);

        $this->store->transition('user-2', '555000111', null, 'gen-b');
    }

    public function test_a_refused_claim_leaves_the_claimant_untouched(): void
    {
        $this->store->transition('user-1', '555000111', null, 'gen-a');
        $this->store->transition('user-2', '777000222', null, 'gen-b');

        try {
            $this->store->transition('user-2', '555000111', 'gen-b', 'gen-c');
            $this->fail('the unique index should have refused this');
        } catch (ChatAlreadyLinked) {
            // expected
        }

        $identity = $this->store->findByUserId('user-2');
        $this->assertSame('777000222', $identity?->chatId);
        $this->assertSame('gen-b', $identity?->generation);
    }

    public function test_several_unlinked_rows_do_not_collide_under_the_unique_index(): void
    {
        // Nullable unique columns permit many NULLs in SQLite, MySQL and
        // PostgreSQL. If they did not, a second account could never unlink.
        $this->store->transition('user-1', '555000111', null, 'gen-a');
        $this->store->transition('user-2', '777000222', null, 'gen-b');

        $this->assertNotNull($this->store->transition('user-1', null, 'gen-a', 'gen-a2'));
        $this->assertNotNull($this->store->transition('user-2', null, 'gen-b', 'gen-b2'));
    }

    public function test_find_by_chat_id_never_matches_an_unlinked_row(): void
    {
        $this->store->transition('user-1', null, null, 'gen-a');

        $this->assertNull($this->store->findByChatId(''));
        $this->assertNull($this->store->findByUserId('user-1')?->chatId);
    }

    public function test_a_missing_row_cannot_be_transitioned(): void
    {
        $this->assertNull($this->store->transition('nobody', '555000111', null, 'gen-a'));
    }

    /**
     * The real database rejects what an application check alone would let
     * through: whichever of two claims arrives second gets an integrity error,
     * translated rather than leaking.
     */
    public function test_the_integrity_error_is_translated_not_leaked(): void
    {
        $this->store->transition('user-1', '555000111', null, 'gen-a');

        try {
            $this->store->transition('user-2', '555000111', null, 'gen-b');
            $this->fail('expected a refusal');
        } catch (ChatAlreadyLinked $e) {
            $this->assertInstanceOf(QueryException::class, $e->getPrevious());
        }
    }
}

/**
 * @internal
 */
final class IdentityStoreTestUser extends Model
{
    protected $table = 'users';

    public $timestamps = false;

    protected $keyType = 'string';

    public $incrementing = false;

    protected $guarded = [];
}
