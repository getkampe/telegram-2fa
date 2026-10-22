# Laravel integration

The package registers its own webhook route, service bindings and commands, so an
integration is a trait, a handful of routes, and a settings page. Everything here
is copy-paste ready.

## 1. Install

```bash
composer require kampe/telegram-2fa
php artisan vendor:publish --tag=telegram-2fa-config
php artisan vendor:publish --tag=telegram-2fa-migrations
php artisan migrate
```

`.env`:

```dotenv
TELEGRAM_BOT_TOKEN=123456789:AA...
TELEGRAM_BOT_USERNAME=your_bot
TELEGRAM_WEBHOOK_SECRET=
TELEGRAM_2FA_HASH_PEPPER=
TELEGRAM_2FA_CACHE_STORE=redis
```

```bash
php artisan telegram:webhook --generate-secret   # paste into .env
php artisan telegram:webhook                     # register it
php artisan telegram:status                      # confirm
```

## 2. The user model

```php
use Kampe\TelegramTwoFactor\Laravel\HasTelegramTwoFactor;

class User extends Authenticatable
{
    use HasTelegramTwoFactor;
}
```

## 3. Routes

```php
use App\Http\Controllers\TelegramSettingsController;
use App\Http\Controllers\TwoFactorController;

Route::middleware('auth')->group(function () {
    Route::get('settings/telegram', [TelegramSettingsController::class, 'show'])
        ->name('telegram.settings');

    Route::post('settings/telegram/code', [TelegramSettingsController::class, 'completeLink'])
        ->middleware('throttle:5,1')     // the paste flow's namespace is shared
        ->name('telegram.link');

    Route::delete('settings/telegram', [TelegramSettingsController::class, 'unlink'])
        ->middleware('throttle:5,1')
        ->name('telegram.unlink');

    Route::post('2fa/send', [TwoFactorController::class, 'send'])
        ->middleware('throttle:5,1')
        ->name('2fa.send');

    Route::post('2fa/verify', [TwoFactorController::class, 'verify'])
        ->middleware('throttle:10,1')
        ->name('2fa.verify');
});
```

The throttles are part of the security of the design, not decoration — see
[SECURITY.md T2](../../SECURITY.md#t2--guessing-a-code). The webhook route is
registered by the package with its own authentication middleware.

## 4. Controllers

```php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class TelegramSettingsController extends Controller
{
    public function show()
    {
        $user = Auth::user();

        if ($user->hasTelegramTwoFactor()) {
            return view('settings.telegram', ['linked' => true]);
        }

        // Minting a token is harmless for a linked account, and cheap, so this
        // can happen on page load. The account check is at completion.
        $link = $user->startTelegramLink();

        return view('settings.telegram', [
            'linked' => false,
            'url' => $link->url,
            'expiresAt' => $link->expiresAt,
        ]);
    }

    public function completeLink(Request $request)
    {
        // The paste flow, for a user whose Telegram is on another device and who
        // cannot tap the link.
        $request->validate(['code' => ['required', 'string', 'size:8']]);

        $result = Auth::user()->completeTelegramLink($request->string('code'));

        if (! $result->ok) {
            return back()->withErrors(['code' => $result->error->message()]);
        }

        return redirect()
            ->route('telegram.settings')
            ->with('status', 'Telegram is now your second factor.');
    }

    public function unlink(Request $request)
    {
        // Proof of the factor, not just a session: removing the second factor is
        // the move an attacker with a stolen session makes.
        $request->validate(['code' => ['required', 'string']]);

        $result = Auth::user()->unlinkTelegram($request->string('code'));

        if (! $result->ok) {
            return back()->withErrors(['code' => $result->error->message()]);
        }

        return back()->with('status', 'Telegram removed.');
    }
}
```

```php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class TwoFactorController extends Controller
{
    public function send(Request $request)
    {
        $purpose = $request->string('purpose', 'login')->toString();
        $result = Auth::user()->sendTelegramCode($purpose);

        // Safe to return whole: the result never carries the code.
        return response()->json($result->toArray(), $result->ok ? 200 : 429);
    }

    public function verify(Request $request)
    {
        $request->validate(['code' => ['required', 'string']]);

        $result = Auth::user()->verifyTelegramCode(
            $request->string('code'),
            $request->string('purpose', 'login')->toString(),
        );

        if (! $result->ok) {
            return response()->json([
                'message' => $result->error->message(),
                'attempts_remaining' => $result->attemptsRemaining,
            ], 422);
        }

        $request->session()->put('2fa_passed_at', now());

        return response()->json(['ok' => true]);
    }
}
```

## 5. Gating actions behind the factor

A middleware for the steps that need fresh proof:

```php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RequireFreshTwoFactor
{
    public function handle(Request $request, Closure $next, int $withinMinutes = 15)
    {
        $passedAt = $request->session()->get('2fa_passed_at');

        if ($passedAt === null || $passedAt->lt(now()->subMinutes($withinMinutes))) {
            return redirect()
                ->route('2fa.challenge')
                ->with('intended', $request->fullUrl());
        }

        return $next($request);
    }
}
```

```php
Route::post('withdrawals', WithdrawalController::class)
    ->middleware(['auth', 'two-factor:5']);
```

Pass a `purpose` that names the action — `withdrawal`, not `login` — so a code
minted to confirm a sign-in cannot be replayed to approve a payout. The library
enforces that when you pass the same purpose to `verify`.

## 6. The settings view

```blade
@if ($linked)
    <p>Telegram is your second factor.</p>

    <form method="POST" action="{{ route('telegram.unlink') }}">
        @csrf @method('DELETE')
        <p>Send <code>/code</code> to the bot, then enter it here to confirm.</p>
        <input name="code" inputmode="numeric" autocomplete="one-time-code" required>
        <button>Remove Telegram</button>
    </form>
@else
    <a href="{{ $url }}" target="_blank" rel="noopener">Link Telegram</a>

    {{-- For desktop users whose Telegram is on their phone. --}}
    <img src="{{ route('telegram.qr') }}" alt="Scan to link Telegram">

    <details>
        <summary>Cannot open the link?</summary>
        <p>Send <code>/link</code> to the bot and enter the code it gives you.</p>
        <form method="POST" action="{{ route('telegram.link') }}">
            @csrf
            <input name="code" maxlength="8" autocapitalize="characters" required>
            <button>Link</button>
        </form>
    </details>
@endif
```

Because the deeplink completes out of band, the browser does not know when the
user has tapped it. Poll `telegram.settings` every few seconds while that page is
open, or push the change over a websocket.

## 7. Replacing a piece

Every binding is swappable in a service provider:

```php
use Kampe\TelegramTwoFactor\Contracts\Messages;
use Kampe\TelegramTwoFactor\Contracts\IdentityStore;

public function register(): void
{
    // Translate the bot.
    $this->app->singleton(Messages::class, fn () => new YorubaMessages());

    // Store the binding somewhere other than the users table.
    $this->app->singleton(IdentityStore::class, fn () => new MyIdentityStore());
}
```
