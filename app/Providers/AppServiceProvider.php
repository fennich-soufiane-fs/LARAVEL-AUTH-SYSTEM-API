<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Notifications\Messages\MailMessage;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        VerifyEmail::toMailUsing(function (object $notifiable, string $url) {
            $parts = parse_url($url);
            $verifyEmailUrl = 'http://localhost:5173/verify-email?id='
                . $notifiable->getKey() . '&hash=' . sha1($notifiable->getEmailForVerification())
                . '&' . $parts['query'];

            return (new MailMessage)
                ->subject('Verify Email Address')
                ->greeting('Hello ' . $notifiable->first_name)
                ->line('Click the button below to verify your email address.')
                ->action('Verify Email Address', $verifyEmailUrl)
                ->line('If you did not create an account, no further action is required.');
        });
    }

        
}
