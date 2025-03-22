<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Auth\Events\PasswordReset;

class AuthController extends Controller
{
    public function register(Request $request) {
        $user = User::create($request->validate([
            'first_name' => 'required|string',
            'last_name' => 'required|string',
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]));

        $user->sendEmailVerificationNotification();

        return response()->json([
            'message' => 'Successfully registred',
            'user' => $user
        ]);
    }

    public function login(Request $request) {
        $fields = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
            'remember' => 'required|boolean',
        ]);

        $credentials = [
            'email' => $fields['email'],
            'password' => $fields['password'],
        ];

        if (!Auth::attempt($credentials, $fields['remember'])) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect'],
            ]);
        }
        
        session()->regenerate();

        return response()->json([
            'message' => 'Successfully logged in',
            'user' => Auth::user(),
        ]);
    }

    public function logout() {
        Auth::guard('web')->logout();
        return response(status: 204);
    }

    public function emailVerify($user_id, Request $request) {
        if(!$request->hasValidSignature()) {
            return response()->json([
                'message' => 'Invalid or expired verification code.'
            ], 400);
        }

        $user = User::find($user_id);

        if(!$user) {
            return response()->json([
                'message' => 'User not found.',
            ], 400);
        }

        if(!$user->hasVerifiedEmail()) {
            $user->markEmailAsVerified();
            return response()->json([
                'message' => 'Email address successfully verified.',
                'user' => $user
            ]);
        }

        return response()->json([
            'message' => 'Email address already verified.',
        ]);
    }

    public function resendEmailVerificationMail(Request $request) {
        $user_id = $request->input('user_id');
        $user = User::find($user_id);
        
        if(!$user) {
            return response()->json([
                'message' => 'User not found.'
            ], 400);
        }

        if($user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email already verified.'
            ], 400);
        }

        $user->sendEmailVerficationNotification();

        return response()->json([
            'message' => 'Email verification link sent to your email address',
        ]);

    }

    public function forgotPassword(Request $request) {
        $request->validate(['email' => 'required|email']);
        $status = Password::sendResetLink(
            $request->only('email')
        );
        return $status === Password::RESET_LINK_SENT 
        ? response()->json(['message' => trans($status)], 200)
        : response()->json(['message' => trans($status)], 400);
    }

    public function resetPassword(Request $request) {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:8|confirmed',
        ]);
        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function (User $user, string $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ])->setRememberToken(Str::random(60));
                $user->save();
                event(new PasswordReset($user));
            }
        );

        return $status === Password::PASSWORD_RESET
        ? response()->json(['message' => trans($status)], 200)
        : response()->json(['message' => trans($status)], 400);
    }
}
