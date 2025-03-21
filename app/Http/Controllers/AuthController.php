<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(Request $request) {
        $user = User::create($request->validate([
            'first_name' => 'required|string',
            'last_name' => 'required|string',
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]));

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
}
