<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request) {
        $request->validate([
            'npm' => 'required|string|unique:users,npm',
            'password' => 'required|string|confirmed',
        ]);

        $user = User::create([
            'npm' => $request->npm,
            'password' => Hash::make($request->password)
        ]);

        $token = $user->createToken('')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response($response, 201);
    }

    public function login(Request $request) {
        $request->validate([
            'npm' => 'required|string',
            'password' => 'required|string'
        ]);

        if (!Auth::attempt(['npm' => $request->npm, 'password' => $request->password], true)) {
            return response(['message' => 'NPM/Password salah!'], 401);
        }

        $user = User::where('npm', $request->npm)->first();
        $token = $user->createToken('')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response($response, 201);
    }

    public function logout(Request $request) {
        $request->user()->tokens()->delete();

        return [
            'message' => 'Logged out'
        ];
    }
}
