<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    private string $privateKey;

    public function __construct()
    {
        $this->privateKey = file_get_contents(storage_path('jwt/private.pem'));
        if (!$this->privateKey) {
            throw new \Exception('Private key not found or not readable');
        }
    }

    // Register new user
    public function register(Request $request)
    {
        $data = $request->validate([
            'name'     => 'required|string|max:255',
            'email'    => 'required|email|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        User::create([
            'name'     => $data['name'],
            'email'    => $data['email'],
            'password' => bcrypt($data['password']),
        ]);

        return response()->json([
            'message' => 'User registered successfully'
        ], 201);
    }

    // Login user - expects RSA-encrypted password base64 encoded
    public function login(Request $request)
    {
        $request->validate([
            'email'    => 'required|email',
            'password' => 'required|string',
        ]);

        $encryptedPassword = base64_decode($request->password);
        $decryptedPassword = null;

        if (!openssl_private_decrypt($encryptedPassword, $decryptedPassword, $this->privateKey)) {
            return response()->json(['message' => 'Password decryption failed'], 400);
        }

        if (!Auth::attempt(['email' => $request->email, 'password' => $decryptedPassword])) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $user = Auth::user();

        $token = auth('api')->login($user);

        return response()->json([
            'user' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60,
        ]);
    }

    // Return authenticated user profile
    public function profile()
    {
        return response()->json(auth('api')->user());
    }

    // Logout user (invalidate JWT token)
    public function logout()
    {
        auth('api')->logout();

        return response()->json([
            'message' => 'Logged out successfully'
        ]);
    }
}