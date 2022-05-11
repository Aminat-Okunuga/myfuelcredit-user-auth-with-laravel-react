<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{

    public function register(Request $request){
        return $user = User::create([
          'name' => $request->input('name'),
          'email' => $request->input('email'),
          'password' => Hash::make($request->input('password')),
        ]);
    }
    
    public function login(Request $request){
        // check if user is authorized
        if(!Auth::attempt($request->only('email', 'password'))){
            return response([
                'message' => 'Invalid Credentials!'
            ], Response::HTTP_UNAUTHORIZED);
        }

        // for authorized user
        $user = Auth::user();
        $token = $user->createToken('token')->plainTextToken;
        $cookie = cookie('jwt', $token, 60 * 24);    //for 1 day
        return response([
            'message' => 'Success'
        ])->withCookie($cookie);
    }

    public function user(){
        return Auth::user();
    }
}
