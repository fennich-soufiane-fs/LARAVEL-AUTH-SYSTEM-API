<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');


Route::post('/login', [AuthController::class, 'login'])->middleware('web');
Route::post('/register', [AuthController::class, 'register'])->middleware('web');
Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:sanctum');
