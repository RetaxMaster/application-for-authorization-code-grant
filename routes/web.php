<?php

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Http;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return Inertia::render('Welcome', [
        'canLogin' => Route::has('login'),
        'canRegister' => Route::has('register'),
        'laravelVersion' => Application::VERSION,
        'phpVersion' => PHP_VERSION,
    ]);
});

Route::middleware(['auth:sanctum', 'verified'])->get('/dashboard', function () {
    return Inertia::render('Dashboard');
})->name('dashboard');

// Authorization Code Grant

Route::get('/code/redirect', function (Request $request) {

    $request->session()->put('state', $state = Str::random(40));

    $query = http_build_query([
        'client_id' => env("CLIENT_ID_CODE"),
        'redirect_uri' => 'http://127.0.0.2:8000/code/callback',
        'response_type' => 'code',
        'scope' => '',
        'state' => $state,
    ]);

    return redirect('http://127.0.0.1:8000/oauth/authorize?'.$query);
});

Route::get('/code/callback', function (Request $request) {

    // Validación del state
    $state = $request->session()->pull('state');

    throw_unless(
        strlen($state) > 0 && $state === $request->state,
        InvalidArgumentException::class
    );

    // Ahora pido el token
    $response = Http::asForm()->post('http://127.0.0.1:8000/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => env("CLIENT_ID_CODE"),
        'client_secret' => env("CLIENT_SECRET_CODE"),
        'redirect_uri' => 'http://127.0.0.2:8000/code/callback',
        'code' => $request->code,
    ])->json();

    $request->session()->put("refresh_token", $response["refresh_token"]);

    return $response;

});

Route::get('/code/refresh-token', function (Request $request) {

    // Solo se debe acceder a esta ruta justo después de solicitar el token, esto es una práctica, no tiene validación. El refresh_token está en una flash sesion por lo que esta muere en cada request

    $refresh_token = $request->session()->pull("refresh_token");

    $response = Http::asForm()->post('http://127.0.0.1:8000/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $refresh_token,
        'client_id' => env("CLIENT_ID_CODE"),
        'client_secret' => env("CLIENT_SECRET_CODE"),
        'scope' => '',
    ])->json();
    
    return $response;

});

// Authorization Code Grant With PKCE (Se debe generar un nuevo cliente específico para este tipo... ¬¬)

Route::get('/code-pkce/redirect', function (Request $request) {

    $request->session()->put('state', $state = Str::random(40));

    $request->session()->put(
        'code_verifier', $code_verifier = Str::random(128)
    );

    $code_challenge = strtr(rtrim(
        base64_encode(hash('sha256', $code_verifier, true))
    , '='), '+/', '-_');

    $query = http_build_query([
        'client_id' => env("CLIENT_ID_PKCE"),
        'redirect_uri' => 'http://127.0.0.2:8000/code-pkce/callback',
        'response_type' => 'code',
        'scope' => '',
        'state' => $state,
        'code_challenge' => $code_challenge,
        'code_challenge_method' => 'S256',
    ]);

    return redirect('http://127.0.0.1:8000/oauth/authorize?'.$query);

});

Route::get('/code-pkce/callback', function (Request $request) {
    $state = $request->session()->pull('state');

    $code_verifier = $request->session()->pull('code_verifier');

    throw_unless(
        strlen($state) > 0 && $state === $request->state,
        InvalidArgumentException::class
    );

    $response = Http::asForm()->post('http://127.0.0.1:8000/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => env("CLIENT_ID_PKCE"),
        'redirect_uri' => 'http://127.0.0.2:8000/code-pkce/callback',
        'code_verifier' => $code_verifier,
        'code' => $request->code,
    ])->json();

    return $response;
});
