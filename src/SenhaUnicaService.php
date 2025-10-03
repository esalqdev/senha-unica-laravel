<?php

namespace Esalqdev\SenhaUnica;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class SenhaUnicaService
{
    private string $consumerKey;
    private string $consumerSecret;
    private string $baseUrl;
    private int $callbackId;

    protected $user;

    public function __construct($consumerKey = null, $consumerSecret = null, $baseUrl = null, $callbackId = null)
    {
        $this->consumerKey = $consumerKey ?? config('services.senha_unica.consumer_key');
        $this->consumerSecret = $consumerSecret ?? config('services.senha_unica.consumer_secret');
        $this->baseUrl = $baseUrl ?? config('services.senha_unica.base_url');
        $this->callbackId = $callbackId ?? config('services.senha_unica.callback_id');
    }

    public function redirect()
    {
        $tokens = $this->getRequestToken();

        session()->put('oauth_token_secret', $tokens['oauth_token_secret']);

        $authorizeUrl = sprintf(
            $this->baseUrl . '/authorize?oauth_token=%s&callback_id=%d',
            rawurlencode($tokens['oauth_token']),
            rawurlencode($this->callbackId)
        );

        return redirect($authorizeUrl);
    }

    public function user()
    {
        $oauthToken = request()->oauth_token;
        $oauthVerifier = request()->oauth_verifier;
        $oauthTokenSecret = session()->pull('oauth_token_secret');

        $tokens = $this->getAccessToken($oauthToken, $oauthVerifier, $oauthTokenSecret);
        $userData = $this->getUserData($tokens['oauth_token'], $tokens['oauth_token_secret']);

        return $userData;
    }

    public function getRequestToken()
    {
        $url = $this->baseUrl . '/request_token';
        $params = $this->generateOAuthParams();
        $params['oauth_signature'] = $this->generateSignature($url, 'POST', $params);

        $response = Http::withHeaders([
            'Authorization' => $this->buildAuthHeader($params),
        ])->post($url);

        if ($response->failed()) {
            throw new \Exception('Erro ao obter request token: ' . $response->body());
        }

        parse_str($response->body(), $tokens);
        return $tokens;
    }

    public function getAccessToken(string $oauthToken, string $oauthVerifier, string $oauthTokenSecret)
    {
        $url = $this->baseUrl . '/access_token';
        $params = $this->generateOAuthParams([
            'oauth_token' => $oauthToken,
            'oauth_verifier' => $oauthVerifier,
        ]);
        $params['oauth_signature'] = $this->generateSignature($url, 'POST', $params, $oauthTokenSecret);

        $response = Http::withHeaders([
            'Authorization' => $this->buildAuthHeader($params),
        ])->post($url);

        if ($response->failed()) {
            throw new \Exception('Erro ao obter access token: ' . $response->body());
        }

        parse_str($response->body(), $tokens);
        return $tokens;
    }

    public function getUserData(string $oauthToken, string $oauthTokenSecret)
    {
        $url = $this->baseUrl . '/usuariousp';
        $params = $this->generateOAuthParams([
            'oauth_token' => $oauthToken,
        ]);
        $params['oauth_signature'] = $this->generateSignature($url, 'POST', $params, $oauthTokenSecret);

        $response = Http::withHeaders([
            'Authorization' => $this->buildAuthHeader($params),
            'Accept' => 'application/json'
        ])->post($url);

        if ($response->failed()) {
            throw new \Exception('Erro ao obter dados do usuário: ' . $response->body());
        }

        $this->user = $response->object();

        return $this->user;
    }

    private function generateOAuthParams(array $additionalParams = []): array
    {
        $params = [
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_nonce' => Str::random(40),
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_version' => '1.0',
        ];

        return array_merge($params, $additionalParams);
    }

    private function generateSignature(string $url, string $httpMethod, array $params, string $tokenSecret = ''): string
    {
        ksort($params);

        $encodedParams = array_map(
            fn($key, $value) => rawurlencode($key) . '=' . rawurlencode($value),
            array_keys($params),
            $params
        );

        $baseString = $httpMethod . '&' . rawurlencode($url) . '&' . rawurlencode(implode('&', $encodedParams));
        $signingKey = rawurlencode($this->consumerSecret) . '&' . rawurlencode($tokenSecret);

        return base64_encode(hash_hmac('sha1', $baseString, $signingKey, true));
    }

    private function buildAuthHeader(array $params): string
    {
        return 'OAuth ' . implode(', ', array_map(
            fn($key, $value) => rawurlencode($key) . '="' . rawurlencode($value) . '"',
            array_keys($params),
            $params
        ));
    }

    public function getVinculo($nomeVinculo)
    {
        if (!isset($this->user->vinculo) || !is_array($this->user->vinculo)) {
            return null;
        }

        foreach ($this->user->vinculo as $vinculo) {
            if ($vinculo->nomeVinculo == $nomeVinculo) {
                return $vinculo;
            }
        }

        return null;
    }
}
