<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;
use carry0987\Falcon\Utils\HTTPUtil;
use carry0987\Falcon\Utils\SecurityUtil;
use GuzzleHttp\Client;

class TwitterProvider implements OAuthInterface
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $apiUrl;
    protected $authUrl;
    protected $httpClient;
    protected $scopes;
    protected $token;

    public function __construct(array $config)
    {
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUri = $config['redirect_uri'];
        $this->apiUrl = 'https://api.twitter.com';
        $this->authUrl = 'https://twitter.com';
        $this->scopes = $config['scopes'] ?? ['tweet.read', 'users.read', 'offline.access'];
        $this->scopes = implode(' ', $this->scopes);
        $this->httpClient = new Client();
    }

    public function authorize(bool $redirect = false)
    {
        $securityUtil = new SecurityUtil($this);
        $state = $securityUtil->generateState();
        $codeVerifier = $securityUtil->generateCodeVerifier();
        $codeChallenge = $this->generateCodeChallenge($codeVerifier);

        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->scopes,
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256'
        ];

        $url = $this->authUrl.'/i/oauth2/authorize?'.http_build_query($params);

        if ($redirect) {
            HTTPUtil::redirectUrl($url);
        }

        return $url;
    }

    public function getTokenWithAuthCode(string $code, string $state = null)
    {
        if (!$code) {
            throw new AuthenticationException('Authorization code must be provided for getting access token.');
        }

        $securityUtil = new SecurityUtil($this);
        $codeVerifier = $securityUtil->getCodeVerifier();
        if (!$codeVerifier) {
            throw new AuthenticationException('Code verifier must be present for getting access token.');
        }
        if (!$securityUtil->validateState($state)) {
            throw new AuthenticationException('Invalid state.');
        }

        try {
            $response = $this->httpClient->request('POST', $this->apiUrl.'/2/oauth2/token', [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Authorization' => HTTPUtil::getBasicAuthorizationHeader($this->clientId, $this->clientSecret)
                ],
                'form_params' => [
                    'code' => $code,
                    'grant_type' => 'authorization_code',
                    'client_id' => $this->clientId,
                    'redirect_uri' => $this->redirectUri,
                    'code_verifier' => $codeVerifier
                ]
            ]);
            if ($response->getStatusCode() !== 200) {
                throw new AuthenticationException('Failed to get authorization token.');
            }
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        $this->token = json_decode($response->getBody(), true);

        return $this->token;
    }

    public function getAccessToken(string $code, string $state = null)
    {
        if ($code && !isset($this->token['access_token'])) {
            $this->getTokenWithAuthCode($code, $state);
        }

        if (!isset($this->token['access_token'])) {
            throw new AuthenticationException('Failed to get access token.');
        }

        return $this->token['access_token'];
    }

    public function getRefreshToken()
    {
        if (!isset($this->token['refresh_token'])) {
            throw new AuthenticationException('Failed to get refresh token.');
        }

        return $this->token['refresh_token'];
    }

    public function getUser(string $accessToken = null)
    {
        if (!isset($accessToken)) {
            throw new AuthenticationException('Access token must be retrieved before fetching user information.');
        }

        try {
            $response = $this->httpClient->request('GET', $this->apiUrl.'/2/users/me', [
                'headers' => ['Authorization' => 'Bearer '.$accessToken]
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() == 200) {
            return json_decode($response->getBody(), true);
        } else {
            throw new AuthenticationException('Failed to get user information.');
        }
    }

    public function refreshAccessToken(string $refreshToken)
    {
        try {
            $response = $this->httpClient->request('POST', $this->apiUrl.'/2/oauth2/token', [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Authorization' => HTTPUtil::getBasicAuthorizationHeader($this->clientId, $this->clientSecret)
                ],
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $refreshToken,
                    'client_id' => $this->clientId,
                ]
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() == 200) {
            return json_decode($response->getBody(), true);
        } else {
            throw new AuthenticationException('Failed to refresh access token.');
        }
    }

    public function revokeAccessToken(string $accessToken)
    {
        try {
            $response = $this->httpClient->post($this->apiUrl.'/2/oauth2/revoke', [
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Authorization' => HTTPUtil::getBasicAuthorizationHeader($this->clientId, $this->clientSecret)
                ],
                'form_params' => [
                    'token' => $accessToken,
                    'client_id' => $this->clientId,
                    'token_type_hint' => 'access_token'
                ],
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() != 200) {
            throw new AuthenticationException('Failed to revoke access token.');
        }
    }

    private function generateCodeChallenge(string $codeVerifier)
    {
        return HTTPUtil::base64UrlEncode(pack('H*', hash('sha256', $codeVerifier)));
    }
}
