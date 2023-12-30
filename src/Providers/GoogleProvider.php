<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;
use carry0987\Falcon\Utils\HTTPUtil;
use Google\Auth\OAuth2;
use Google\Auth\Middleware\AuthTokenMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;

class GoogleProvider implements OAuthInterface
{
    protected $oauth2;
    protected $httpClient;
    protected $token;

    public function __construct(array $config)
    {
        $scopes = $config['scopes'] ?? ['openid', 'email', 'profile'];
        $this->oauth2 = new OAuth2([
            'clientId' => $config['client_id'],
            'clientSecret' => $config['client_secret'],
            'redirectUri' => $config['redirect_uri'],
            'authorizationUri' => 'https://accounts.google.com/o/oauth2/auth',
            'tokenCredentialUri' => 'https://oauth2.googleapis.com/token',
            'scope' => implode(' ', $scopes),
            'access_type' => 'offline',
        ]);
    }

    public function authorize(bool $redirect = false)
    {
        $authUrl = $this->oauth2->buildFullAuthorizationUri();

        if ($redirect) {
            HTTPUtil::redirectURL($authUrl);
        }

        return $authUrl;
    }

    public function getTokenWithAuthCode(string $code)
    {
        if (empty($code)) {
            throw new AuthenticationException('No authentication code provided.');
        }
        $this->oauth2->setCode($code);
        $this->token = $this->oauth2->fetchAuthToken();

        if (array_key_exists('error', $this->token)) {
            throw new AuthenticationException('Error fetching auth token: ' . $this->token['error']);
        }

        return $this->token;
    }

    public function getAccessToken(string $code)
    {
        if ($code && !isset($this->token['access_token'])) {
            $this->getTokenWithAuthCode($code);
        }

        if (!isset($this->token['access_token'])) {
            throw new AuthenticationException('Failed to get access token.');
        }

        return $this->token['access_token'];
    }

    public function getRefreshToken()
    {
        if (!isset($this->token['refresh_token'])) {
            return null;
        }

        return $this->token['refresh_token'];
    }

    public function getUser()
    {
        if (!$this->httpClient) {
            // Prepare a Guzzle HTTP client with the Google OAuth 2.0 handler.
            $stack = HandlerStack::create();
            $middleware = new AuthTokenMiddleware($this->oauth2);
            $stack->push($middleware);

            $this->httpClient = new Client([
                'handler' => $stack,
                'base_uri' => 'https://www.googleapis.com',
                'headers' => [
                    'Authorization' => 'Bearer ' . $this->oauth2->getLastReceivedToken()['access_token'],
                ],
            ]);
        }

        try {
            $response = $this->httpClient->get('/oauth2/v2/userinfo', [
                'query' => ['alt' => 'json']
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() == 200) {
            $user = json_decode($response->getBody(), true);
            return $user;
        } else {
            throw new AuthenticationException('Failed to retrieve user information.');
        }
    }

    public function refreshAccessToken(string $refreshToken = null)
    {
        if ($refreshToken === null) return null;

        $this->oauth2->setGrantType('refresh_token');
        $this->oauth2->setRefreshToken($refreshToken);
        $authToken = $this->oauth2->fetchAuthToken();

        return $authToken;
    }

    public function revokeAccessToken(string $accessToken)
    {
        $this->httpClient = new Client(['base_uri' => 'https://oauth2.googleapis.com']);

        try {
            $response = $this->httpClient->post('/revoke', [
                'headers' => [
                    'Content-type' => 'application/x-www-form-urlencoded',
                ],
                'body' => http_build_query(['token' => $accessToken]),
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() != 200) {
            throw new AuthenticationException('Failed to revoke access token.');
        }

        return json_decode((string) $response->getBody(), true);
    }
}
