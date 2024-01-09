<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;
use carry0987\Falcon\Utils\HTTPUtil;
use carry0987\Falcon\Utils\SecurityUtil;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class RedditProvider implements OAuthInterface
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $apiBaseUrl;
    protected $authorizeUrl;
    protected $accessTokenUrl;
    protected $revokeTokenUrl;
    protected $httpClient;
    protected $token;
    protected $userAgent = 'Falcon OAuth2.0 Client';

    public function __construct(array $config)
    {
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUri = $config['redirect_uri'];
        $this->apiBaseUrl = 'https://oauth.reddit.com/api/v1/';
        $this->authorizeUrl = 'https://www.reddit.com/api/v1/authorize';
        $this->accessTokenUrl = 'https://www.reddit.com/api/v1/access_token';
        $this->revokeTokenUrl = 'https://www.reddit.com/api/v1/revoke_token';
        $this->httpClient = new Client();
    }

    public function authorize(bool $redirect = false)
    {
        $securityUtil = new SecurityUtil($this);
        $state = $securityUtil->generateState();

        $params = [
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'state' => $state,
            'redirect_uri' => $this->redirectUri,
            'duration' => 'permanent',
            'scope' => 'identity'
        ];

        $url = $this->authorizeUrl.'?'.http_build_query($params);

        if ($redirect) {
            HTTPUtil::redirectURL($url);
        }

        return $url;
    }

    public function getTokenWithAuthCode(string $code, string $state = null)
    {
        if (!$code) {
            throw new AuthenticationException('Authorization code must be provided for getting access token.');
        }

        $securityUtil = new SecurityUtil($this);
        if (!$securityUtil->validateState($state)) {
            throw new AuthenticationException('Invalid state.');
        }

        try {
            $response = $this->httpClient->post($this->accessTokenUrl, [
                'headers' => [
                    'Authorization' => HTTPUtil::getBasicAuthorizationHeader($this->clientId, $this->clientSecret)
                ],
                'form_params' => [
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'redirect_uri' => $this->redirectUri
                ]
            ]);
            if ($response->getStatusCode() !== 200) {
                throw new AuthenticationException('Failed to get authorization token.');
            }
        } catch (GuzzleException $e) {
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
        if (!$accessToken) {
            throw new AuthenticationException('Access token is not available.');
        }

        try {
            $response = $this->httpClient->get($this->apiBaseUrl.'me', [
                'headers' => [
                    'Authorization' => 'bearer '.$accessToken,
                    'User-Agent' => $this->userAgent
                ]
            ]);
            if ($response->getStatusCode() !== 200) {
                throw new AuthenticationException('Failed to get user data.');
            }
        } catch (GuzzleException $e) {
            throw new AuthenticationException($e->getMessage());
        }

        $userData = json_decode($response->getBody(), true);

        return $userData;
    }

    public function refreshAccessToken(string $refreshToken)
    {
        if (!$refreshToken) {
            throw new AuthenticationException('Refresh token is not available.');
        }

        try {
            $response = $this->httpClient->post($this->accessTokenUrl, [
                'headers' => [
                    'Authorization' => HTTPUtil::getBasicAuthorizationHeader($this->clientId, $this->clientSecret),
                    'User-Agent' => $this->userAgent
                ],
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $refreshToken
                ]
            ]);
            if ($response->getStatusCode() !== 200) {
                throw new AuthenticationException('Failed to refresh the access token.');
            }
        } catch (GuzzleException $e) {
            throw new AuthenticationException($e->getMessage());
        }

        $this->token = json_decode($response->getBody(), true);

        return $this->token['access_token'] ?? null;
    }

    public function revokeAccessToken(string $accessToken, string $tokenTypeHint = 'access_token')
    {
        if (!$accessToken) {
            throw new AuthenticationException('Access token is required to revoke.');
        }

        try {
            $response = $this->httpClient->post($this->revokeTokenUrl, [
                'headers' => [
                    'Authorization' => HTTPUtil::getBasicAuthorizationHeader($this->clientId, $this->clientSecret),
                    'User-Agent' => $this->userAgent
                ],
                'form_params' => [
                    'token' => $accessToken,
                    'token_type_hint' => $tokenTypeHint
                ]
            ]);
        } catch (GuzzleException $e) {
            throw new AuthenticationException($e->getMessage());
        }

        return $response->getStatusCode() === 204;
    }
}
