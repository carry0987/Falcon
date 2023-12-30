<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;
use carry0987\Falcon\Utils\HTTPUtil;
use carry0987\Falcon\Utils\SecurityUtil;
use GuzzleHttp\Client;

class LineProvider implements OAuthInterface
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $profileUrl = 'https://api.line.me/v2/profile';
    protected $apiUrl = 'https://api.line.me/oauth2/v2.1';
    protected $authUrl = 'https://access.line.me/oauth2/v2.1/authorize';
    protected $httpClient;
    protected $scopes;
    protected $token;

    public function __construct(array $config)
    {
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUri = $config['redirect_uri'];
        $this->scopes = $config['scopes'] ?? ['profile', 'openid', 'email'];
        $this->httpClient = new Client();
    }

    public function authorize(bool $redirect = false)
    {
        $securityUtil = new SecurityUtil($this);
        $state = $securityUtil->generateState();

        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $this->scopes),
            'state' => $state
        ];

        $url = $this->authUrl.'?'.http_build_query($params);

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

        $params = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ];

        try {
            $response = $this->httpClient->post($this->apiUrl.'/token', [
                'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
                'form_params' => $params
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() != 200) {
            throw new AuthenticationException('Failed to get access token');
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

    public function getUser()
    {
        if (isset($this->token) && isset($this->token['access_token'])) {
            $response = $this->httpClient->get($this->profileUrl, [
                'headers' => ['Authorization' => 'Bearer ' . $this->token['access_token']]
            ]);

            if ($response->getStatusCode() != 200) {
                throw new AuthenticationException('Failed to get user profile');
            }

            $user = json_decode($response->getBody(), true);
            return $user;
        } else {
            throw new AuthenticationException('No access token available');
        }
    }

    public function refreshAccessToken(string $refreshToken)
    {
        $params = [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret
        ];

        $response = $this->httpClient->post($this->apiUrl, [
            'headers'     => ['Content-Type' => 'application/x-www-form-urlencoded'],
            'form_params' => $params
        ]);

        if ($response->getStatusCode() != 200) {
            throw new AuthenticationException('Failed to refresh access token');
        }

        $this->token = json_decode($response->getBody(), true);

        return $this->token;
    }

    public function revokeAccessToken(string $accessToken)
    {
        $params = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'access_token'  => $accessToken,
        ];

        $response = $this->httpClient->post($this->apiUrl.'/revoke', [
            'headers'     => ['Content-Type' => 'application/x-www-form-urlencoded'],
            'form_params' => $params
        ]);

        if ($response->getStatusCode() != 200) {
            throw new AuthenticationException('Failed to revoke access token');
        }
    }
}
