<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;
use carry0987\Falcon\Utils\HTTPUtil;
use carry0987\Falcon\Utils\SecurityUtil;
use GuzzleHttp\Client;

class DiscordProvider implements OAuthInterface
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $authorizeUrl = 'https://discord.com/api/oauth2/authorize';
    protected $tokenUrl = 'https://discord.com/api/oauth2/token';
    protected $apiUrlBase = 'https://discord.com/api/users/@me';
    protected $revokeUrl = 'https://discord.com/api/oauth2/token/revoke';
    protected $scopes;
    protected $httpClient;
    protected $token;

    public function __construct(array $config)
    {
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUri = $config['redirect_uri'];
        $this->scopes = $config['scopes'] ?? ['identify', 'email'];
        $this->httpClient = new Client();
    }

    public function authorize(bool $redirect = false)
    {
        $securityUtil = new SecurityUtil($this);
        $state = $securityUtil->generateState();

        $params = [
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $this->scopes),
            'state' => $state
        ];

        $url = $this->authorizeUrl.'?'.http_build_query($params);

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
        if (!$securityUtil->validateState($state)) {
            throw new AuthenticationException('Invalid state.');
        }

        try {
            // Once the state is verified, we can fetch the access token
            $response = $this->httpClient->post($this->tokenUrl, [
                'headers' => [
                    'Accept' => 'application/json',
                ],
                'form_params' => [
                    'grant_type' => 'authorization_code',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'redirect_uri' => $this->redirectUri,
                    'code' => $code,
                ],
            ]);
            // Handle bad response
            if ($response->getStatusCode() != 200) {
                throw new AuthenticationException('Failed to get access token, HTTP status code: '.$response->getStatusCode());
            }
            $this->token = json_decode($response->getBody()->getContents(), true);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if (isset($this->token['error'])) {
            throw new AuthenticationException('Error retrieving access token: '.$this->token['error_description']);
        }

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
            $response = $this->httpClient->get($this->apiUrlBase, [
                'headers' => [
                    'Authorization' => 'Bearer '.$accessToken,
                ],
            ]);
            if ($response->getStatusCode() !== 200) {
                throw new AuthenticationException('Failed to get user data.');
            }
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        $user = json_decode($response->getBody(), true);

        if (isset($user['error'])) {
            throw new AuthenticationException('Error retrieving user profile: '.$user['error_description']);
        }

        return $user;
    }

    public function refreshAccessToken(string $refreshToken)
    {
        if (!$refreshToken) {
            throw new AuthenticationException('Refresh token is not available.');
        }

        try {
            $response = $this->httpClient->post($this->tokenUrl, [
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $refreshToken,
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ],
            ]);
            if ($response->getStatusCode() !== 200) {
                throw new AuthenticationException('Failed to refresh access token.');
            }
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        $this->token = json_decode($response->getBody(), true);

        if (isset($this->token['error'])) {
            throw new AuthenticationException('Error refreshing access token: '.$this->token['error_description']);
        }

        return $this->token['access_token'] ?? null;
    }

    public function revokeAccessToken(string $accessToken)
    {
        if (!$accessToken) {
            throw new AuthenticationException('Access token is not available.');
        }

        $data = [];
        try {
            $response = $this->httpClient->post($this->revokeUrl, [
                'form_params' => [
                    'token' => $accessToken,
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ],
            ]);
            $data = json_decode($response->getBody(), true);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        return !(isset($data['error']));
    }
}
