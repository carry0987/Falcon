<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;
use carry0987\Falcon\Utils\HTTPUtil;
use GuzzleHttp\Client;

class InstagramProvider implements OAuthInterface
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $apiBaseUrl;
    protected $authorizeUrl;
    protected $accessTokenUrl;
    protected $scopes;
    protected $httpClient;
    protected $token;

    public function __construct(array $config)
    {
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUri = $config['redirect_uri'];
        $this->apiBaseUrl = 'https://graph.instagram.com';
        $this->authorizeUrl = 'https://api.instagram.com/oauth/authorize';
        $this->accessTokenUrl = 'https://api.instagram.com/oauth/access_token';
        $this->scopes = $config['scopes'] ?? ['user_profile', 'user_media'];
        $this->httpClient = new Client();
    }

    public function authorize(bool $redirect = false)
    {
        $url = $this->authorizeUrl . '?' . http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(',', $this->scopes),
            'response_type' => 'code',
        ]);

        if ($redirect) {
            HTTPUtil::redirectURL($url);
        }

        return $url;
    }

    public function getTokenWithAuthCode(string $code)
    {
        try {
            $response = $this->httpClient->post($this->accessTokenUrl, [
                'form_params' => [
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'grant_type' => 'authorization_code',
                    'redirect_uri' => $this->redirectUri,
                    'code' => $code,
                ]
            ]);
            $this->token = json_decode($response->getBody(), true);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
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
        return null;
    }

    public function getUser(string $accessToken = null)
    {
        $accessToken = $accessToken ?? $this->token['access_token'];

        if (empty($accessToken)) {
            throw new \InvalidArgumentException('Invalid access token! Please try again later!');
        }

        $profile = [];
        try {
            $response = $this->httpClient->get($this->apiUrl.'/v1/users/self', [
                'query' => [
                    'access_token' => $accessToken,
                ]
            ]);
            $profile = json_decode($response->getBody(), true);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if (empty($profile)) {
            throw new AuthenticationException('Could not retrieve profile information! Please try again later!');
        }

        return $profile;
    }

    public function refreshAccessToken(string $refreshToken = null)
    {
        return null;
    }

    public function revokeAccessToken(string $accessToken)
    {
        return false;
    }
}