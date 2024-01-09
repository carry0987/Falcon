<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;
use carry0987\Falcon\Utils\HTTPUtil;
use carry0987\Falcon\Utils\SecurityUtil;
use GuzzleHttp\Client;

class GithubProvider implements OAuthInterface
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $apiUrl;
    protected $webUrl;
    protected $scopes;
    protected $httpClient;
    protected $state;
    protected $token;

    public function __construct(array $config)
    {
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUri = $config['redirect_uri'];
        $this->apiUrl = 'https://api.github.com';
        $this->webUrl = 'https://github.com';
        $this->scopes = $config['scopes'] ?? ['user:email'];
        $this->httpClient = new Client();
    }

    public function authorize(bool $redirect = false)
    {
        $securityUtil = new SecurityUtil($this);
        $state = $securityUtil->generateState();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $this->scopes),
            'state' => $state
        ];

        $url = $this->webUrl.'/login/oauth/authorize?'.http_build_query($params);

        if ($redirect) {
            HTTPUtil::redirectUrl($url);
        }

        return $url;
    }

    public function getTokenWithAuthCode(string $code, string $state = null)
    {
        if (!$code) {
            throw new AuthenticationException('No authorization code provided.');
        }

        $securityUtil = new SecurityUtil($this);
        if (!$securityUtil->validateState($state)) {
            throw new AuthenticationException('Invalid state.');
        }

        $url = $this->webUrl.'/login/oauth/access_token?'.http_build_query([
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code
        ]);

        try {
            $response = $this->httpClient->post($url, [
                'headers' => [
                    'Accept' => 'application/json'
                ],
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() !== 200) {
            if (isset($this->token['error']) || !isset($this->token['access_token'])) {
                throw new AuthenticationException('Failed to obtain authorization token: '.($this->token['error'] ?? 'Unknown error'));
            }
            throw new AuthenticationException('Failed to get authorization token.');
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
        return null;
    }

    public function getUser(string $accessToken = null)
    {
        try {
            $response = $this->httpClient->get($this->apiUrl.'/user', [
                'headers' => [
                    'Authorization' => 'token '.$accessToken
                ]
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() !== 200) {
            throw new AuthenticationException('Failed to retrieve user information.');
        }

        return json_decode((string) $response->getBody(), true);
    }

    public function refreshAccessToken(string $refreshToken = null)
    {
        return null;
    }

    public function revokeAccessToken(string $accessToken)
    {
        $url = $this->apiUrl.'/applications/'.$this->clientId.'/token';

        try {
            $response = $this->httpClient->delete($url, [
                'headers' => [
                    'Accept' => 'application/vnd.github+json',
                    'X-GitHub-Api-Version' => '2022-11-28'
                ],
                'auth' => [$this->clientId, $this->clientSecret],
                'json' => ['access_token' => $accessToken]
            ]);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        if ($response->getStatusCode() != 204) {
            throw new AuthenticationException('Failed to revoke access token.');
        }
    }
}
