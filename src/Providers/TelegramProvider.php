<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;
use carry0987\Falcon\Utils\HTTPUtil;
use carry0987\Falcon\Utils\SecurityUtil;

class TelegramProvider implements OAuthInterface
{
    protected $botID;
    protected $botToken;
    protected $botUsername;
    protected $redirectUri;
    protected $callbackUrl;
    protected $authorizeUrl;

    public function __construct(array $config)
    {
        $this->botID = $config['client_id']; // Bot token ID
        $this->botToken = $config['client_secret']; // Bot token
        $this->redirectUri = $config['redirect_uri'];
        $this->callbackUrl = $config['callback_url'] ?? $this->redirectUri;
        $this->authorizeUrl = 'https://oauth.telegram.org/auth';
    }

    public function authorize(bool $redirect = false)
    {
        $securityUtil = new SecurityUtil($this);
        $state = $securityUtil->generateState();

        $params = [
            'bot_id' => $this->botID,
            'origin' => $this->redirectUri,
            'return_to' => $this->callbackUrl,
            'scopes' => 'inline',
            'state' => $state,
            'request_access' => 'write',
            'embed' => 1,
        ];

        $url = $this->authorizeUrl.'?'.http_build_query($params);

        if ($redirect) {
            HTTPUtil::redirectUrl($url);
        }

        return $url;
    }

    public function getTokenWithAuthCode(string $code, string $state = null)
    {
        return null;
    }

    public function getAccessToken(string $code)
    {
        return null;
    }

    public function getRefreshToken()
    {
        return null;
    }

    public function getUser(array $data = null)
    {
        if (!$data || !$this->isValidChecksum($data)) {
            throw new AuthenticationException('Invalid data or checksum.');
        }

        if (time() - $data['auth_date'] > 86400) {
            throw new AuthenticationException('Authorization data is outdated.');
        }

        $user_data = $this->sanitizeUserData($data);

        return $user_data;
    }

    public function refreshAccessToken(string $refreshToken)
    {
        return true;
    }

    public function revokeAccessToken(string $accessToken = null)
    {
        return true;
    }

    private function isValidChecksum(array $data)
    {
        $requiredKeys = ['id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date'];
        $check_hash = $data['hash'] ?? '';
        if (!$check_hash) {
            return false;
        }

        $data_check_array = [];
        foreach ($requiredKeys as $key) {
            if (isset($data[$key])) {
                $data_check_array[] = $key.'='.$data[$key];
            }
        }

        sort($data_check_array);
        $data_check_string = implode("\n", $data_check_array);
        $secret_key = hash('sha256', $this->botID.':'.$this->botToken, true);
        $hash = hash_hmac('sha256', $data_check_string, $secret_key);

        return strcmp($hash, $check_hash) === 0;
    }

    private function sanitizeUserData(array $data)
    {
        $sanitized_data = [];
        foreach ($data as $key => $value) {
            $sanitized_data[$key] = htmlspecialchars(strip_tags($value));
        }

        return $sanitized_data;
    }
}
