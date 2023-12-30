<?php
namespace carry0987\Falcon\Providers;

use carry0987\Falcon\Interfaces\OAuthInterface;
use carry0987\Falcon\Exceptions\AuthenticationException;

class TelegramProvider implements OAuthInterface
{
    protected $botToken;
    protected $botUsername;

    public function __construct(array $config)
    {
        $this->botToken = $config['bot_token'] ?? null;
        $this->botUsername = $config['bot_username'] ?? null;
    }

    public function authorize(bool $redirect = false)
    {
        return null;
    }

    public function getTokenWithAuthCode(string $code)
    {
        return null;
    }

    public function getAccessToken(string $token)
    {
        return null;
    }

    public function getRefreshToken()
    {
        return null;
    }

    public function getUser(array $data = null)
    {
        if (!$this->checkAuthorization($data)) {
            return false;
        }
        $user_data = $this->saveUserData($data);
        $user_data = $this->getUserData($user_data);

        return $user_data ? $this->sanitizeUserData($user_data) : null;
    }

    public function refreshAccessToken(string $refreshToken)
    {
        return null;
    }

    public function revokeAccessToken(string $accessToken = null)
    {
        $this->clearUserData();
    }

    private function saveUserData(array $auth_data)
    {
        $auth_data_json = json_encode($auth_data);
        setcookie('tg_user', $auth_data_json);

        return $auth_data_json;
    }

    private function getUserData(string $user_data = null)
    {
        $user_data = $user_data ?? $_COOKIE['tg_user'] ?? null;
        if (isset($user_data)) {
            $auth_data_json = urldecode($user_data);
            $auth_data = json_decode($auth_data_json, true);

            return $auth_data;
        }

        return false;
    }

    private function clearUserData()
    {
        setcookie('tg_user', '', time() - 3600);
    }

    private function sanitizeUserData(array $tg_user)
    {
        $result = array();
        $result['first_name'] = htmlspecialchars($tg_user['first_name']);
        $result['last_name'] = htmlspecialchars($tg_user['last_name']);
        if (isset($tg_user['username'])) {
            $result['username'] = htmlspecialchars($tg_user['username']);
        }
        if (isset($tg_user['photo_url'])) {
            $result['photo_url'] = htmlspecialchars($tg_user['photo_url']);
        }

        return $result;
    }

    private function checkAuthorization(array $auth_data)
    {
        $check_hash = $auth_data['hash'] ?? '';
        unset($auth_data['provider'], $auth_data['hash']);

        $data_check_arr = [];
        foreach ($auth_data as $key => $value) {
            $data_check_arr[] = "$key=$value";
        }

        sort($data_check_arr);
        $data_check_string = implode("\n", $data_check_arr);

        $secret_key = hash('sha256', $this->botToken, true);
        $hash = hash_hmac('sha256', $data_check_string, $secret_key);

        if (strcmp($hash, $check_hash) !== 0) {
            throw new AuthenticationException('Data is NOT from Telegram');
        }

        if ((time() - $auth_data['auth_date']) > 86400) {
            throw new AuthenticationException('Data is outdated');
        }

        return true;
    }
}
