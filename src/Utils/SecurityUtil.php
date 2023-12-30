<?php
namespace carry0987\Falcon\Utils;

use carry0987\Falcon\Interfaces\OAuthInterface;

class SecurityUtil
{
    private $providerName;

    public function __construct(OAuthInterface $instance)
    {
        $this->providerName = $this->getProviderName($instance);
    }

    public function generateState()
    {
        $state = self::generateRandom(16);
        $this->storeInSession('state', $state);

        return $state;
    }

    public function validateState(string $state = null)
    {
        $storedState = $this->getFromSession('state');
        if ($state !== $storedState) {
            return false;
        }
        $this->removeFromSession('state');

        return true;
    }

    public function generateCodeVerifier()
    {
        $codeVerifier = self::generateRandom(32);
        $this->storeInSession('code_verifier', $codeVerifier);

        return $codeVerifier;
    }

    public function getCodeVerifier()
    {
        return $this->getFromSession('code_verifier');
    }

    private function getProviderName(OAuthInterface $instance)
    {
        return substr(strrchr(get_class($instance), '\\'), 1);
    }

    private static function generateRandom(int $length = 16)
    {
        return bin2hex(random_bytes($length));
    }

    private function storeInSession(string $key, string $value)
    {
        if (!isset($_SESSION['Falcon'])) {
            $_SESSION['Falcon'] = [];
        }
        $_SESSION['Falcon'][$this->providerName][$key] = $value;
    }

    private function getFromSession(string $key)
    {
        return $_SESSION['Falcon'][$this->providerName][$key] ?? null;
    }

    private function removeFromSession(string $key)
    {
        unset($_SESSION['Falcon'][$this->providerName][$key]);
    }
}
