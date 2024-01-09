<?php
namespace carry0987\Falcon;

use carry0987\Falcon\Interfaces\OAuthInterface;

class Falcon
{
    private $config;
    private $providerMap = [];

    public function __construct(array $config)
    {
        $this->config = $config;
        if (!session_id()) {
            session_start();
        }
        $this->initializeProviderMap();
    }

    private function initializeProviderMap()
    {
        $this->providerMap = [
            'github' => Providers\GithubProvider::class,
            'google' => Providers\GoogleProvider::class,
            'facebook' => Providers\FacebookProvider::class,
            'instagram' => Providers\InstagramProvider::class,
            'twitter' => Providers\TwitterProvider::class,
            'reddit' => Providers\RedditProvider::class,
            'telegram' => Providers\TelegramProvider::class,
            'line' => Providers\LineProvider::class
        ];
    }

    public function createProvider(string $providerName)
    {
        if (!isset($this->providerMap[strtolower($providerName)])) {
            throw new \InvalidArgumentException('The provider '.$providerName.' is not supported.');
        }

        $providerClass = $this->providerMap[strtolower($providerName)];
        
        if (!isset($this->config['providers'][strtolower($providerName)])) {
            throw new \RuntimeException('Configuration for '.$providerName.' is missing.');
        }

        $providerConfig = $this->config['providers'][strtolower($providerName)];

        $requiredConfig = ['client_id', 'client_secret', 'redirect_uri'];
        foreach ($requiredConfig as $configKey) {
            if (!isset($providerConfig[$configKey])) {
                throw new \RuntimeException('Configuration for '.$providerName.' is missing required key: '.$configKey);
            }
        }

        return new $providerClass($providerConfig);
    }

    public function addProvider(string $providerName, string $providerClass)
    {
        if (!class_exists($providerClass)) {
            throw new \RuntimeException('Class '.$providerClass.' does not exist.');
        }

        $interfaces = class_implements($providerClass);
        if (!isset($interfaces[OAuthInterface::class])) {
            throw new \RuntimeException('Class '.$providerClass.' must implement the OAuthInterface.');
        }

        $this->providerMap[strtolower($providerName)] = $providerClass;
    }

    public function removeProvider(string $providerName)
    {
        if (isset($this->providerMap[strtolower($providerName)])) {
            unset($this->providerMap[strtolower($providerName)]);
            return true;
        }

        return false;
    }

    public function getProviderMap()
    {
        return array_keys($this->providerMap);
    }

    public function getConfig(string $providerName = null)
    {
        if ($providerName) {
            return $this->config['providers'][strtolower($providerName)] ?? null;
        }

        return $this->config;
    }
}
