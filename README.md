# Falcon
[![Packgist](https://img.shields.io/packagist/v/carry0987/falcon.svg?style=flat-square)](https://packagist.org/packages/carry0987/falcon)  
Falcon - A versatile PHP framework designed for seamless integration of third-party social logins. Supports major services including Github, Google, Facebook, Twitter, Line, and Telegram, delivering simple and secure authentication via a unified interface and design patterns.

## Features
- Easily integrate multiple third-party logins.
- Unified interface to simplify third-party authentication processes.
- Support for extending more third-party login providers.

## Installation
Install Falcon into your project with [Composer](https://getcomposer.org/):

```
composer require carry0987/falcon
```

## Usage Example
First, set up the credentials and other configuration information for each third-party service in your project:

```php
$config = [
    'providers' => [
        'github' => [
            'client_id' => 'your_github_client_id',
            'client_secret' => 'your_github_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=github'
        ],
        'line' => [
            'client_id' => 'your_line_client_id', // Channel ID
            'client_secret' => 'your_line_client_secret', // Channel secret
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=line'
        ],
        'telegram' => [
            'client_id' => 'your_telegram_client_id', // Bot username
            'client_secret' => 'your_telegram_client_secret', // Bot token
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=telegram'
        ],
        // Configuration for other third-party login providers...
    ],
];
```

Next, create an instance of `Falcon` and initiate the login process with the chosen third-party provider:

```php
$falcon = new \Carry0987\Falcon\Falcon($config);
$providerName = $_GET['provider'] ?? 'default';
$provider = $falcon->createProvider($providerName);

// Start the OAuth login process
if (!isset($_GET['code'])) {
    $loginUrl = $provider->authorize();
    // Redirect user to the login page
    header('Location: ' . $loginUrl);
    exit;
}

// Handle the callback and retrieve user information
if ($providerName === 'telegram') {
    // Special handling for Telegram login flow...
} else {
    $accessToken = $provider->getTokenWithAuthCode($_GET['code']);
    $user = $provider->getUser();
    
    // Output user information
    echo "<pre>" . print_r($user, true) . "</pre>";
}
```

To end the **login** session, you can revoke the `access token`:

```php
if (isset($_GET['logout'])) {
    $provider->revokeAccessToken($_GET['access_token'] ?? null);
    // Redirect back to the login page or homepage
    header('Location: ?provider=' . $providerName);
    exit;
}
```

You can add more standard OAuth processing logic to your code, such as handling error states, redirecting to other pages, etc.

## Support
If you have any issues, please open an issue on our GitHub repository.

Enjoy using Falcon in your project!
