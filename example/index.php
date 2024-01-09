<?php
require dirname(__DIR__).'/vendor/autoload.php';

use carry0987\Falcon\Falcon;

$config = [
    'providers' => [
        'github' => [
            'client_id' => 'your_github_client_id',
            'client_secret' => 'your_github_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/callback.php'
        ],
        'google' => [
            'client_id' => 'your_google_client_id',
            'client_secret' => 'your_google_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=google'
        ],
        'facebook' => [
            'client_id' => 'your_facebook_client_id',
            'client_secret' => 'your_facebook_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=facebook'
        ],
        'instagram' => [
            'client_id' => 'your_instagram_client_id',
            'client_secret' => 'your_instagram_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=instagram'
        ],
        'twitter' => [
            'client_id' => 'your_twitter_client_id',
            'client_secret' => 'your_twitter_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=twitter'
        ],
        'reddit' => [
            'client_id' => 'your_reddit_client_id',
            'client_secret' => 'your_reddit_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=reddit'
        ],
        'line' => [
            'client_id' => 'your_line_channel_id', // Channel ID
            'client_secret' => 'your_line_channel_secret', // Channel secret
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=line'
        ],
        'telegram' => [
            'client_id' => 'your_telegram_bot_username', // Bot username
            'client_secret' => 'your_telegram_bot_token', // Bot token
            'redirect_uri' => 'https://your-website.com/path/to/callback.php?provider=telegram'
        ],
    ],
];

$falcon = new Falcon($config);
$providerName = $_GET['provider'] ?? 'github';
$provider = $falcon->createProvider($providerName);

if (isset($_GET['logout'])) {
    $provider->revokeAccessToken($_GET['access_token'] ?? null);
    header('Location: ?provider='.$providerName);
}

switch ($providerName) {
    case 'github':
    case 'twitter':
    case 'reddit':
    case 'line':
        if (!isset($_GET['code'])) {
            $login_url = $provider->authorize();
        } else {
            $accessToken = $provider->getAccessToken($_GET['code'], $_GET['state']);
            $user = $provider->getUser($accessToken);
            echo '<h2>Authenticated User Information:</h2>';
            echo '<pre>' . print_r($user, true) . '</pre>';
        }
        break;
    case 'google':
    case 'facebook':
    case 'instagram':
        if (!isset($_GET['code'])) {
            $login_url = $provider->authorize();
        } else {
            $accessToken = $provider->getAccessToken($_GET['code']);
            $user = $provider->getUser($accessToken);
            echo '<h2>Authenticated User Information:</h2>';
            echo '<pre>' . print_r($user, true) . '</pre>';
        }
        break;
    case 'telegram':
        $tg_config = $provider->getConfig('telegram');
        $redirect_uri = $tg_config['redirect_uri'];
        if (empty($_COOKIE['tg_user']) && !isset($_GET['hash'])) {
            $provider->authorize();
        } else {
            $user = $provider->getUser($_GET);
            echo '<h2>Authenticated User Information:</h2>';
            echo '<pre>' . print_r($user, true) . '</pre>';
        }
        break;
    default:
        throw new Exception('Invalid provider name');
}
?>

<ul>
    <?php if (!isset($user) && $providerName !== 'telegram'): ?>
    <li><a href="<?=$login_url;?>">Login with <?=ucfirst($providerName);?></a></li>
    <?php endif; ?>
</ul>
<?php if (!isset($user) && $providerName === 'telegram'): ?>
<h2>Authentication Buttons:</h2>
<script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="falcon_auth_bot" data-size="large" data-auth-url="<?=$redirect_uri;?>" data-request-access="write"></script>
<?php endif; ?>

<?php if (isset($user)): ?>
<a href="?provider=<?=$providerName;?>&logout=true&access_token=<?=$accessToken ?? null;?>">Logout</a>
<?php endif; ?>
