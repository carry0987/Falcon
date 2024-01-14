<?php
require dirname(__DIR__).'/vendor/autoload.php';

use carry0987\Falcon\Falcon;

$config = [
    'providers' => [
        'github' => [
            'client_id' => 'your_github_client_id',
            'client_secret' => 'your_github_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php'
        ],
        'google' => [
            'client_id' => 'your_google_client_id',
            'client_secret' => 'your_google_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php?provider=google'
        ],
        'facebook' => [
            'client_id' => 'your_facebook_client_id',
            'client_secret' => 'your_facebook_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php?provider=facebook'
        ],
        'instagram' => [
            'client_id' => 'your_instagram_client_id',
            'client_secret' => 'your_instagram_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php?provider=instagram'
        ],
        'twitter' => [
            'client_id' => 'your_twitter_client_id',
            'client_secret' => 'your_twitter_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php?provider=twitter'
        ],
        'reddit' => [
            'client_id' => 'your_reddit_client_id',
            'client_secret' => 'your_reddit_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php?provider=reddit'
        ],
        'discord' => [
            'client_id' => 'your_discord_client_id',
            'client_secret' => 'your_discord_client_secret',
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php?provider=discord'
        ],
        'line' => [
            'client_id' => 'your_line_channel_id', // Channel ID
            'client_secret' => 'your_line_channel_secret', // Channel secret
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php?provider=line'
        ],
        'telegram' => [
            'client_id' => 'XXXXXXXX', // Bot token ID, e.g. XXXXXXXX:###########, just XXXXXXXX
            'client_secret' => '###########', // Bot token, e.g. XXXXXXXX:###########, just ###########
            'redirect_uri' => 'https://your-website.com/path/to/redirect.php?provider=telegram',
            'callback_url' => 'https://your-website.com/path/to/redirect.php?provider=telegram&getUser=true', // Callback URL
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
    case 'discord':
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
        //Get url query string
        if (!isset($_GET['hash']) && !isset($_GET['getUser'])) {
            $login_url = $provider->authorize();
        } else {
            $user = !isset($_GET['getUser']) ? $provider->getUser($_GET) : null;
            echo '<h2>Authenticated User Information:</h2>';
            echo '<pre>' . print_r($user, true) . '</pre>';
        }
        break;
    default:
        throw new Exception('Invalid provider name');
}
?>

<ul>
    <?php if (!isset($user)): ?>
    <li><a href="<?=$login_url;?>">Login with <?=ucfirst($providerName);?></a></li>
    <?php endif; ?>
</ul>
<script>
if (window.location.hash.startsWith('#tgAuthResult=')) {
    const tgAuthResult = window.location.hash.substring('#tgAuthResult='.length);

    // Decode base64
    const decoded = atob(tgAuthResult);
    alert(decoded);
}
</script>

<?php if (isset($user)): ?>
<a href="?provider=<?=$providerName;?>&logout=true&access_token=<?=$accessToken ?? null;?>">Logout</a>
<?php endif; ?>
