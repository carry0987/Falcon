<?php
namespace carry0987\Falcon\Utils;

use carry0987\Falcon\Exceptions\UtilsException;

class HTTPUtil
{
    public static function redirectURL(string $url)
    {
        if (!headers_sent()) {
            header('Location: '.$url);
            exit;
        } else {
            throw new UtilsException('Headers have already been sent.');
        }
    }

    public static function base64UrlEncode(string $data)
    {
        $b64 = base64_encode($data);
        $urlSafe = str_replace(['+', '/', '='], ['-', '_', ''], $b64);

        return $urlSafe;
    }
}
