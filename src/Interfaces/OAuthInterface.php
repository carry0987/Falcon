<?php
namespace carry0987\Falcon\Interfaces;

interface OAuthInterface
{
    /**
     *  Redirect to the provider's authentication page.
     * 
     * @param bool $redirect
     * @return string
     */
    public function authorize(bool $redirect = false);

    /**
     *  Get the authorization code from the provider callback.
     *
     *  @param string $code The authorization code from the provider callback.
     *  @return array
     */
    public function getTokenWithAuthCode(string $code);

    /**
     *  Exchange the authorization code for an access token.
     *
     *  @param string $token The authorization code from the provider callback.
     *  @return string
     */
    public function getAccessToken(string $token);

    /**
     *  Get the refresh token.
     *
     *  @param string $token The authorization code from the provider callback.
     *  @return string
     */
    public function getRefreshToken();
    
    /**
     *  Get the authenticated user.
     *
     *  @return array
     */
    public function getUser();
    
    /**
     *  Refreshes an expired access token.
     *
     *  @param string $refreshToken
     *  @return mixed
     */
    public function refreshAccessToken(string $refreshToken);
    
    /**
     *  Revoke the access token.
     *
     *  @param string $accessToken
     *  @return mixed
     */
    public function revokeAccessToken(string $accessToken);
}
