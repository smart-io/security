<?php
namespace Sinergi\Security\RedirectToken;

use Sinergi\Token\StringGenerator;

trait RedirectTokenTrait
{
    private static $redirectTokenApcCacheKey = 'sinergi.redirect.token.';
    private static $redirectTokenExpirationTime = 86400;

    /**
     * @param string $redirectUrl
     * @return string
     */
    protected function createRedirectToken($redirectUrl)
    {
        $token = StringGenerator::randomAlnum(16);
        apc_store(self::$redirectTokenApcCacheKey . $token, $redirectUrl);
        return $token;
    }

    /**
     * @param string $token
     * @return string
     */
    protected function getRedirectUrlFromToken($token)
    {
        $cacheKey = self::$redirectTokenApcCacheKey . $token;
        if (apc_exists($cacheKey)) {
            $retval = apc_fetch($cacheKey);
            apc_delete($cacheKey);
            return $retval;
        }
        return null;
    }
}
