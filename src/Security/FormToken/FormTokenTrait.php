<?php
namespace Sinergi\Security\FormToken;

use Sinergi\Token\StringGenerator;

trait FormTokenTrait
{
    private static $formTokenApcCacheKey = 'sinergi.form.token';
    private static $formTokenExpirationTime = 86400;

    /**
     * @return string
     */
    protected function createFormToken()
    {
        $token = StringGenerator::randomAlnum(128);
        $cacheKey = self::$formTokenApcCacheKey . '.' . $token;
        apc_store($cacheKey, true, self::$formTokenExpirationTime);
        return $token;
    }

    /**
     * @param string $token
     * @return bool
     * @throws InvalidFormTokenException
     */
    protected function validateFormToken($token)
    {
        $retval = false;
        $cacheKey = self::$formTokenApcCacheKey . '.' . $token;
        if (apc_exists($cacheKey)) {
            $retval = apc_fetch($cacheKey);
            apc_delete($cacheKey);
        }
        if ($retval === true) {
            return true;
        }
        throw new InvalidFormTokenException;
    }
}
