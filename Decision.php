<?php
declare(strict_types=1);

namespace app\nova\plugin\security;

enum Decision: string
{
    case ALLOW = 'allow';
    case DENY  = 'deny';

    public function isAllowed(): bool
    {
        return $this === self::ALLOW;
    }

    public function isDenied(): bool
    {
        return $this === self::DENY;
    }
}
