<?php
declare(strict_types=1);

namespace app\nova\plugin\security;

use nova\framework\core\Context;

/**
 * Immutable value object holding WAF configuration.
 */
class WafConfig
{


    public bool $useRule = true; //使用规则拦截

    public bool $useRateLimit = false;// 使用访问限速

    public bool $useFailedFlood = true;

    public int $rateLimit = 5;// 每秒访问限制频率

    public int $basePenaltySeconds = 600; //异常封禁秒数

    public int $failureThreshold = 10; //每秒失败次数


    public function __construct()
    {
        $config = Context::instance()->config()->get("waf",[
            'useRule' => true,
            'useRateLimit' => false,
            'useFailedFlood' => true,
            'rateLimit' => 5,
            'basePenaltySeconds' => 600,
            'failureThreshold' => 10,
        ]);

        foreach ($config as $key => $value) {
            $this->{$key} = $value;
        }
    }

    public function __destruct()
    {
        Context::instance()->config()->set("waf",get_object_vars($this));
    }
}
