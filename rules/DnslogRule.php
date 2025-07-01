<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class DnslogRule extends iRuleItem
{
    function name(): string
    {
        return "DNSLog";
    }

    function description(): string
    {
        return "检测是否存在通过DNSLog加载外部资源的漏洞。";
    }

    public function locations(): array
    {
        return [
            RuleLocation::PARAMETERS,
        RuleLocation::BODY
        ];
    }

    function regex(): array
    {
        return [
        new RuleRegex("DNSLog Blacklist Domain", "dnslog\\.[\\w]+", 2),
        new RuleRegex("Dig.pm Domain", "dig\\.pm", 2),
        new RuleRegex("Ceye Domain", "ceye\\.[\\w]+", 2),
        new RuleRegex("Eyes.sh Domain", "\"eyes\\.sh", 2)
    ];
    }
}
