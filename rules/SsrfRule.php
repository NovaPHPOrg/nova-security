<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class SsrfRule extends iRuleItem
{
    function name(): string
    {
        return "SSRF";
    }

    function description(): string
    {
        return "SSRF是一种常见的攻击手段，通过在输入框中输入URL，获取服务器的内部信息。";
    }

    public function locations(): array
    {
        return [
            RuleLocation::PATHS,
        RuleLocation::BODY
        ];
    }

    function regex(): array
    {
        return [
        new RuleRegex("Potential SSRF URL", "(gopher|doc|php|glob|file|phar|zlib|ftp|ldap|dict|ogg|data|smb|tftp|rsync|telnet|jdbc|rmi|dns|ws|wss|sftp):", 2)
    ];
    }
}
