<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class LdapInjectionRule extends iRuleItem
{
    function name(): string
    {
        return "Ldap Injection";
    }

    function description(): string
    {
        return "检测是否存在可能绕过LDAP安全控制的字符串形式。";
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
        new RuleRegex("Basic and Protocol Variants JNDI Injection", '\\${jndi:(?:ldap|ldaps|rmi|dns|nis|nds|corba|iiop):', 3),
        new RuleRegex("URL Encoded JNDI Injection", "\\%24\\%7Bjndi:(?:ldap|ldaps|rmi|dns|nis|nds|corba|iiop):", 3),
        new RuleRegex("Colon Prefixed Lowercase Function Injection", '\\${(.+)?j}\\${(.+)?n}\\${(.+)?d}\\${(.+)?i}:', 3)
    ];
    }
}
