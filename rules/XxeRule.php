<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class XxeRule extends iRuleItem
{
    function name(): string
    {
        return "XXE";
    }

    function description(): string
    {
        return "检测是否存在通过XML实体加载外部资源的漏洞。";
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
        new RuleRegex("Generic ENTITY Declaration", "<!ENTITY\\s+.+>", 1),
        new RuleRegex("DOCTYPE Declaration", "<!DOCTYPE\\s+.+\\[", 1),
        new RuleRegex("SYSTEM Entity Declaration", "<!ENTITY\\s+.+\\s+SYSTEM\\s+['\\\"].+['\\\"]\\s*>", 3),
        new RuleRegex("PUBLIC Entity Declaration", "<!ENTITY\\s+.+\\s+PUBLIC\\s+['\\\"].+['\\\"]\\s+['\\\"].+['\\\"]\\s*>", 2)
    ];
    }
}
