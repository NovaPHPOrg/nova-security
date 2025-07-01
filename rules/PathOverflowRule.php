<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class PathOverflowRule extends iRuleItem
{
    function name(): string
    {
        return "Path Overflow";
    }

    function description(): string
    {
        return "检测是否允许用户通过输入访问系统文件系统中的未经授权的文件或目录。";
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
        new RuleRegex("Parent Directory Traversal (/../)", "/\\.\\./", 1),
        new RuleRegex("Parent Directory Traversal (../)", "\\.\\./", 1)
    ];
    }
}
