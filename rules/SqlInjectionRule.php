<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class SqlInjectionRule extends iRuleItem
{
    function name(): string
    {
        return "Sql Injection";
    }

    function description(): string
    {
        return "SQL注入是一种常见的攻击手段，通过在输入框中输入SQL语句，获取数据库中的数据。";
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
        new RuleRegex("Select-From Statement", "select\\s+.*\\s+from\\s+.*", 3),
        new RuleRegex("Select-Limit Statement", "select\\s+.*\\s+limit\\s+.*", 3),
        new RuleRegex("Union-Select Statement", "UNION\\s+SELECT", 3),
        new RuleRegex("Sleep Function", "sleep\\s*\\(\\s*\\d+\\s*\\)", 3),
        new RuleRegex("Benchmark Function", "benchmark\\s*\\(\\s*\\d+\\s*,\\s*.*\\s*\\)", 3),
        new RuleRegex("Information Schema Access", "FROM\\s+information_schema", 3),
        new RuleRegex("Into Outfile Statement", "INTO\\s+(?:dump|out)file\\s+.*", 3),
        new RuleRegex("Group By Statement", "GROUP\\s+BY", 3),
        new RuleRegex("Load File Function", "load_file\\s*\\(\\s*.*\\s*\\)", 3),
        new RuleRegex("Boolean Logic SQL Injection", "(?:\\sor\\s|\\sand\\s).*=.*", 2),
        new RuleRegex("SQL Keywords", "(?:\\sunion\\s|\\sselect\\s|\\sinsert\\s|\\supdate\\s|\\sdelete\\s|\\sdrop\\s|\\salter\\s)", 2)
    ];
    }
}
