<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class CommandInjectionRule extends iRuleItem
{
    function name(): string
    {
        return "Command Injection";
    }

    function description(): string
    {
        return "检测到可能的命令执行行为";
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
        new RuleRegex("PHP Functions", "(exec|system|passthru|shell_exec|proc_open|popen)", 3),
        new RuleRegex("Python Functions", "(os\\.system|os\\.popen|subprocess\\.Popen|subprocess\\.call|subprocess\\.run|eval|exec)", 3),
        new RuleRegex("Ruby Methods", "(system|exec|popen|spawn|IO\\.popen|IO\\.sysopen|eval)", 3),
        new RuleRegex("Perl Functions", "(system|exec|open|eval)", 3),
        new RuleRegex("Java Methods", "(Runtime\\.getRuntime|ProcessBuilder)", 3),
        new RuleRegex("Non-alphanumeric Characters Around Command Execution Functions", "(exec|system|passthru|shell_exec|proc_open|popen|os\\.system|os\\.popen|subprocess\\.Popen|subprocess\\.call|subprocess\\.run|eval|exec|Runtime\\.getRuntime|ProcessBuilder)", 3),
        new RuleRegex("Logical Operators and Newline Characters", "([|][|]|[&][&]|\\n|\\r)", 2),
        new RuleRegex("Common Linux Commands", "(cat|whoami|uname|netstat|ifconfig|wget|curl|chmod|chown|find|grep|echo|kill)[\\s\\\"'`}]?(?!\\w)", 2),
        new RuleRegex("Common Linux Files", "(/etc/passwd|/etc/shadow|/etc/hosts|/var/log/|/tmp/|/home/)", 2),
        new RuleRegex("Common Windows Files", "(C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts|C:\\\\Windows\\\\System32\\\\config\\\\|C:\\\\Users\\\\|C:\\\\Program Files\\\\|C:\\\\Temp\\\\)", 2),
        new RuleRegex("Common Windows Commands and Files", "(dir|type|whoami|systeminfo|tasklist|netstat|ipconfig|certutil|powershell|echo|findstr|ping|tracert|nslookup|net|netsh|wmic)[\\s\\\"'`}]?(?!\\w)", 2)
    ];
    }
}
