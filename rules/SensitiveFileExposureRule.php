<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class SensitiveFileExposureRule extends iRuleItem
{
    function name(): string
    {
        return "Sensitive File Exposure";
    }

    function description(): string
    {
        return "检测是否存在敏感文件暴露在应用程序中。";
    }

    public function locations(): array
    {
        return [
            RuleLocation::PATHS
        ];
    }

    function regex(): array
    {
        return [
        new RuleRegex("Configuration File Exposure", "(config|settings|database|env|plist)\\.(xml|json|ini|cfg|conf|properties|yml)", 2),
        new RuleRegex("Key or Certificate File Exposure", "(key|cert|pem|rsa|id_rsa|id_dsa)\\.(pub|pem|key)", 2),
        new RuleRegex("Password or Credentials File Exposure", "(password|passwd|credentials|secret|token)\\.(txt|csv|log|doc|xls|xlsx|pdf|json|yaml|yml)", 2),
        new RuleRegex("Backup or Log File Exposure", "(backup|bak|old|log|dat|db)\\.(xml|json|ini|cfg|conf|properties|yml|txt|csv|log|doc|xls|xlsx|pdf|dat|db)", 2)
    ];
    }
}
