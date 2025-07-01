<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class BackupFileRule extends iRuleItem
{
    function name(): string
    {
        return "Backup File";
    }

    function description(): string
    {
        return "检测是否存在不安全的备份文件暴露在应用程序中，包括隐藏文件。";
    }

    public function locations(): array
    {
        return [
            RuleLocation::PARAMETERS
        ];
    }

    function regex(): array
    {
        return [
        new RuleRegex("Common Backup and Temporary File Extensions", "\\.(bak[0-9]*|backup[0-9]*|old[0-9]*|orig|copy|save|tmp|temp|swp[0-9]*|sql[0-9]*|db[0-9]*|sqlite[0-9]*|log[0-9]*|1|part|crdownload|dmp|~|\\.~[0-9]*~|bak~|old~|tmp~)(?![\\w.;/\\\\-])", 3),
        new RuleRegex("Unsecure Compressed Backup Files", "(backup|bak|old|www|site|web|archive|copy|stored|saved|temp|temporary|dump|data|test)[0-9]*\\.(tar|gz|zip|rar|7z|tgz)(?![\\w.;/\\\\-])", 3),
        new RuleRegex("Hidden Files", "\\.(?:git|env|htaccess|config|svn|DS_Store|bzr|cvs|hg|npmrc|yarnrc|editorconfig|eslintignore|prettierignore|dockerignore|gitignore|gitattributes|gitmodules|credentials|aws|bashrc|bash_profile|bash_logout|inputrc|nanorc|profile|tmux\\.conf|vimrc|zshrc|zprofile|zlogin|zlogout|zpreztorc)(?![\\w.;/\\\\-])", 3)
    ];
    }
}
