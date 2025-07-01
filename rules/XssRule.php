<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class XssRule extends iRuleItem
{
    function name(): string
    {
        return "XSS";
    }

    function description(): string
    {
        return "XSS是一种常见的攻击手段，通过在输入框中输入JavaScript代码，获取用户的Cookie信息。";
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
        new RuleRegex("Script Tag Injection", "<script\\b[^<]*(?:(?!<\\/script>)<[^<]*)*<\\/script>", 3),
        new RuleRegex("Iframe Tag Injection", "<iframe\\b[^<]*(?:(?!<\\/iframe>)<[^<]*)*<\\/iframe>", 3),
        new RuleRegex("Object Tag Injection", "<object\\b[^<]*(?:(?!<\\/object>)<[^<]*)*<\\/object>", 3),
        new RuleRegex("Embed Tag Injection", "<embed\\b[^<]*(?:(?!<\\/embed>)<[^<]*)*<\\/embed>", 3),
        new RuleRegex("Style Tag Injection", "<style\\b[^<]*(?:(?!<\\/style>)<[^<]*)*<\\/style>", 3),
        new RuleRegex("Link Tag Injection", "<link\\b[^<]*(?:(?!<\\/link>)<[^<]*)*<\\/link>", 3),
        new RuleRegex("Javascript URI", "\\bjavascript:[^<]+", 3),
        new RuleRegex("Data URI", "data:text/html", 2),
        new RuleRegex("VBScript URI", "vbscript:[^<]+", 2),
        new RuleRegex("Event Handler Injection", "<.+on\\w+=", 3),
        new RuleRegex("HTML Tag Injection", "<[a-zA-Z]+[\\s\\S]*>", 3),
        new RuleRegex("Encoded JavaScript URL", "href(.+)javascript:", 3)
    ];
    }
}
