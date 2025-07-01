<?php
declare(strict_types=1);

namespace app\nova\plugin\security\rules;

use app\nova\plugin\security\iRuleItem;
use app\nova\plugin\security\RuleLocation;
use app\nova\plugin\security\RuleRegex;

class BotRule extends iRuleItem
{
    function name(): string
    {
        return "Bot";
    }

    function description(): string
    {
        return "恶意爬虫是一种恶意程序，通过模拟浏览器行为，对网站进行大量访问，占用服务器资源。";
    }

    public function locations(): array
    {
        return [
            RuleLocation::HEADERS
        ];
    }

    function regex(): array
    {
        return [
        new RuleRegex("Common Malicious Crawler User-Agent Strings", "user-agent: (go|curl|wget|python-requests|libwww-perl|httpclient|python-urllib|http_request|java|scrapy|php|node\\.js|mechanize|axios|httpie|okhttp|lua-resty-http|Go-http-client|Jakarta Commons-HttpClient|Apache-HttpClient|Jakarta HttpClient|libcurl|python-httpx|python-tornado|guzzlehttp|httplib2|perseus|resty|simplepie|typhoeus|axios/axios|aiohttp|http\\.client|http\\.request|http\\.rb|Net::HTTP|HTTPie|PycURL|Requests|httplib|Mechanize|Scrapy|LWP::Simple|RestClient|async-http-client)(?![\\w.;/\\\\-])", 3)
    ];
    }
}
