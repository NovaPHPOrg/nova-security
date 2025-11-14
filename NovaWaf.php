<?php
declare(strict_types=1);

namespace nova\plugin\security;

use nova\framework\core\Context;
use nova\framework\core\Logger;
use nova\framework\event\EventManager;
use nova\framework\exception\AppExitException;
use nova\framework\http\Request;
use nova\framework\http\Response;

class NovaWaf
{
    public static function register(): void
    {
        self::instance();
    }


    public static function instance(): NovaWaf
    {
        return Context::instance()->getOrCreateInstance("nova_waf", function () {
            return new NovaWaf();
        });
    }

    protected WafConfig $wafConfig;

    protected array $whiteList = [];

    /** @var array<string, int> 路径限流配置 path => maxRequestsPerMinute */
    protected array $pathLimits = [];

    public function __construct()
    {

        $this->wafConfig = new WafConfig();

        // if (App::getInstance()->debug)return;
        EventManager::addListener("app.start", function ($event, Request &$request) {
            $reason = Reason::BLACKLIST;
            if (!$this->checkRequest($request, $reason)) {
                $useHtml = $request->getHeaderValue("accept");
                if (!empty($useHtml)) {
                    $useHtml = str_contains($useHtml, "html");
                }

                if (!$useHtml) {
                    throw new AppExitException(Response::asJson([
                        "code" => 403,
                        "msg" => $reason->detail(),
                    ], 403));
                } else {
                    throw new AppExitException(Response::asHtml($this->createHtml($reason), [], 403));
                }
            }
        });
        EventManager::addListener("app.send", function ($event, Response &$response) {
            $code = $response->code();
            $request = Context::instance()->request();
            $ipAddress = IpAddress::load($request->getClientIP());
            if ($this->wafConfig->useFailedFlood && $code == 404) {
                $ipAddress->registerFailure(time());
            }
        });
    }

    private function createHtml(Reason $reason): string
    {
        // 你可以根据Reason类型显示不同内容
        $title = '访问受限';
        $desc = $reason->detail();

        return <<<HTML
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{$title}</title>
    <style>
        html, body { height: 100%; margin: 0; padding: 0; }
        body {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background: #f7f8fa;
            font-family: -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
        }
        .box {
            background: #fff;
            border-radius: 18px;
            box-shadow: 0 4px 24px 0 rgba(30,32,37,.10);
            padding: 40px 24px;
            max-width: 94vw;
            width: 360px;
            text-align: center;
        }
        .icon {
            font-size: 54px;
            color: #faad14;
            margin-bottom: 18px;
            user-select: none;
        }
        .title {
            font-size: 1.4rem;
            font-weight: 600;
            margin-bottom: 12px;
        }
        .desc {
            color: #636e72;
            font-size: 1.05rem;
        }
    </style>
</head>
<body>
    <div class="box">
        <div class="icon">🚫</div>
        <div class="title">{$title}</div>
        <div class="desc">{$desc}</div>
    </div>
</body>
</html>
HTML;
    }


    /**
     * @param Request $request
     * @param Reason $reason
     * @return bool true放行
     */
    private function checkRequest(Request $request, Reason &$reason): bool
    {

        if (in_array($request->getUri(), $this->whiteList)) return true;

        $now = time();
        $ipAddress = IpAddress::load($request->getClientIP());

        // Blacklist check
        if ($ipAddress->isBlacklisted($now)) {
            Logger::warning('WAF deny (blacklist)', ['ip' => $ipAddress->ip()]);
            $reason = Reason::BLACKLIST;
            return false;
        }

        // Rate limit check
        if ($this->wafConfig->useRateLimit) {
            $uri = $request->getUri();
            
            // 检查是否需要对此路径进行限流追踪
            foreach ($this->pathLimits as $path => $maxRequests) {
                if (str_starts_with($uri, $path)) {
                    $ipAddress->tick($path, $now);
                    
                    if ($ipAddress->isRateLimited($path, $maxRequests)) {
                        $ipAddress->punish($now, $this->wafConfig->basePenaltySeconds);
                        Logger::warning('WAF deny (rate limit)', ['ip' => $ipAddress->ip(), 'path' => $path]);
                        $reason = Reason::RATE_LIMIT;
                        return false;
                    }
                }
            }
        }

        // Failure flood check
        if ($this->wafConfig->useFailedFlood) {
            if ($ipAddress->hasExcessiveFailures($this->wafConfig->failureThreshold)) {
                $ipAddress->punish($now, $this->wafConfig->basePenaltySeconds);
                Logger::warning('WAF deny (fail flood)', ['ip' => $ipAddress->ip()]);
                $reason = Reason::TOO_MANY_FAILURES;
                return false;
            }
        }

        // TODO 规则判断
        //

        return true;
    }


    /**
     * 配置路径限流：限制指定路径每60秒的最大访问次数
     * @param string $path 路径前缀（如 "/api/login"）
     * @param int $maxRequests 60秒内最大请求次数
     * @return NovaWaf
     */
    public function limit(string $path, int $maxRequests): NovaWaf
    {
        $this->pathLimits[$path] = $maxRequests;
        return $this;
    }

    public function whiteList(string $path): NovaWaf
    {
        if (!in_array($path, $this->whiteList)) $this->whiteList[] = $path;
        return $this;
    }
}