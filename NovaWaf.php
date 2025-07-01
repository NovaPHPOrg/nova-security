<?php
declare(strict_types=1);

namespace app\nova\plugin\security;

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
        new NovaWaf();
    }

    protected WafConfig $wafConfig;

    public function __construct()
    {

        $this->wafConfig = new WafConfig();

        // if (App::getInstance()->debug)return;
        EventManager::addListener("app.start", function ($event, Request &$request) {
            $reason = Reason::BLACKLIST;
            if ($this->checkRequest($request,$reason)->isDenied()){
                $useHtml = $request->getHeaderValue("accept");
                if (!empty($useHtml)){
                    $useHtml = str_contains($useHtml, "html");
                }

                if(!$useHtml){
                    throw new AppExitException(Response::asJson([
                        "code" => 403,
                        "msg" => $reason->detail(),
                    ],403));
                }else{
                    throw new AppExitException(Response::asHtml($this->createHtml($reason),[],403));
                }
            }
        });

    }

    private function createHtml(Reason $reason): string
    {
        // 你可以根据Reason类型显示不同内容
        $title = '访问受限';
        $desc  = $reason->detail();

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


    private function checkRequest(Request $request,Reason &$reason): Decision{
      try{
          $now = time();
          $ipAddress = new IpAddress($request->getClientIP());
          // Blacklist check
          if ($ipAddress->blacklistedUntil() > $now) {
              Logger::warning('WAF deny (blacklist)', ['ip' => $ipAddress->ip()]);
              $reason = Reason::BLACKLIST;
              return Decision::DENY;
          }

          // Rate‑limit check
          if ($this->wafConfig->useRateLimit) {
              $ipAddress->tick($now);
              if ($ipAddress->hitsPerMinute() > $this->wafConfig->rateLimit) {
                  $ipAddress->punish($now, Reason::RATE_LIMIT, $this->wafConfig->basePenaltySeconds);
                  Logger::warning('WAF deny (rate limit)', [
                      'ip'   => $ipAddress->ip(),
                      'hits' => $ipAddress->hitsPerMinute(),
                  ]);
                  $reason = Reason::RATE_LIMIT;
                  return Decision::DENY;
              }
          }

          // Failure flood check
          if ($this->wafConfig->useFailedFlood &&
              $ipAddress->failuresPerMinute() > $this->wafConfig->failureThreshold) {
              $ipAddress->punish($now, Reason::TOO_MANY_FAILURES, $this->wafConfig->basePenaltySeconds);
              Logger::warning('WAF deny (fail flood)', [
                  'ip'       => $ipAddress->ip(),
                  'failures' => $ipAddress->failuresPerMinute(),
              ]);
              $reason = Reason::TOO_MANY_FAILURES;
              return Decision::DENY;
          }

          // Regex WAF
          if ($this->wafConfig->useRule) {
              $count = (new RuleManager($request))->check();
              if($count > 0 && $ipAddress->increaseConfidence(time(), $count)) {
                  //根据置信度判断为恶意
                  $ipAddress->punish($now, Reason::MALICIOUS_RULE, $this->wafConfig->basePenaltySeconds);
                  Logger::warning('WAF deny (rule)', [
                      'ip'   => $ipAddress->ip(),
                  ]);
                  $reason = Reason::MALICIOUS_RULE;
                  return Decision::DENY;
              }

          }
      }catch (\Exception $exception){
          $reason = Reason::ILLEGAL_REQUEST;
          return  Decision::DENY;
      }
        $reason = Reason::ILLEGAL_REQUEST;
        return  Decision::DENY;
    }


    /**
     * 限制每分钟访问$times
     * @param $times
     * @return void
     * @throws AppExitException
     */
    public static function limit($times): void
    {
        $ip = Context::instance()->request()->getClientIP();
        $address = new IpAddress($ip);
        if($address->hitsPerMinute() > $times){
            // 超出限制阈值
            throw new AppExitException(Response::asJson([
                "code" => 403,
                "msg"  => "IP address limit exceeded",
            ],403));
        }

        $address->tick(time());
    }
}