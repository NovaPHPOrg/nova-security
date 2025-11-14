<?php
declare(strict_types=1);

namespace nova\plugin\security;
enum Reason: string
{
    case BLACKLIST         = 'IP已被封禁';
    case RATE_LIMIT        = '访问过于频繁';
    case MALICIOUS_RULE    = '触发安全防护规则';
    case TOO_MANY_FAILURES = '异常操作过多';
    case ILLEGAL_REQUEST   = '非法请求';
    case ABNORMAL_DEVICE   = '检测到设备环境异常';
    case REGION_BLOCK      = '该地区暂不开放访问';
    case ACCOUNT_BAN       = '账号被封禁';
    case SYSTEM_MAINTAIN   = '系统维护中，请稍后访问';

    /** 获取详细说明 */
    public function detail(): string
    {
        return match($this) {
            Reason::BLACKLIST         => '您的IP已被系统封禁，请稍后再试。',
            Reason::RATE_LIMIT        => '您的访问请求过于频繁，请稍后重试。',
            Reason::MALICIOUS_RULE    => '系统检测到您的请求存在风险，已被拦截。',
            Reason::TOO_MANY_FAILURES => '检测到过多异常或失败操作，已限制访问。',
            Reason::ILLEGAL_REQUEST   => '您的请求不被允许，访问已被拦截。',
            Reason::ABNORMAL_DEVICE   => '检测到您的设备环境异常，无法继续访问。',
            Reason::REGION_BLOCK      => '当前地区暂不开放访问，感谢理解。',
            Reason::ACCOUNT_BAN       => '当前账号已被封禁，无法访问。',
            Reason::SYSTEM_MAINTAIN   => '系统维护中，暂时无法访问。',
        };
    }
}
