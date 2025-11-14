<?php
declare(strict_types=1);

namespace nova\plugin\security;

use InvalidArgumentException;
use nova\framework\core\Context;

/**
 * IP 行为追踪器 - 60秒滑动窗口
 *
 * 用法：
 *   $ip = IpAddress::load('1.2.3.4');
 *   $ip->tick(time());
 *   if ($ip->isBlacklisted($now)) { ... }
 *   if ($ip->isRateLimited(100)) { ... }
 */
class IpAddress
{
    private const int WINDOW_SECONDS = 60;
    private const string CACHE_KEY_PREFIX = 'waf:ip:';

    private array $hits = [];
    private int $failures = 0;
    private int $blacklistedTil = 0;
    private int $maliceCount = 0;
    private int $lastSeen = 0;


    /** 从缓存加载或创建新实例 */
    public static function load(string $ip): IpAddress
    {
        return Context::instance()->getOrCreateInstance($ip, function () use ($ip) {
            $key = self::CACHE_KEY_PREFIX . $ip;
            $instance = Context::instance()->cache->get($key);
            if ($instance instanceof self) {
                return $instance;
            }

            return new self($ip);
        });

    }

    /** 验证 IP 并初始化 */
    private function __construct(
        private readonly string $ip
    )
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException("Invalid IP: {$ip}");
        }
        $this->lastSeen = time();
    }

    public function ip(): string
    {
        return $this->ip;
    }

    /** 是否在黑名单中 */
    public function isBlacklisted(int $now): bool
    {
        return $this->blacklistedTil > $now;
    }

    /** 是否超过速率限制 */
    public function isRateLimited(string $uri, int $limit): bool
    {
        $this->applyTimeWindow(time());
        return $this->getHits($uri) > $limit;
    }

    /** 获取指定URI的访问次数 */
    private function getHits(string $uri): int
    {
        return $this->hits[$uri] ?? 0;
    }

    /** 增加指定URI的访问次数 */
    private function incrementHits(string $uri): void
    {
        if (!isset($this->hits[$uri])) {
            $this->hits[$uri] = 0;
        }
        $this->hits[$uri]++;
    }

    /** 是否失败次数过多 */
    public function hasExcessiveFailures(int $threshold): bool
    {
        $this->applyTimeWindow(time());
        return $this->failures > $threshold;
    }

    /** 记录一次请求 */
    public function tick(string $uri, int $now): void
    {
        $this->applyTimeWindow($now);
        $this->incrementHits($uri);
        $this->lastSeen = $now;
        $this->save();
    }

    /** 记录一次失败 */
    public function registerFailure(int $now): void
    {
        $this->applyTimeWindow($now);
        $this->failures++;
        $this->lastSeen = $now;
    }

    /** 拉黑 + 重置，惩罚时间递增 */
    public function punish(int $now, int $basePenaltySeconds): int
    {
        $this->applyTimeWindow($now);
        $this->maliceCount++;
        $this->blacklistedTil = $now + $basePenaltySeconds * $this->maliceCount;
        $this->failures = 0;
        $this->hits = [];
        $this->lastSeen = $now;
        $this->save();
        return $this->blacklistedTil;
    }

    /** 时间窗口过期则重置计数器 */
    private function applyTimeWindow(int $now): void
    {
        if ($now - $this->lastSeen > self::WINDOW_SECONDS) {
            $this->hits = [];
            $this->failures = 0;
            $this->save();
        }
    }


    private function save()
    {
        $key = self::CACHE_KEY_PREFIX . $this->ip;
        Context::instance()->cache->set($key, $this, 3600);
    }

    /** 析构时自动保存到缓存 */
    public function __destruct()
    {
        $this->save();
    }
}
