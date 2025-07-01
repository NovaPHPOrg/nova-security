<?php
declare(strict_types=1);

namespace app\nova\plugin\security;

use InvalidArgumentException;

/**
 * Tracks per-IP behaviour, including hits, failures,
 * escalating blacklist penalties and now a confidence score.
 */
final class IpAddress
{
    // ── configuration ─────────────────────────────────────────
    public const CONFIDENCE_WINDOW    = 300;  // 秒：置信度有效时间窗（默认 5 分钟）
    public const CONFIDENCE_THRESHOLD = 10;   // 分：超过即视为恶意

    /**
     * @param string $ip Client IP (IPv4/IPv6)
     */
    public function __construct(private readonly string $ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException("Invalid IP address: {$ip}");
        }
        $now              = time();
        $this->lastSeen   = $now;
        $this->lastFailureTime   = $now;
        $this->lastConfidenceTime = $now;
    }

    // ── runtime state ──────────────────────────────────────────
    private int $hitsPerMinute        = 0;
    private int $lastSeen;
    private int $maliceCount          = 0;
    private int $blacklistedTil       = 0;

    private int $failedPerMinute      = 0;
    private int $lastFailureTime;

    // ↳ NEW: confidence tracking
    private int $confidence           = 0;
    private int $lastConfidenceTime;

    // ── getters ───────────────────────────────────────────────
    public function ip(): string              { return $this->ip; }
    public function blacklistedUntil(): int   { return $this->blacklistedTil; }
    public function hitsPerMinute(): int      { return $this->hitsPerMinute; }
    public function failuresPerMinute(): int  { return $this->failedPerMinute; }

    /** 当前置信度（自动检查并可能归零） */
    public function confidence(int $now = null): int
    {
        $now ??= time();
        $this->expireConfidenceIfNeeded($now);
        return $this->confidence;
    }

    /** 置信度 ≥ 阈值即认为恶意 */
    public function isMalicious(int $now = null): bool
    {
        return $this->confidence($now) >= self::CONFIDENCE_THRESHOLD;
    }

    // ── counters ──────────────────────────────────────────────
    public function tick(int $now): void
    {
        if ($now - $this->lastSeen <= 60) {
            ++$this->hitsPerMinute;
        } else {
            $this->hitsPerMinute = 1;
        }
        $this->lastSeen = $now;
    }

    public function registerFailure(int $now): void
    {
        if ($now - $this->lastFailureTime <= 60) {
            ++$this->failedPerMinute;
        } else {
            $this->failedPerMinute = 1;
        }
        $this->lastFailureTime = $now;
    }

    /**
     * ↑ UPDATED
     * 累加置信度并立即判定是否已达到恶意阈值。
     *
     * @param int      $now            当前 Unix 时间戳
     * @param int      $points         本次要累加的分值（默认 +1）
     * @param int|null $windowSeconds  自定义窗口；null ⇒ 使用默认 CONFIDENCE_WINDOW
     *
     * @return bool  true  ⇒ 当前置信度 ≥ CONFIDENCE_THRESHOLD（视为恶意）
     *               false ⇒ 尚未达到阈值
     */
    public function increaseConfidence(
        int $now,
        int $points = 1,
        ?int $windowSeconds = null
    ): bool {
        $this->expireConfidenceIfNeeded(
            $now,
            $windowSeconds ?? self::CONFIDENCE_WINDOW
        );

        $this->confidence       += $points;
        $this->lastConfidenceTime = $now;

        // 自动判定并返回结果
        return $this->confidence >= self::CONFIDENCE_THRESHOLD;
    }


    /** Apply punishment & reset other counters. */
    public function punish(int $now, Reason $reason, int $basePenaltySeconds): int
    {
        $this->maliceCount++;
        $this->blacklistedTil  = $now + $basePenaltySeconds * $this->maliceCount;
        $this->hitsPerMinute   = 0;
        $this->failedPerMinute = 0;
        $this->confidence      = 0;           // 可选：处罚后清零置信度
        return $this->blacklistedTil;
    }

    // ── helpers ───────────────────────────────────────────────
    private function expireConfidenceIfNeeded(
        int $now,
        int $windowSeconds = self::CONFIDENCE_WINDOW
    ): void {
        if ($now - $this->lastConfidenceTime > $windowSeconds) {
            $this->confidence = 0;
        }
    }
}
