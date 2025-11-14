# nova-security

一个基于60秒滑动窗口的Web应用防火墙，用于防御速率滥用和简单攻击。

## 设计哲学

**"Bad programmers worry about the code. Good programmers worry about data structures."**

这个模块做对了以下几点：

### ✅ 数据结构优先

`IpAddress` 只用4个字段就表达了所有状态：

```php
private array $hits = [];              // 按URI计数的请求次数
private int $failures = 0;             // 失败次数
private int $blacklistedTil = 0;       // 封禁到什么时候
private int $maliceCount = 0;          // 累犯次数（影响封禁时长）
```

没有花哨的"置信度评分"、"风险等级"这些过度设计的垃圾。

### ✅ 消除特殊情况

所有检查都遵循同一模式：
```php
$this->applyTimeWindow($now);
return $this->counter > $threshold;
```

没有"首次登录特殊处理"、"VIP用户例外"这种边界情况。**好代码不需要if。**

### ✅ 实用主义

60秒滑动窗口 = `$now - $lastSeen > 60`，就这么简单。
- 不需要令牌桶
- 不需要漏桶算法  
- 不需要Redis的ZSET

**"Theory and practice sometimes clash. Theory loses. Every single time."**

## 核心功能

### 1. IP行为追踪（IpAddress）

```php
$ip = IpAddress::load('1.2.3.4');

// 记录访问
$ip->tick('/api/login', time());

// 记录失败（404、登录失败等）
$ip->registerFailure(time());

// 检查状态
if ($ip->isBlacklisted($now)) { ... }                    // 是否被封
if ($ip->isRateLimited('/api/login', 5)) { ... }         // 是否超速
if ($ip->hasExcessiveFailures(10)) { ... }               // 失败过多

// 惩罚（递增封禁）
$until = $ip->punish($now, 600); // 封禁 600秒 * 累犯次数
```

**自动持久化** - 析构函数自动保存到缓存，调用方不用操心。

### 2. WAF拦截器（NovaWaf）

自动注册到应用启动事件，提供3层防护：

#### ① 黑名单拦截

```php
if ($ip->isBlacklisted($now)) → 403
```

已封禁的IP直接拒绝，不浪费资源。

#### ② 路径限流

```php
NovaWaf::instance()
    ->limit('/api/login', 5)    // 登录接口：60秒最多5次
    ->limit('/api/search', 100); // 搜索接口：60秒最多100次
```

**按路径前缀匹配** - `/api/login` 会匹配 `/api/login?user=foo`。

#### ③ 失败洪水防护

```php
'useFailedFlood' => true,
'failureThreshold' => 10,  // 60秒内超过10次404 → 封禁
```

在 `app.send` 事件中检测404响应，自动记录失败。

### 3. 配置（WafConfig）

在 `config/waf.php` 配置：

```php
return [
    'useRule'            => true,   // TODO: 规则引擎（未实现）
    'useRateLimit'       => false,  // 是否启用路径限流
    'useFailedFlood'     => true,   // 是否启用失败洪水检测
    'rateLimit'          => 5,      // 全局限流（每60秒）
    'failureThreshold'   => 10,     // 失败阈值（每60秒）
    'basePenaltySeconds' => 600,    // 基础封禁时长（会递增）
];
```

**配置是不可变的** - 构造后不会写回，避免运行时修改配置文件。

### 4. 响应格式

**JSON**（Accept 不包含 html）：
```json
{
    "code": 403,
    "msg": "您的访问请求过于频繁，请稍后重试。"
}
```

**HTML**（Accept 包含 html）：
现代化错误页面，带🚫图标和友好提示。

## 技术细节

### 为什么封禁时长递增？

```php
$blacklistedTil = $now + $basePenaltySeconds * $maliceCount;
```

- 首次：600秒（10分钟）
- 二次：1200秒（20分钟）
- 三次：1800秒（30分钟）

**让攻击者的成本递增** - 这是最简单的反制策略。

### 为什么60秒窗口？

```php
if ($now - $this->lastSeen > self::WINDOW_SECONDS) {
    $this->hits = [];
    $this->failures = 0;
}
```

- 超过60秒未活动 → 自动重置
- 持续活动 → 累积计数
- **无需定时器、无需清理任务**

这就是"好品味"：用时间戳解决了定时清理的问题。

### 为什么路径限流要显式配置？

```php
->limit('/api/login', 5)
```

因为**不是所有路径都需要追踪**：
- 静态资源不需要追踪
- 公开页面不需要追踪
- 只追踪敏感接口，节省内存

**"If you need more than 3 levels of indentation, you're screwed."**  
显式配置比自动检测所有路径要清晰100倍。

## 使用方法

### 全局启用

```php
// 在 Application 启动时
NovaWaf::register();

// 配置限流
NovaWaf::instance()
    ->limit('/api/login', 5)
    ->limit('/api/register', 3)
    ->whiteList('/health');  // 健康检查不拦截
```

### 手动记录失败

```php
// 登录失败、验证码错误时
$ip = IpAddress::load($request->getClientIP());
$ip->registerFailure(time());

// 检查是否需要惩罚
if ($ip->hasExcessiveFailures(10)) {
    $ip->punish(time(), 600);
}
```

## 已知问题

### ⚠️ 规则引擎未实现

```php
// TODO 规则判断
//
```

`checkRequest()` 里有个空的TODO - **SQL注入、XSS检测都还没做**。

这是有意为之：
- 先做好数据结构和速率限制
- 规则引擎可以后续插入，不破坏现有逻辑
- **"Never put policy in low-level code"**

### ⚠️ 路径限流可能有性能问题

```php
foreach ($this->pathLimits as $path => $maxRequests) {
    if (str_starts_with($uri, $path)) { ... }
}
```

如果配置了100个路径限流规则，每次请求都要遍历100次。

**解决方案**（如果真遇到性能瓶颈再说）：
- 用Trie树做前缀匹配
- 或者把常见路径放最前面

但现在**不做** - 因为大部分应用只会限流5-10个接口。

**"We don't add complexity for hypothetical problems."**

## 文件清单

```
src/nova/plugin/security/
├── IpAddress.php    # IP行为追踪器（核心数据结构）
├── NovaWaf.php      # WAF拦截器（策略执行层）
├── Reason.php       # 拦截原因枚举
├── WafConfig.php    # 配置管理（只读）
└── README.md        # 本文件
```

## License

MIT

---

> **"Talk is cheap. Show me the code."**  
> 有问题看代码，代码才是真相。

