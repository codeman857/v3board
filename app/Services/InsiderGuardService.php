<?php

namespace App\Services;

use App\Models\ServerAnytls;
use App\Models\ServerHysteria;
use App\Models\ServerShadowsocks;
use App\Models\ServerTrojan;
use App\Models\ServerTuic;
use App\Models\ServerV2node;
use App\Models\ServerVless;
use App\Models\ServerVmess;
use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * 风控中心（InsiderGuard）：登录 / 订阅审计、风险评分、节点 TCP 健康探测、告警与清理。
 * 采集点三处：AuthController::login 成功后、ClientController 与 AppController 拿到可下发节点后；写入失败只记日志，不影响业务。
 * 节点用 (node_type, node_id) 定位，因为各协议表的 id 互相独立。
 *
 * 数据量控制：
 *   - 活动表按小时合并：同一用户、同一类型、同一小时、同一 IP、同一 UA 只有一行并计数，客户端再频繁轮询也封顶；
 *     同一小时桶数超过上限后合并到溢出桶，随机 UA / 伪造 IP 也刷不大；UA 文本放字典表，活动行只存哈希
 *   - 节点下发表每人每节点一行（首次 / 最近时间 + 次数），总行数封顶为用户数 × 节点数
 *   - 健康探测只在状态变化时落库，状态不变时每小时补记一行
 *   - 清理任务每小时按保留天数删除过期记录
 *
 * 限制：被限制的用户账号、凭据、节点列表都不动，只是拉订阅时所有节点的入口地址换成假地址，让泄露出去的订阅拿不到真实入口；
 * 假地址在风控设置里配置，留空则按用户生成一个固定的、看起来像公网的 IPv4（240～254 开头的 IANA 保留段，全网不可路由，
 * 不会把流量打到别人的服务器上）；解除后恢复。
 */
class InsiderGuardService
{
    const EVENT_LOGIN = 'login';
    const EVENT_SUBSCRIPTION = 'subscription';
    // UDP / QUIC 协议不做 TCP 探测：按节点类型，v2node 再看 protocol 字段
    const UDP_TYPES = ['hysteria', 'tuic'];
    const UDP_PROTOCOLS = ['hysteria', 'hysteria2', 'tuic'];
    // 同一用户、同一节点集合在这个窗口内只记一次下发；查「异常前 24h 内被下发过」时要把这个窗口加进查询下界，否则边界上会漏
    const DELIVERY_DEDUP_SECONDS = 6 * 3600;
    // 活动按这个粒度合并
    const BUCKET_SECONDS = 3600;
    // 同一用户同一小时最多这么多个桶（IP × UA 组合），超过后合并到溢出桶
    const BUCKETS_PER_HOUR_LIMIT = 30;
    // UA 字典每个 UA 在这个窗口内只写一次（更新 last_seen）
    const UA_SEEN_SECONDS = 86400;
    // 健康探测状态不变时，每隔这么久补记一行
    const HEALTH_HEARTBEAT_SECONDS = 3600;
    // 清理时每批删除的行数
    const CLEANUP_BATCH = 5000;
    // 评分：最近 1 小时订阅次数 > 20 记 25 分，来源 IP 数 > 8 记 25 分，最高 50 分
    const SCORE_WINDOW_SECONDS = 3600;
    const SCORE_PULLS_THRESHOLD = 20;
    const SCORE_IPS_THRESHOLD = 8;
    const SCORE_POINTS = 25;
    // 设置默认值（与 ConfigController::fetch、前端 GuardSettings 一致）；高风险阈值 50 与「需人工复核」一致
    const DEFAULT_RISK_THRESHOLD = 50;
    const DEFAULT_RETENTION_DAYS = 3;
    const DEFAULT_HEALTH_TIMEOUT = 2;
    const DEFAULT_ALERT_COOLDOWN_MINUTES = 120;
    // 自动生成的假入口 IPv4 的首段范围：240～254（IANA 保留，全网不可路由，外观与公网 IP 无异）
    const DECOY_FIRST_OCTET_MIN = 240;
    const DECOY_FIRST_OCTET_MAX = 254;
    // 假入口要替换的字段名（不分大小写）：连接地址，以及 SNI / Host 头 / obfs host 这类能反查真实服务器的字段
    const DECOY_FIELDS = ['host', 'server', 'address', 'server_name', 'servername', 'sni', 'obfs-host', 'obfs_host'];
    // 被限制用户的 ID 集合整体缓存（限制表很小），限制 / 解除后主动清
    const RESTRICT_CACHE_KEY = 'insider_guard_restricted_ids';
    const RESTRICT_CACHE_SECONDS = 300;
    // 日志限频：同一类错误 5 分钟一条
    const LOG_THROTTLE_SECONDS = 300;
    // 节点类型 => 模型，只用来查名称
    const NODE_MODELS = [
        'shadowsocks' => ServerShadowsocks::class,
        'vmess' => ServerVmess::class,
        'trojan' => ServerTrojan::class,
        'tuic' => ServerTuic::class,
        'hysteria' => ServerHysteria::class,
        'vless' => ServerVless::class,
        'anytls' => ServerAnytls::class,
        'v2node' => ServerV2node::class,
    ];

    /** 缓存不可用时的进程内日志限频（webman 每个 worker 一份） */
    private static $lastLogAt = [];

    public static function setting(string $key, $default = null)
    {
        return config('v2board.insider_guard_' . $key, $default);
    }

    /** 登录成功：记录来源 IP 与 UA */
    public static function recordLogin(User $user, Request $request): void
    {
        self::record(self::EVENT_LOGIN, (int)$user->id, $request, null);
    }

    /** 拉取订阅：记录活动，并记录「向该用户下发过哪些节点」；下发的是假入口时不算下发过 */
    public static function recordSubscribe(User $user, Request $request, array $servers, bool $decoy = false): void
    {
        self::record(self::EVENT_SUBSCRIPTION, (int)$user->id, $request, count($servers));
        if (!$decoy) self::deliveries((int)$user->id, $servers);
    }

    /** 用户是否被限制；缓存或查询失败按未限制处理，不影响订阅 */
    public static function isRestricted(int $userId): bool
    {
        try {
            $ids = Cache::remember(self::RESTRICT_CACHE_KEY, self::RESTRICT_CACHE_SECONDS, function () {
                return array_map('intval', DB::table('v2_insider_guard_restrict')->pluck('user_id')->all());
            });
            return is_array($ids) && in_array($userId, $ids, true);
        } catch (\Throwable $e) {
            self::logWriteError('InsiderGuard restrict lookup unavailable', $e);
            return false;
        }
    }

    /** 限制：记入限制表（已限制则只更新原因，保留首次限制时间）；调用方提交事务后要再调 refreshRestricted */
    public static function restrict(int $userId, int $adminId, string $reason): void
    {
        DB::table('v2_insider_guard_restrict')->upsert(
            [['user_id' => $userId, 'admin_id' => $adminId, 'reason' => $reason, 'created_at' => time()]],
            ['user_id'],
            ['admin_id', 'reason']
        );
    }

    public static function release(int $userId): void
    {
        DB::table('v2_insider_guard_restrict')->where('user_id', $userId)->delete();
    }

    /** 清掉限制集合缓存，让下一次拉订阅就生效；必须在事务提交之后调用，否则并发的订阅请求会把旧集合重新缓存 */
    public static function refreshRestricted(): void
    {
        Cache::forget(self::RESTRICT_CACHE_KEY);
    }

    /**
     * 假入口地址：设置里填了就用（自己的蜜罐域名或 IP）；留空则按用户生成一个固定的假 IPv4，
     * 由用户 ID 和 APP_KEY 派生，同一用户每次拉到的都一样，不同用户不同，外人推不出来
     */
    public static function decoyHost(int $userId): string
    {
        // 配置里的 IPv6 允许带方括号，这里去掉；URI 类输出由 Helper::formatHost 补括号，QuantumultX / Surge / Loon 等行式输出不补，
        // 所以假入口建议填 IPv4 或域名
        $host = trim(trim((string)self::setting('decoy_host', '')), '[]');
        if ($host !== '') return $host;
        $hash = md5('insider_guard_decoy:' . $userId . ':' . config('app.key'));
        $octet = function (int $index, int $min, int $max) use ($hash) {
            return $min + hexdec(substr($hash, $index * 2, 2)) % ($max - $min + 1);
        };
        return $octet(0, self::DECOY_FIRST_OCTET_MIN, self::DECOY_FIRST_OCTET_MAX)
            . '.' . $octet(1, 1, 254) . '.' . $octet(2, 1, 254) . '.' . $octet(3, 1, 254);
    }

    /**
     * 假入口：节点列表照常，端口、凭据都不动，只换地址类字段（节点名只在与地址相同时替换）。
     * 连接地址（host / server / address）与 SNI、Host 头、obfs host 一律换成假地址：这些字段指向真实服务器时解析即得真实 IP，
     * 换掉没有副作用（假地址本来就连不上）；其它字符串只在与原地址相同时替换
     */
    public static function applyDecoy(array &$servers, int $userId): void
    {
        $decoy = self::decoyHost($userId);
        $renamed = 0;
        foreach ($servers as &$server) {
            $originals = [];
            foreach (['host', 'server', 'address'] as $field) {
                $value = strtolower(trim((string)($server[$field] ?? '')));
                if ($value !== '') $originals[$value] = true;
            }
            // 节点名恰好就是地址时也要换掉；多个节点都这样时加序号，避免客户端因 proxy 重名拒绝整份配置
            $name = (string)($server['name'] ?? '');
            if ($name !== '' && isset($originals[strtolower(trim($name))])) {
                $renamed++;
                $server['name'] = $decoy . ($renamed > 1 ? " {$renamed}" : '');
            }
            self::replaceHostDeep($server, $originals, $decoy, true);
        }
        unset($server);
    }

    /** $force：上层键名已命中 DECOY_FIELDS（例如 tcp + http 伪装把 Host 存成列表），里面的字符串一律替换 */
    private static function replaceHostDeep(array &$data, array $originals, string $decoy, bool $top = false, bool $force = false): void
    {
        foreach ($data as $key => &$value) {
            $field = is_string($key) ? strtolower($key) : '';
            $hit = $force || in_array($field, self::DECOY_FIELDS, true);
            if (is_array($value)) {
                self::replaceHostDeep($value, $originals, $decoy, false, $hit);
                continue;
            }
            // 空字符串不动（没配 SNI 就别凭空加一个）；顶层 name 是节点名，在 applyDecoy 里单独处理
            if (!is_string($value) || $value === '' || ($top && $key === 'name')) continue;
            if ($hit || isset($originals[strtolower(trim($value))])) {
                $value = $decoy;
            }
        }
        unset($value);
    }

    /** 按小时合并写入活动表：同一桶已存在时次数 +1、更新 last_at 与节点数 */
    private static function record(string $type, int $userId, Request $request, ?int $nodeCount): void
    {
        try {
            $now = time();
            $hourStart = $now - $now % self::BUCKET_SECONDS;
            // 去掉非法 UTF-8，否则 utf8mb4 列会拒绝写入
            $ua = mb_substr(mb_convert_encoding((string)($request->userAgent() ?? ''), 'UTF-8', 'UTF-8'), 0, 512);
            $ip = substr((string)$request->ip(), 0, 45);
            $uaHash = $ua === '' ? '' : md5($ua);
            // 同一小时内桶数超限（随机 UA / 伪造 IP 刷表）：后续记录并入该小时的溢出桶，只计数不再建新行、不写字典
            $buckets = DB::table('v2_insider_guard_activity')
                ->where('user_id', $userId)->where('last_at', '>=', $hourStart)->count();
            if ($buckets >= self::BUCKETS_PER_HOUR_LIMIT) {
                $ip = '';
                $uaHash = '';
            } elseif ($uaHash !== '') {
                self::rememberUa($uaHash, $ua, $now);
            }
            DB::table('v2_insider_guard_activity')->upsert([[
                'user_id' => $userId,
                'event_type' => $type,
                'hour_start' => $hourStart,
                'ip_address' => $ip,
                'ua_hash' => $uaHash,
                'times' => 1,
                'node_count' => $nodeCount,
                'first_at' => $now,
                'last_at' => $now,
            ]], ['user_id', 'event_type', 'hour_start', 'ip_address', 'ua_hash'], [
                'times' => DB::raw('times + 1'),
                'last_at',
                'node_count',
            ]);
        } catch (\Throwable $e) {
            self::logWriteError('InsiderGuard audit unavailable', $e);
        }
    }

    /** UA 字典：同一个 UA 一天只写一次；缓存或写入失败只记日志（活动行照常写，带哈希），下次再试 */
    private static function rememberUa(string $hash, string $ua, int $now): void
    {
        $key = 'insider_guard_ua:' . $hash;
        try {
            if (!Cache::add($key, 1, self::UA_SEEN_SECONDS)) return;
            DB::table('v2_insider_guard_ua')->upsert(
                [['ua_hash' => $hash, 'ua' => $ua, 'first_seen' => $now, 'last_seen' => $now]],
                ['ua_hash'],
                ['last_seen']
            );
        } catch (\Throwable $e) {
            self::forgetQuietly($key);
            self::logWriteError('InsiderGuard ua dictionary unavailable', $e);
        }
    }

    /** 清缓存键；缓存不可用时也不能再抛（调用方都在 catch 里） */
    private static function forgetQuietly(string $key): void
    {
        try {
            Cache::forget($key);
        } catch (\Throwable $ignore) {
        }
    }

    /** 每人每节点一行：已有时次数 +1、更新 last_at，总行数封顶为用户数 × 节点数 */
    private static function deliveries(int $userId, array $servers): void
    {
        $dedupKey = null;
        try {
            $rows = [];
            $keys = [];
            $now = time();
            foreach ($servers as $server) {
                $id = $server['id'] ?? null;
                $type = (string)($server['type'] ?? '');
                if (!is_numeric($id) || (int)$id < 1 || $type === '') continue;
                $keys[] = $type . ':' . (int)$id;
                $rows[] = [
                    'user_id' => $userId,
                    'node_type' => substr($type, 0, 40),
                    'node_id' => (int)$id,
                    'times' => 1,
                    'first_at' => $now,
                    'last_at' => $now,
                ];
            }
            if (!$rows) return;
            // 客户端每小时自动更新订阅，节点集合没变时不重复写库；集合一变（加节点、换套餐）立刻记一次
            sort($keys);
            $dedupKey = 'insider_guard_delivery:' . $userId . ':' . md5(implode(',', $keys));
            if (!Cache::add($dedupKey, 1, self::DELIVERY_DEDUP_SECONDS)) return;
            foreach (array_chunk($rows, 200) as $batch) {
                DB::table('v2_insider_guard_node_user')->upsert($batch, ['user_id', 'node_type', 'node_id'], [
                    'times' => DB::raw('times + 1'),
                    'last_at',
                ]);
            }
        } catch (\Throwable $e) {
            // 写失败要撤掉去重键，否则 6 小时内不会再记，候选账号 / 时间线会漏掉这个人
            if ($dedupKey) self::forgetQuietly($dedupKey);
            self::logWriteError('InsiderGuard delivery audit unavailable', $e);
        }
    }

    /**
     * 写入失败只记底层错误，去掉引号里的片段（Duplicate entry '…' 之类会带 IP / UA），同一类错误 5 分钟内只记一次；
     * 缓存不可用时退回进程内限频，避免每个请求都写日志
     */
    private static function logWriteError(string $message, \Throwable $e): void
    {
        $error = $e instanceof QueryException && $e->getPrevious() ? $e->getPrevious()->getMessage() : $e->getMessage();
        $error = preg_replace("/'[^']*'/", "'…'", $error);
        try {
            if (!Cache::add('insider_guard_write_error:' . md5($message), 1, self::LOG_THROTTLE_SECONDS)) return;
        } catch (\Throwable $ignore) {
            if ((self::$lastLogAt[$message] ?? 0) > time() - self::LOG_THROTTLE_SECONDS) return;
            self::$lastLogAt[$message] = time();
        }
        Log::warning($message, ['error' => $error]);
    }

    /**
     * 风险评分（最近 1 小时）：达到高风险阈值即需人工复核。
     * 活动按小时合并，这里取最近 1 小时内有活动的桶，桶内更早的记录也会算进来（最多多算一个小时）
     */
    public static function score(int $userId): array
    {
        $since = time() - self::SCORE_WINDOW_SECONDS;
        $rows = DB::table('v2_insider_guard_activity')->where('user_id', $userId)->where('last_at', '>=', $since);
        $pulls = (int)(clone $rows)->where('event_type', self::EVENT_SUBSCRIPTION)->sum('times');
        // 溢出桶的 ip_address 为空，不算一个 IP
        $ips = (clone $rows)->where('ip_address', '<>', '')->distinct()->count('ip_address');
        $score = self::calcScore($pulls, $ips);
        $threshold = (int)self::setting('risk_threshold', self::DEFAULT_RISK_THRESHOLD);
        return [
            'score' => $score,
            'subscription_requests_1h' => $pulls,
            'distinct_ips_1h' => $ips,
            'manual_review_required' => $score >= $threshold,
        ];
    }

    public static function calcScore(int $pulls, int $ips): int
    {
        return min(100, ($pulls > self::SCORE_PULLS_THRESHOLD ? self::SCORE_POINTS : 0)
            + ($ips > self::SCORE_IPS_THRESHOLD ? self::SCORE_POINTS : 0));
    }

    /** 告警（同一事件在冷却时间内只发一次），通过 Telegram 发给绑定了 Telegram 的管理员 */
    public static function alert(string $message, string $key): void
    {
        $minutes = max(10, (int)self::setting('alert_cooldown_minutes', self::DEFAULT_ALERT_COOLDOWN_MINUTES));
        try {
            // 缓存不可用时当作冷却中，不发也不抛（调用方正在探测，不能因此把节点记成 error）
            if (!Cache::add('insider_guard_alert:' . hash('sha256', $key), 1, $minutes * 60)) return;
            (new TelegramService())->sendMessageWithAdmin($message);
        } catch (\Throwable $e) {
            Log::warning('InsiderGuard alert failed', ['error' => $e->getMessage()]);
        }
    }

    /** 全部节点的 "type:id" => 名称 映射；只查 id、name，不走 ServerService 的流量 / 状态合并 */
    public static function nodeNames(): array
    {
        $names = [];
        foreach (self::NODE_MODELS as $type => $class) {
            foreach ($class::query()->get(['id', 'name']) as $row) {
                $names[$type . ':' . $row->id] = (string)$row->name;
            }
        }
        return $names;
    }

    /**
     * 探测一个节点的 TCP 连通性并记录（只记状态变化，状态不变时每小时补记一行）；
     * $alert 为真时连续两次失败告警（定时任务用；后台手动检测不告警）
     */
    public static function healthOne(string $type, int $id, ?array $server = null, bool $alert = true): array
    {
        $result = ['node_type' => $type, 'node_id' => $id];
        if (!self::setting('health_enable', 0)) {
            return $result + ['status' => 'disabled', 'message' => '请先在风控中心设置里开启节点健康检查'];
        }
        if ($server === null) {
            $model = (new ServerService())->getServer($id, $type);
            if (!$model) return $result + ['status' => 'error', 'message' => '节点不存在'];
            $server = $model->toArray();
            $server['type'] = $type;
        }
        $result['name'] = (string)($server['name'] ?? '');
        if (in_array($type, self::UDP_TYPES, true)
            || ($type === 'v2node' && in_array(strtolower((string)($server['protocol'] ?? '')), self::UDP_PROTOCOLS, true))) {
            return $result + ['status' => 'skipped', 'message' => 'UDP/QUIC 节点不支持 TCP 探测'];
        }
        // IPv6 可能带方括号，校验前去掉，拼目标地址时再补
        $host = trim(trim((string)($server['host'] ?? '')), '[]');
        $portRaw = (string)(!empty($server['port']) ? $server['port'] : ($server['server_port'] ?? ''));
        if ($host === '' || preg_match('/[\s\/\?#@]/', $host)
            || (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME))) {
            return $result + ['status' => 'skipped', 'message' => '节点地址不是可探测的单一域名或 IP'];
        }
        if (!preg_match('/^\d+$/', $portRaw) || (int)$portRaw < 1 || (int)$portRaw > 65535) {
            return $result + ['status' => 'skipped', 'message' => '节点端口无效或为端口范围'];
        }
        $port = (int)$portRaw;
        $timeout = max(1, min(5, (int)self::setting('health_timeout', self::DEFAULT_HEALTH_TIMEOUT)));
        $target = 'tcp://' . (strpos($host, ':') !== false ? '[' . $host . ']' : $host) . ':' . $port;
        $start = microtime(true);
        $errno = 0;
        $err = '';
        $fp = @stream_socket_client($target, $errno, $err, $timeout, STREAM_CLIENT_CONNECT);
        $status = $fp ? 'up' : 'down';
        if ($fp) fclose($fp);
        $latency = (int)round((microtime(true) - $start) * 1000);
        // 系统错误文本可能不是 UTF-8，写库与返回 JSON 都要先清洗
        $error = $fp ? null : mb_substr(mb_convert_encoding((string)$err, 'UTF-8', 'UTF-8'), 0, 180);
        $prior = DB::table('v2_insider_guard_health')
            ->where('node_type', $type)->where('node_id', $id)
            ->orderByDesc('created_at')->orderByDesc('id')->first(['status', 'created_at']);
        if (!$prior || $prior->status !== $status || (int)$prior->created_at < time() - self::HEALTH_HEARTBEAT_SECONDS) {
            DB::table('v2_insider_guard_health')->insert([
                'node_id' => $id,
                'node_type' => $type,
                'status' => $status,
                'latency_ms' => $latency,
                'error' => $error,
                'created_at' => time(),
            ]);
        }
        if ($alert && $status === 'down' && $prior && $prior->status === 'down') {
            self::alert(
                "InsiderGuard：节点 TCP 连续探测失败 [{$type}#{$id}] {$result['name']} {$host}:{$port}",
                "health-{$type}-{$id}"
            );
        }
        return $result + ['status' => $status, 'latency_ms' => $latency, 'error' => $error];
    }

    /** 探测全部显示中的节点 */
    public static function health(): array
    {
        if (!self::setting('health_enable', 0)) {
            return ['disabled' => true, 'message' => '请先在风控中心设置里开启节点健康检查'];
        }
        $results = [];
        foreach ((new ServerService())->getAllServers() as $server) {
            if (empty($server['show'])) continue;
            $type = (string)$server['type'];
            $id = (int)$server['id'];
            try {
                $results[] = self::healthOne($type, $id, $server);
            } catch (QueryException $e) {
                // 表不存在之类的数据库错误不是单个节点的问题，交给命令层提示
                throw $e;
            } catch (\Throwable $e) {
                Log::warning('InsiderGuard node probe failed', ['node' => "{$type}:{$id}", 'error' => $e->getMessage()]);
                $results[] = ['node_type' => $type, 'node_id' => $id, 'status' => 'error', 'message' => '检查发生异常，请查看 Laravel 日志'];
            }
            if (count($results) >= 1000) break;
        }
        return ['checked' => count($results), 'results' => $results];
    }

    /** 清理过期的活动 / 节点下发 / 健康 / UA 字典记录（保留 1～365 天）与已删除用户的限制记录，由定时任务每小时调用 */
    public static function cleanup(): array
    {
        $days = max(1, min(365, (int)self::setting('retention_days', self::DEFAULT_RETENTION_DAYS)));
        $cutoff = time() - $days * 86400;
        $targets = [
            'v2_insider_guard_activity' => ['last_at', $cutoff, 'id'],
            'v2_insider_guard_node_user' => ['last_at', $cutoff, 'id'],
            'v2_insider_guard_health' => ['created_at', $cutoff, 'id'],
            // UA 的 last_seen 最多比引用它的活动晚一天更新，多留一天，避免还在保留期内的活动查不到 UA
            'v2_insider_guard_ua' => ['last_seen', $cutoff - self::UA_SEEN_SECONDS, 'ua_hash'],
        ];
        $counts = [];
        // 用户删除时限制表没有联动，顺带清掉已不存在用户的限制记录
        $counts['v2_insider_guard_restrict'] = DB::table('v2_insider_guard_restrict')
            ->whereNotIn('user_id', User::query()->select('id'))->delete();
        if ($counts['v2_insider_guard_restrict'] > 0) self::forgetQuietly(self::RESTRICT_CACHE_KEY);
        foreach ($targets as $table => [$column, $before, $orderBy]) {
            // 分批删，避免一条大 DELETE 长时间持锁；带 ORDER BY 让语句级 binlog 不报 unsafe
            $counts[$table] = 0;
            do {
                $deleted = DB::table($table)->where($column, '<', $before)->orderBy($orderBy)->limit(self::CLEANUP_BATCH)->delete();
                $counts[$table] += $deleted;
            } while ($deleted > 0);
        }
        return $counts;
    }
}
