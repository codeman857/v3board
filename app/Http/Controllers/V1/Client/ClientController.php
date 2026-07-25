<?php

namespace App\Http\Controllers\V1\Client;

use App\Http\Controllers\Controller;
use App\Protocols\General;
use App\Protocols\NextinEncrypted;
use App\Protocols\Singbox\Singbox;
use App\Protocols\Singbox\SingboxOld;
use App\Protocols\ClashMeta;
use App\Services\ServerService;
use App\Services\SubscribeEncryptService;
use App\Services\UserService;
use App\Utils\Helper;
use Illuminate\Http\Request;

class ClientController extends Controller
{
    // 标记本次响应是否已由 NextinEncrypted 通道处理，避免叠加订阅加密
    private $nextinHandled = false;

    public function subscribe(Request $request)
    {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $response = $this->buildSubscribe($request, $userAgent);
        if ($this->nextinHandled) {
            return $response;
        }
        return SubscribeEncryptService::encryptResponse($response, $request->user, $userAgent, (string)$request->header('X-IV', ''));
    }

    private function buildSubscribe(Request $request, $userAgent)
    {
        $flag = $request->input('flag') ?? $userAgent;
        $flag = strtolower($flag);
        $user = $request->user;
        // account not expired and is not banned.
        $userService = new UserService();
        if ($userService->isAvailable($user)) {
            $serverService = new ServerService();
            $servers = $serverService->getAvailableServers($user);
            $this->applyDomainRewriteRules($servers, $flag);
            $this->applyNodeWhitelistRules($servers, $flag);
            if($flag) {
                $nextinEncrypted = new NextinEncrypted($user, $servers);
                $shouldBlockNextinSubscription =
                    NextinEncrypted::shouldBlockSubscriptionForUserAgent($userAgent);
                $shouldReturnEncryptedClashMeta =
                    NextinEncrypted::shouldEncryptForUserAgent($userAgent)
                    || strpos($flag, $nextinEncrypted->flag) !== false;

                if ($shouldBlockNextinSubscription) {
                    return response('', 403);
                }

                if ($shouldReturnEncryptedClashMeta || !strpos($flag, 'sing')) {
                    $this->setSubscribeInfoToServers($servers, $user);
                    $nextinEncrypted = new NextinEncrypted($user, $servers);
                }

                if ($shouldReturnEncryptedClashMeta) {
                    $this->nextinHandled = true;
                    return $nextinEncrypted->handle();
                }

                if (!strpos($flag, 'sing')) {
                    foreach (array_reverse(glob(app_path('Protocols') . '/*.php')) as $file) {
                        $file = 'App\\Protocols\\' . basename($file, '.php');
                        $class = new $file($user, $servers);
                        if (strpos($flag, $class->flag) !== false) {
                            return $class->handle();
                        }
                    }
                }
                if (strpos($flag, 'sing') !== false) {
                    $version = null;
                    if (preg_match('/sing-box\s+([0-9.]+)/i', $flag, $matches)) {
                        $version = $matches[1];
                    }
                    if (!is_null($version) && $version >= '1.12.0') {
                        $class = new Singbox($user, $servers);
                    } else {
                        $class = new SingboxOld($user, $servers);
                    }
                    return $class->handle();
                }
            }
            $class = new General($user, $servers);
            return $class->handle();
        }
    }

    private function applyDomainRewriteRules(&$servers, $ua)
    {
        $rules = config('v2board.subscribe_domain_rewrite_rules', []);
        if (empty($rules) || empty($ua)) return;

        $matchedRules = [];
        foreach ($rules as $rule) {
            if (empty($rule['ua']) || empty($rule['domain']) || empty($rule['ip'])) continue;
            if (stripos($ua, $rule['ua']) !== false) {
                $matchedRules[] = $rule;
            }
        }
        if (empty($matchedRules)) return;

        $addressFields = ['host', 'server', 'address'];
        foreach ($servers as &$server) {
            foreach ($matchedRules as $rule) {
                foreach ($addressFields as $field) {
                    if (isset($server[$field]) && strtolower($server[$field]) === strtolower($rule['domain'])) {
                        $server[$field] = $rule['ip'];
                    }
                }
            }
        }
        unset($server);
    }

    private function applyNodeWhitelistRules(&$servers, $ua)
    {
        $rules = config('v2board.subscribe_node_whitelist_rules', []);
        if (empty($rules) || !is_array($rules)) return;

        // Build map: "type:id" => [allowed UA keyword, ...]
        $restricted = [];
        foreach ($rules as $rule) {
            if (!is_array($rule)) continue;
            $ruleUa = isset($rule['ua']) ? trim((string)$rule['ua']) : '';
            if ($ruleUa === '') continue;
            if (empty($rule['nodes']) || !is_array($rule['nodes'])) continue;
            foreach ($rule['nodes'] as $node) {
                if (!is_array($node) || empty($node['type']) || !isset($node['id'])) continue;
                $key = $node['type'] . ':' . (int)$node['id'];
                $restricted[$key][] = $ruleUa;
            }
        }
        if (empty($restricted)) return;

        $servers = array_values(array_filter($servers, function ($server) use ($restricted, $ua) {
            $key = ($server['type'] ?? '') . ':' . (isset($server['id']) ? (int)$server['id'] : '');
            if (!isset($restricted[$key])) {
                return true;
            }
            if (empty($ua)) {
                return false;
            }
            foreach ($restricted[$key] as $allowedUa) {
                if ($allowedUa === '') continue;
                if (stripos($ua, $allowedUa) !== false) {
                    return true;
                }
            }
            return false;
        }));
    }

    private function setSubscribeInfoToServers(&$servers, $user)
    {
        if (!isset($servers[0])) return;
        if (!(int)config('v2board.show_info_to_server_enable', 0)) return;
        $useTraffic = $user['u'] + $user['d'];
        $totalTraffic = $user['transfer_enable'];
        $remainingTraffic = Helper::trafficConvert($totalTraffic - $useTraffic);
        $expiredDate = $user['expired_at'] ? date('Y-m-d', $user['expired_at']) : '长期有效';
        $userService = new UserService();
        $resetDay = $userService->getResetDay($user);
        array_unshift($servers, array_merge($servers[0], [
            'name' => "套餐到期：{$expiredDate}",
        ]));
        if ($resetDay) {
            array_unshift($servers, array_merge($servers[0], [
                'name' => "距离下次重置剩余：{$resetDay} 天",
            ]));
        }
        array_unshift($servers, array_merge($servers[0], [
            'name' => "剩余流量：{$remainingTraffic}",
        ]));
    }
}
