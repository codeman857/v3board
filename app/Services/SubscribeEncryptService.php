<?php

namespace App\Services;

use Symfony\Component\HttpFoundation\Response;

class SubscribeEncryptService
{
    public static function resolveIv(string $requestIv): string
    {
        $requestIv = trim($requestIv);
        if ($requestIv !== '') return $requestIv;
        return trim((string)config('v2board.subscribe_encrypt_iv', ''));
    }

    public static function shouldEncrypt($user, string $userAgent, string $requestIv): bool
    {
        if (!(int)config('v2board.subscribe_encrypt_enable', 0)) return false;

        $key = trim((string)config('v2board.subscribe_encrypt_key', ''));
        if ($key === '' || self::resolveIv($requestIv) === '') return false;

        $uaKeywords = self::parseList((string)config('v2board.subscribe_encrypt_ua', ''));
        if (!empty($uaKeywords)) {
            if ($userAgent === '') return false;
            $hit = false;
            foreach ($uaKeywords as $keyword) {
                if (stripos($userAgent, $keyword) !== false) {
                    $hit = true;
                    break;
                }
            }
            if (!$hit) return false;
        }

        $rawPlanIds = trim((string)config('v2board.subscribe_encrypt_plan_ids', ''));
        if ($rawPlanIds !== '') {
            $planIds = self::parsePlanIds($rawPlanIds);
            // 配置了内容却解析不出有效 ID（分隔符写错等）时不加密，避免误扩大到全部套餐
            if (empty($planIds)) return false;
            $planId = isset($user['plan_id']) ? (int)$user['plan_id'] : 0;
            if (!in_array($planId, $planIds, true)) return false;
        }

        return true;
    }

    public static function encrypt(string $plaintext, string $iv): string
    {
        $key = trim((string)config('v2board.subscribe_encrypt_key', ''));

        if (strlen($key) >= 32) {
            $cipher = 'aes-256-cbc';
            $keyBytes = substr($key, 0, 32);
        } else {
            $cipher = 'aes-128-cbc';
            $keyBytes = substr(str_pad($key, 16, "\0"), 0, 16);
        }
        $ivBytes = substr(str_pad(self::resolveIv($iv), 16, "\0"), 0, 16);

        $encrypted = openssl_encrypt($plaintext, $cipher, $keyBytes, 0, $ivBytes);
        if ($encrypted === false) {
            abort(500, '订阅处理失败');
        }
        return $encrypted;
    }

    public static function encryptResponse($response, $user, string $userAgent, string $requestIv)
    {
        if ($response === null) return $response;
        if (!self::shouldEncrypt($user, $userAgent, $requestIv)) return $response;

        if ($response instanceof Response) {
            if ($response->getStatusCode() !== 200) return $response;
            $content = (string)$response->getContent();
            if ($content === '') return $response;
            $response->setContent(self::encrypt($content, $requestIv));
            $response->headers->set('Content-Type', 'text/plain; charset=utf-8');
            $response->headers->set('X-Encrypted', '1');
            $response->headers->set('X-Content-Sha', self::contentSha($content));
            $response->headers->set('Vary', 'User-Agent, X-IV');
            return $response;
        }

        if (is_string($response) && $response !== '') {
            return response(self::encrypt($response, $requestIv), 200, [
                'Content-Type' => 'text/plain; charset=utf-8',
                'X-Encrypted' => '1',
                'X-Content-Sha' => self::contentSha($response),
                'Vary' => 'User-Agent, X-IV'
            ]);
        }

        return $response;
    }

    /**
     * 明文摘要，供客户端校验解密结果是否正确（CBC 本身无完整性保护）。
     */
    private static function contentSha(string $plaintext): string
    {
        return substr(hash('sha256', $plaintext), 0, 16);
    }

    /**
     * 套餐 ID 列表：兼容逗号、分号、顿号、空格、换行等常见分隔符，仅保留纯数字项。
     */
    private static function parsePlanIds(string $raw): array
    {
        // 仅按分隔符切分，每项必须是纯数字；出现 1-3、10.5 等无法确定含义的写法时
        // 该项整体丢弃，由调用方按"配置了却解析不出有效 ID"处理，避免猜错范围
        $items = preg_split('/[\s,;、，；]+/u', $raw);
        $ids = [];
        foreach ($items as $item) {
            $item = trim($item);
            if ($item === '' || !ctype_digit($item)) continue;
            $ids[] = (int)$item;
        }
        return array_values(array_unique($ids));
    }

    private static function parseList(string $raw): array
    {
        if (trim($raw) === '') return [];
        $items = preg_split('/[\n\r,，]+/u', $raw);
        $items = array_map('trim', $items);
        $items = array_filter($items, function ($item) {
            return $item !== '';
        });
        return array_values(array_unique($items));
    }
}
