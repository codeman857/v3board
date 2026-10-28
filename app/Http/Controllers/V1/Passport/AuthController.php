<?php

namespace App\Http\Controllers\V1\Passport;

use App\Http\Controllers\Controller;
use App\Http\Requests\Passport\AuthForget;
use App\Http\Requests\Passport\AuthLogin;
use App\Http\Requests\Passport\AuthRegister;
use App\Http\Requests\Passport\AuthChangeEmail; // 新增：引入 AuthChangeEmail Request 类
use App\Jobs\SendEmailJob;
use App\Models\InviteCode;
use App\Models\Plan;
use App\Models\User;
use App\Services\AuthService;
use App\Services\InsiderGuardService;
use App\Services\TelegramService;
use App\Utils\CacheKey;
use App\Utils\Dict;
use App\Utils\Helper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use ReCaptcha\ReCaptcha;

class AuthController extends Controller
{
    private function debugLog($message, $data = [])
    {
        // 只有在 APP_DEBUG 为 true 时才生成日志
        if (!config('app.debug')) {
            return;
        }

        $log_prefix = "[" . date('Y-m-d H:i:s') . "] [changeEmail] ";
        $log_message = $log_prefix . $message;
        if (!empty($data)) {
            $log_message .= " | Data: " . json_encode($data, JSON_UNESCAPED_UNICODE);
        }
        $log_message .= PHP_EOL;

        // 确保日志目录存在
        $logDir = storage_path('logs');
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        error_log($log_message, 3, storage_path('logs/debug.log'));
        flush();
    }

    /**
     * Telegram MarkdownV2 安全转义（保留 `...` 和 ```...``` 中的原文，仅转义其中的 \ 和 `）
     */
    private function escapeMarkdownV2PreservingCode(string $text): string
    {
        // 拆分为：代码段（```...``` 或 `...`） 与 非代码段
        $pattern = '/(```[\s\S]*?```|`[^`]*`)/m';
        $parts = preg_split($pattern, $text, -1, PREG_SPLIT_DELIM_CAPTURE);

        if ($parts === false) {
            // 回退：极端情况下直接做全局转义
            return $this->escapeAllMarkdownV2($text);
        }

        $out = '';
        foreach ($parts as $part) {
            if ($part === '') {
                continue;
            }

            // 命中代码块 ```...```
            if (substr($part, 0, 3) === '```' && substr($part, -3) === '```') {
                // 去掉围栏
                $inner = substr($part, 3, -3);

                // 支持可选语言前缀（第一行）
                $nlPos = strpos($inner, "\n");
                if ($nlPos !== false) {
                    $lang = substr($inner, 0, $nlPos);
                    $code = substr($inner, $nlPos + 1);
                    // 代码里仅转义 \ 和 `
                    $code = str_replace(['\\', '`'], ['\\\\', '\`'], $code);
                    $part = "```{$lang}\n{$code}```";
                } else {
                    $code = str_replace(['\\', '`'], ['\\\\', '\`'], $inner);
                    $part = "```{$code}```";
                }
                $out .= $part;
                continue;
            }

            // 命中行内代码 `...`
            if ($part[0] === '`' && substr($part, -1) === '`') {
                $code = substr($part, 1, -1);
                $code = str_replace(['\\', '`'], ['\\\\', '\`'], $code); // 只转义 \ 和 `
                $out .= '`' . $code . '`';
                continue;
            }

            // 非代码段：完整 MarkdownV2 转义
            $out .= $this->escapeAllMarkdownV2($part);
        }

        return $out;
    }

    /**
     * MarkdownV2 全字符转义（非代码段）
     * 保留 * 和 _ 以支持粗体/斜体
     */
    private function escapeAllMarkdownV2(string $text): string
    {
        // 根据官方文档： _ * [ ] ( ) ~ ` > # + - = | { } . !
        // 我们这里保留 _ 和 * 不转义
        $special = ['[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'];
        $repl = array_map(function ($c) {
            return '\\' . $c;
        }, $special);
        return str_replace($special, $repl, $text);
    }

    /**
     * 统一出口：发送前自动转义并使用 MarkdownV2
     */
    private function sendTelegramMessage(int $chatId, string $text, string $parseMode = '')
    {
        try {
            // 只要调用方传了 markdown / markdownv2，就自动做安全转义并统一为 MarkdownV2
            $mode = strtolower($parseMode);
            if ($mode === 'markdown' || $mode === 'markdownv2') {
                $text = $this->escapeMarkdownV2PreservingCode($text);
                $parseMode = 'MarkdownV2';
            }

            $telegramService = new TelegramService();
            $telegramService->sendMessage($chatId, $text, $parseMode);
        } catch (\Exception $e) {
            \Log::error("Failed to send Telegram message: " . $e->getMessage());
        }
    }
    public function loginWithMailLink(Request $request)
    {
        if (!(int) config('v2board.login_with_mail_link_enable')) {
            abort(404);
        }
        $params = $request->validate([
            'email' => 'required|email:strict',
            'redirect' => 'nullable'
        ]);

        if (Cache::get(CacheKey::get('LAST_SEND_LOGIN_WITH_MAIL_LINK_TIMESTAMP', $params['email']))) {
            abort(500, __('Sending frequently, please try again later'));
        }

        $user = User::where('email', $params['email'])->first();
        if (!$user) {
            return response([
                'data' => true
            ]);
        }

        $code = Helper::guid();
        $key = CacheKey::get('TEMP_TOKEN', $code);
        Cache::put($key, $user->id, 300);
        Cache::put(CacheKey::get('LAST_SEND_LOGIN_WITH_MAIL_LINK_TIMESTAMP', $params['email']), time(), 60);


        $redirect = '/#/login?verify=' . $code . '&redirect=' . ($request->input('redirect') ? $request->input('redirect') : 'dashboard');
        if (config('v2board.app_url')) {
            $link = config('v2board.app_url') . $redirect;
        } else {
            $link = url($redirect);
        }

        SendEmailJob::dispatch([
            'email' => $user->email,
            'subject' => __('Login to :name', [
                'name' => config('v2board.app_name', 'V2Board')
            ]),
            'template_name' => 'login',
            'template_value' => [
                'name' => config('v2board.app_name', 'V2Board'),
                'link' => $link,
                'url' => config('v2board.app_url')
            ]
        ]);

        return response([
            'data' => true
        ]);

    }

    public function register(AuthRegister $request)
    {
        if ((int) config('v2board.register_limit_by_ip_enable', 0)) {
            $registerCountByIP = Cache::get(CacheKey::get('REGISTER_IP_RATE_LIMIT', $request->ip())) ?? 0;
            if ((int) $registerCountByIP >= (int) config('v2board.register_limit_count', 3)) {
                abort(500, __('Register frequently, please try again after :minute minute', [
                    'minute' => config('v2board.register_limit_expire', 60)
                ]));
            }
        }
        if ((int) config('v2board.recaptcha_enable', 0)) {
            $recaptcha = new ReCaptcha(config('v2board.recaptcha_key'));
            $recaptchaResp = $recaptcha->verify($request->input('recaptcha_data'));
            if (!$recaptchaResp->isSuccess()) {
                abort(500, __('Invalid code is incorrect'));
            }
        }
        if ((int) config('v2board.email_whitelist_enable', 0)) {
            if (
                !Helper::emailSuffixVerify(
                    $request->input('email'),
                    config('v2board.email_whitelist_suffix', Dict::EMAIL_WHITELIST_SUFFIX_DEFAULT)
                )
            ) {
                abort(500, __('Email suffix is not in the Whitelist'));
            }
        }
        if ((int) config('v2board.email_gmail_limit_enable', 0)) {
            $prefix = explode('@', $request->input('email'))[0];
            if (strpos($prefix, '.') !== false || strpos($prefix, '+') !== false) {
                abort(500, __('Gmail alias is not supported'));
            }
        }
        if ((int) config('v2board.stop_register', 0)) {
            abort(500, __('Registration has closed'));
        }
        if ((int) config('v2board.invite_force', 0)) {
            if (empty($request->input('invite_code'))) {
                abort(500, __('You must use the invitation code to register'));
            }
        }
        $email = $request->input('email');
        $cacheKeyEmail = is_string($email) ? strtolower(trim($email)) : '';
        if ((int) config('v2board.email_verify', 0)) {
            if (empty($request->input('email_code'))) {
                abort(500, __('Email verification code cannot be empty'));
            }
            if ((string) Cache::get(CacheKey::get('EMAIL_VERIFY_CODE', $request->input('email'))) !== (string) $request->input('email_code')) {
                abort(500, __('Incorrect email verification code'));
            }
            $inputCode = $request->input('email_code');
            if (!is_string($inputCode) || !preg_match('/^\d{6}$/', $inputCode)) {
                abort(500, __('Incorrect email verification code'));
            }
            $cachedCode = Cache::get(CacheKey::get('EMAIL_VERIFY_CODE', $cacheKeyEmail));
            if ($cachedCode === null || $cachedCode === '' || !hash_equals((string)$cachedCode, $inputCode)) {
                abort(500, __('Incorrect email verification code'));
            }
        }
        $password = $request->input('password');
        $exist = User::where('email', $email)->first();
        if ($exist) {
            abort(500, __('Email already exists'));
        }
        $user = new User();
        $user->email = $email;
        $user->password = password_hash($password, PASSWORD_DEFAULT);
        $user->uuid = Helper::guid(true);
        $user->token = Helper::guid();
        if ($request->input('invite_code')) {
            $inviteCode = InviteCode::where('code', $request->input('invite_code'))
                ->where('status', 0)
                ->first();
            if (!$inviteCode) {
                if ((int) config('v2board.invite_force', 0)) {
                    abort(500, __('Invalid invitation code'));
                }
            } else {
                $user->invite_user_id = $inviteCode->user_id ? $inviteCode->user_id : null;
                if (!(int) config('v2board.invite_never_expire', 0)) {
                    $inviteCode->status = 1;
                    $inviteCode->save();
                }
            }
        }

        // try out
        if ((int) config('v2board.try_out_plan_id', 0)) {
            $plan = Plan::find(config('v2board.try_out_plan_id'));
            if ($plan) {
                $user->transfer_enable = $plan->transfer_enable * 1073741824;
                $user->device_limit = $plan->device_limit;
                $user->plan_id = $plan->id;
                $user->group_id = $plan->group_id;
                $user->expired_at = time() + (config('v2board.try_out_hour', 1) * 3600);
                $user->speed_limit = $plan->speed_limit;
            }
        }

        $user->remind_expire = (int) config('v2board.remind_expire_default', 1);
        $user->remind_traffic = (int) config('v2board.remind_traffic_default', 1);

        if (!$user->save()) {
            abort(500, __('Register failed'));
        }
        if ((int) config('v2board.email_verify', 0)) {
            Cache::forget(CacheKey::get('EMAIL_VERIFY_CODE', $request->input('email')));
            Cache::forget(CacheKey::get('EMAIL_VERIFY_CODE', $cacheKeyEmail));
        }

        $user->last_login_at = time();
        $user->save();

        if ((int) config('v2board.register_limit_by_ip_enable', 0)) {
            Cache::put(
                CacheKey::get('REGISTER_IP_RATE_LIMIT', $request->ip()),
                (int) $registerCountByIP + 1,
                (int) config('v2board.register_limit_expire', 60) * 60
            );
        }

        $authService = new AuthService($user);

        return response()->json([
            'data' => $authService->generateAuthData($request)
        ]);
    }

    public function login(AuthLogin $request)
    {
        $email = $request->input('email');
        $password = $request->input('password');

        if ((int) config('v2board.password_limit_enable', 1)) {
            $passwordErrorCount = (int) Cache::get(CacheKey::get('PASSWORD_ERROR_LIMIT', $email), 0);
            if ($passwordErrorCount >= (int) config('v2board.password_limit_count', 5)) {
                abort(500, __('There are too many password errors, please try again after :minute minutes.', [
                    'minute' => config('v2board.password_limit_expire', 60)
                ]));
            }
        }

        $user = User::where('email', $email)->first();
        if (!$user) {
            abort(500, __('Incorrect email or password'));
        }
        if (
            !Helper::multiPasswordVerify(
                $user->password_algo,
                $user->password_salt,
                $password,
                $user->password
            )
        ) {
            if ((int) config('v2board.password_limit_enable')) {
                Cache::put(
                    CacheKey::get('PASSWORD_ERROR_LIMIT', $email),
                    (int) $passwordErrorCount + 1,
                    60 * (int) config('v2board.password_limit_expire', 60)
                );
            }
            abort(500, __('Incorrect email or password'));
        }

        if ($user->banned) {
            abort(500, __('Your account has been suspended'));
        }

        InsiderGuardService::recordLogin($user, $request);
        $authService = new AuthService($user);
        return response([
            'data' => $authService->generateAuthData($request)
        ]);
    }

    public function token2Login(Request $request)
    {
        if ($request->input('token')) {
            $redirect = '/#/login?verify=' . $request->input('token') . '&redirect=' . ($request->input('redirect') ? $request->input('redirect') : 'dashboard');
            if (config('v2board.app_url')) {
                $location = config('v2board.app_url') . $redirect;
            } else {
                $location = url($redirect);
            }
            return redirect()->to($location)->send();
        }

        if ($request->input('verify')) {
            $key = CacheKey::get('TEMP_TOKEN', $request->input('verify'));
            $userId = Cache::get($key);
            if (!$userId) {
                abort(500, __('Token error'));
            }
            $user = User::find($userId);
            if (!$user) {
                abort(500, __('The user does not '));
            }
            if ($user->banned) {
                abort(500, __('Your account has been suspended'));
            }
            Cache::forget($key);
            $authService = new AuthService($user);
            return response([
                'data' => $authService->generateAuthData($request)
            ]);
        }
    }

    public function getQuickLoginUrl(Request $request)
    {
        $authorization = $request->input('auth_data') ?? $request->header('authorization');
        if (!$authorization)
            abort(403, '未登录或登陆已过期');

        $user = AuthService::decryptAuthData($authorization);
        if (!$user)
            abort(403, '未登录或登陆已过期');

        $code = Helper::guid();
        $key = CacheKey::get('TEMP_TOKEN', $code);
        Cache::put($key, $user['id'], 60);
        $redirect = '/#/login?verify=' . $code . '&redirect=' . ($request->input('redirect') ? $request->input('redirect') : 'dashboard');
        if (config('v2board.app_url')) {
            $url = config('v2board.app_url') . $redirect;
        } else {
            $url = url($redirect);
        }
        return response([
            'data' => $url
        ]);
    }

    public function forget(AuthForget $request)
    {
        $forgetRequestLimitKey = CacheKey::get('FORGET_REQUEST_LIMIT', $request->input('email'));
        $forgetRequestLimit = (int) Cache::get($forgetRequestLimitKey);
        if ($forgetRequestLimit >= 3)
            abort(500, __('Reset failed, Please try again later'));
        if ((string) Cache::get(CacheKey::get('EMAIL_VERIFY_CODE', $request->input('email'))) !== (string) $request->input('email_code')) {
            Cache::put($forgetRequestLimitKey, $forgetRequestLimit ? $forgetRequestLimit + 1 : 1, 300);
            abort(500, __('Incorrect email verification code'));
        }

        $email     = $request->input('email');
        $inputCode = $request->input('email_code');
        $password  = $request->input('password');

        if (!is_string($email) || !is_string($inputCode) || !is_string($password)) {
            abort(500, __('Incorrect email verification code'));
        }
        if (!preg_match('/^\d{6}$/', $inputCode)) {
            abort(500, __('Incorrect email verification code'));
        }

        $cacheKeyEmail         = strtolower(trim($email));
        $forgetRequestLimitKey = CacheKey::get('FORGET_REQUEST_LIMIT', $cacheKeyEmail);
        $forgetRequestLimit    = (int)Cache::get($forgetRequestLimitKey);
        if ($forgetRequestLimit >= 3) {
            abort(500, __('Reset failed, Please try again later'));
        }

        $cachedCode = Cache::get(CacheKey::get('EMAIL_VERIFY_CODE', $cacheKeyEmail));
        if ($cachedCode === null || $cachedCode === '' || !hash_equals((string)$cachedCode, $inputCode)) {
            Cache::put($forgetRequestLimitKey, $forgetRequestLimit + 1, 300);
            abort(500, __('Incorrect email verification code'));
        }
        $user = User::where('email', $email)->first();
        if (!$user) {
            abort(500, __('This email is not registered in the system'));
        }
        $user->password      = password_hash($password, PASSWORD_DEFAULT);
        $user->password_algo = null;
        $user->password_salt = null;
        if (!$user->save()) {
            abort(500, __('Reset failed'));
        }
        Cache::forget(CacheKey::get('EMAIL_VERIFY_CODE', $cacheKeyEmail));
        (new AuthService($user))->removeAllSession();
        return response([
            'data' => true
        ]);
    }

    /**
     * 用户更改邮箱
     *
     * @param AuthChangeEmail $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function changeEmail(AuthChangeEmail $request)
    {
        // 添加详细的调试日志
        $this->debugLog("START - Received request", [
            'request_all_keys' => array_keys($request->all()),
            'has_auth_header' => $request->hasHeader('authorization'),
            'auth_header_length' => strlen($request->header('authorization', '')),
        ]);

        // 使用和Passport控制器中其他方法一样的方式获取用户
        $authorization = $request->input('auth_data') ?? $request->header('authorization');
        $this->debugLog("Authorization token check", [
            'auth_token_provided' => !empty($authorization),
            'auth_token_length' => strlen($authorization ?? ''),
        ]);

        if (!$authorization) {
            $this->debugLog("ERROR: No authorization token provided");
            abort(403, '未登录或登陆已过期');
        }

        $user = AuthService::decryptAuthData($authorization);
        $this->debugLog("AuthService::decryptAuthData result", [
            'user_data_exists' => !is_null($user),
            'user_data_type' => gettype($user),
            'user_data' => is_array($user) ? array_slice($user, 0, 5) : $user,
        ]);

        if (!$user) {
            $this->debugLog("ERROR: User authentication failed");
            abort(403, '未登录或登陆已过期');
        }

        // 现在$user是一个数组，包含用户信息
        $this->debugLog("Attempting to find user by ID", [
            'user_id' => $user['id'],
        ]);

        $userModel = User::find($user['id']);
        if (!$userModel) {
            $this->debugLog("ERROR: User not found in database", [
                'requested_user_id' => $user['id'],
            ]);
            abort(500, '用户未认证或认证已过期，请重新登录');
        }

        $this->debugLog("User found", [
            'user_id' => $userModel->id,
            'user_email' => $userModel->email,
        ]);

        $newEmail = $request->input('new_email');
        $emailCode = $request->input('email_code');

        $this->debugLog("Processing email change", [
            'new_email' => $newEmail,
            'email_code_provided' => !empty($emailCode),
        ]);

        // 检查新邮箱是否与旧邮箱相同
        if ($userModel->email === $newEmail) {
            $this->debugLog("ERROR: New email is same as current email", [
                'current_email' => $userModel->email,
                'new_email' => $newEmail,
            ]);
            abort(500, '新邮箱地址不能与当前邮箱地址相同');
        }

        // 检查系统是否开启了邮箱验证
        $emailVerifyEnabled = (bool) config('v2board.email_verify', 0);
        $this->debugLog("Email verification status", [
            'enabled' => $emailVerifyEnabled,
        ]);

        if ($emailVerifyEnabled) {
            // 如果开启了邮箱验证，必须提供验证码
            if (!$emailCode) {
                $this->debugLog("ERROR: Email code required but not provided");
                abort(500, '请输入邮箱验证码');
            }

            // 验证验证码
            $cacheKey = CacheKey::get('EMAIL_VERIFY_CODE', $newEmail);
            $cachedCode = Cache::get($cacheKey);

            $this->debugLog("Verifying email code", [
                'cache_key' => $cacheKey,
                'cached_code' => $cachedCode,
                'provided_code' => $emailCode,
                'codes_match' => (string) $cachedCode === (string) $emailCode,
            ]);

            if ((string) $cachedCode !== (string) $emailCode) {
                $this->debugLog("ERROR: Invalid or expired email code", [
                    'cached_code' => $cachedCode,
                    'provided_code' => $emailCode,
                ]);
                abort(500, '邮箱验证码不正确或已过期');
            }

            // 验证码正确，可以继续
            $this->debugLog("SUCCESS: Email code verified");

        }

        // 更新用户邮箱
        $this->debugLog("Updating user email", [
            'user_id' => $userModel->id,
            'old_email' => $userModel->email,
            'new_email' => $newEmail,
        ]);

        $userModel->email = $newEmail;
        if (!$userModel->save()) {
            $this->debugLog("ERROR: Failed to save user");
            abort(500, '邮箱地址更新失败');
        }

        $this->debugLog("SUCCESS: User email updated", [
            'user_id' => $userModel->id,
            'new_email' => $newEmail,
        ]);

        // 如果开启了邮箱验证并且验证码已使用，则清除验证码缓存
        if ($emailVerifyEnabled && $cachedCode) {
            Cache::forget($cacheKey);
            $this->debugLog("INFO: Email verification code cleared from cache", [
                'cache_key' => $cacheKey,
            ]);
        }

        // 如果用户绑定了Telegram，则发送通知
        if ($userModel->telegram_id) {
            $this->debugLog("Sending Telegram notification for email change", [
                'user_id' => $userModel->id,
                'telegram_id' => $userModel->telegram_id,
                'new_email' => $newEmail,
            ]);

            // 发送Telegram通知
            $message = "您的邮箱地址已成功更改为: `{$newEmail}`\n\n新邮箱地址已生效，所有通知将发送到此邮箱。";
            $this->sendTelegramMessage($userModel->telegram_id, $message, 'markdown');
        }

        return response([
            'data' => true,
            'message' => '邮箱地址已成功更新'
        ]);
    }

}
