<?php

namespace App\Console\Commands;

use App\Services\InsiderGuardService;
use Illuminate\Console\Command;
use Illuminate\Database\QueryException;

class InsiderGuardHealth extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'insider-guard:health';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '风控中心：探测显示中节点的 TCP 连通性';

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        try {
            $result = InsiderGuardService::health();
        } catch (QueryException $e) {
            // SQLSTATE 42S02 = 表不存在，多半是没跑升级脚本；其它数据库错误原样提示
            $this->warn($e->getCode() === '42S02'
                ? '风控中心的数据表不存在，请先执行 php artisan v2board:update'
                : '风控中心数据库错误：' . $e->getMessage());
            return 1;
        }
        if (!empty($result['disabled'])) {
            $this->info($result['message']);
            return 0;
        }
        $down = count(array_filter($result['results'], function ($item) {
            return ($item['status'] ?? '') === 'down';
        }));
        $this->info("已检测 {$result['checked']} 个节点，不通 {$down} 个");
        return 0;
    }
}
