<?php

namespace App\Console\Commands;

use App\Services\InsiderGuardService;
use Illuminate\Console\Command;
use Illuminate\Database\QueryException;

class InsiderGuardCleanup extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'insider-guard:cleanup';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '风控中心：按保留天数清理过期的活动、节点下发、健康探测与 UA 字典记录，以及已删除用户的限制记录';

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        try {
            $counts = InsiderGuardService::cleanup();
        } catch (QueryException $e) {
            // SQLSTATE 42S02 = 表不存在，多半是没跑升级脚本；其它数据库错误原样提示
            $this->warn($e->getCode() === '42S02'
                ? '风控中心的数据表不存在，请先执行 php artisan v2board:update'
                : '风控中心数据库错误：' . $e->getMessage());
            return 1;
        }
        foreach ($counts as $table => $count) {
            $this->info("{$table}: 删除 {$count} 条");
        }
        return 0;
    }
}
