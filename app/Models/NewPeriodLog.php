<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class NewPeriodLog extends Model
{
    // 流量用尽后提前开启下一计费周期
    const TYPE_NEW_PERIOD = 1;
    // 购买不同订阅导致原订阅被覆盖
    const TYPE_PLAN_CHANGE = 2;

    protected $table = 'v2_new_period_log';
    protected $dateFormat = 'U';
    protected $guarded = ['id'];
    protected $casts = [
        'created_at' => 'timestamp',
        'updated_at' => 'timestamp'
    ];
}
