<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class NewPeriodLog extends Model
{
    protected $table = 'v2_new_period_log';
    protected $dateFormat = 'U';
    protected $guarded = ['id'];
    protected $casts = [
        'created_at' => 'timestamp',
        'updated_at' => 'timestamp'
    ];
}
