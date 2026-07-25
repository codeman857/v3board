<?php

namespace App\Http\Controllers\V1\Admin;

use App\Http\Controllers\Controller;
use App\Models\NewPeriodLog;
use App\Models\Plan;
use App\Models\User;
use Illuminate\Http\Request;

class NewPeriodLogController extends Controller
{
    public function fetch(Request $request)
    {
        $current = (int) $request->input('current');
        if ($current < 1) $current = 1;
        $pageSize = (int) $request->input('pageSize');
        if ($pageSize < 10) $pageSize = 10;
        if ($pageSize > 500) $pageSize = 500;

        $model = NewPeriodLog::orderBy('created_at', 'DESC');
        if ($request->input('email')) {
            $userIds = User::where('email', 'like', '%' . $request->input('email') . '%')
                ->pluck('id')
                ->toArray();
            $model->whereIn('user_id', $userIds);
        }
        if ($request->input('user_id')) {
            $model->where('user_id', (int)$request->input('user_id'));
        }

        $total = $model->count();
        $res = $model->forPage($current, $pageSize)->get();

        $users = User::whereIn('id', $res->pluck('user_id')->unique())->get()->keyBy('id');
        $plans = Plan::whereIn('id', $res->pluck('plan_id')->unique()->filter())->get()->keyBy('id');
        foreach ($res as $item) {
            $item['user_email'] = isset($users[$item->user_id]) ? $users[$item->user_id]->email : null;
            $item['plan_name'] = isset($plans[$item->plan_id]) ? $plans[$item->plan_id]->name : null;
        }

        return response([
            'data' => $res,
            'total' => $total
        ]);
    }
}
