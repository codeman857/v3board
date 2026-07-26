<?php

namespace App\Http\Controllers\V1\Admin;

use App\Http\Controllers\Controller;
use App\Models\NewPeriodLog;
use App\Models\Order;
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
        if ($request->input('type')) {
            $model->where('type', (int)$request->input('type'));
        }
        if ($request->input('email')) {
            $email = $request->input('email');
            $model->whereIn('user_id', function ($query) use ($email) {
                $query->select('id')
                    ->from((new User)->getTable())
                    ->where('email', 'like', '%' . $email . '%');
            });
        }
        if ($request->input('user_id')) {
            $model->where('user_id', (int)$request->input('user_id'));
        }
        if ($request->input('trade_no')) {
            $tradeNo = $request->input('trade_no');
            $model->whereIn('order_id', function ($query) use ($tradeNo) {
                $query->select('id')
                    ->from((new Order)->getTable())
                    ->where('trade_no', 'like', '%' . $tradeNo . '%');
            });
        }

        $total = $model->count();
        $res = $model->forPage($current, $pageSize)->get();

        $users = User::whereIn('id', $res->pluck('user_id')->unique())->get()->keyBy('id');
        $planIds = $res->pluck('plan_id')->merge($res->pluck('new_plan_id'))->unique()->filter();
        $plans = Plan::whereIn('id', $planIds)->get()->keyBy('id');
        $orders = Order::whereIn('id', $res->pluck('order_id')->unique()->filter())->get()->keyBy('id');
        foreach ($res as $item) {
            $item['user_email'] = isset($users[$item->user_id]) ? $users[$item->user_id]->email : null;
            $item['plan_name'] = isset($plans[$item->plan_id]) ? $plans[$item->plan_id]->name : null;
            $item['new_plan_name'] = isset($plans[$item->new_plan_id]) ? $plans[$item->new_plan_id]->name : null;
            $item['trade_no'] = isset($orders[$item->order_id]) ? $orders[$item->order_id]->trade_no : null;
        }

        return response([
            'data' => $res,
            'total' => $total
        ]);
    }
}
