<img src="https://avatars.githubusercontent.com/u/56885001?s=200&v=4" alt="logo" width="130" height="130" align="right"/>

# V3Board - V2Board 增强版

基于 [wyx2685/v2board](https://github.com/wyx2685/v2board) 分支进行二次开发，新增多项实用功能和优化。

---

## ✨ 新功能与改进

### 🎁 签到系统

全新签到功能，用户可通过每日签到获得随机流量奖励。

- **普通签到** (`/sign`)：每日可签到一次，随机获得 10MB ~ 1GB 流量
- **运气签到** (`/sign2 <数值><单位>`)：高风险高回报模式
  - 用户输入想要赌的流量值（如 `100GB`）
  - 可能获得 -100% 到 +100% 的浮动流量
  - 支持 MB 和 GB 单位
- 签到通过减少已用流量实现，续费时不会重置签到奖励
- 支持 Web API 和 Telegram 机器人两种方式

### 🔐 OAuth 第三方登录

集成完整的第三方登录系统，提升用户体验。

- **Google OAuth 登录/注册**
  - 完整的 OAuth 2.0 授权流程
  - 支持新用户自动注册，老用户直接登录
  - 自动发送欢迎邮件（含随机密码）
- **Telegram 登录**
  - 通过 Telegram 机器人验证身份登录
  - 用户向机器人发送验证码完成登录
  - 前端轮询接口检查登录状态
- 支持邀请码关联

### 📡 节点监控增强

大幅增强服务器监控功能，提供更智能的告警机制。

| 功能 | 原版 | 增强版 |
|------|------|--------|
| 掉线检测 | 30分钟超时立即通知 | 5分钟超时，连续5次才通知 |
| 重复通知 | 每次检测都通知 | 24小时内不重复 |
| 恢复通知 | 无 | ✅ 节点恢复时发送通知 |
| 状态报告 | 无 | ✅ 定时发送全节点状态报告 |

- **连续掉线计数**：避免短暂网络波动造成误报
- **恢复通知**：节点恢复后自动发送恢复通知
- **定时状态报告**：可配置每 N 小时发送一次全节点状态汇总
- 自动过滤隐藏节点 (`show=0`)

### 🤖 Telegram 机器人扩展

新增 6 个 Telegram 命令，从 5 个增加到 11 个：

| 命令 | 功能 | 状态 |
|------|------|------|
| `/start` | 欢迎消息和快捷指令 | 🆕 新增 |
| `/help` | 显示帮助信息 | 🆕 新增 |
| `/info` | 查询账户信息 | 🆕 新增 |
| `/sign` | 普通签到 | 🆕 新增 |
| `/sign2` | 运气签到 | 🆕 新增 |
| `/login <验证码>` | Telegram 登录验证 | 🆕 新增 |
| `/bind` | 绑定账号 | ✅ 增强 |
| `/unbind` | 解绑账号 | 原有 |
| `/traffic` | 查询流量 | 原有 |
| `/getlatesturl` | 获取最新网址 | 原有 |
| `/replyticket` | 回复工单 | 原有 |

**TelegramService 增强**：
- 新增 MarkdownV2 安全转义，支持代码块保护
- 统一的 `sendReply()` 方法，自动处理格式转换
- 更好的错误处理和日志记录

### 📧 邮件模板

- 新增 **fashion** 邮件主题风格（完整的 6 个模板）
- 新增 **googleWelcome.blade.php** 模板用于 OAuth 用户欢迎邮件
- 邮件服务代码优化

### 🔧 其他改进

- **优惠券 API 增强**：CouponController
- **用户控制器优化**：UserController 新增签到相关逻辑
- **服务器信息扩展**：ServerController 返回更多信息
- **认证服务增强**：AuthService 新增第三方登录支持
- **命令行工具**：
  - 新增 `ClearCheckinCache` 清理签到缓存
  - 新增 `UpdateTelegramCommands` 更新机器人命令
- **邮件提醒优化**：SendRemindMail

---

## 本分支支持的后端
 - [修改版V2bX](https://github.com/wyx2685/V2bX)
 - [v2node](https://github.com/wyx2685/v2node)

## 原版迁移步骤

按以下步骤从xiao v2board无缝迁移，数据库无需任何改动：

    git remote set-url origin https://github.com/codeman857/v3board  
    git checkout master  
    ./update.sh  


按以下步骤配置缓存驱动为redis，然后刷新设置缓存，重启队列:

    sed -i 's/^CACHE_DRIVER=.*/CACHE_DRIVER=redis/' .env
    php artisan config:clear
    php artisan config:cache
    php artisan horizon:terminate

最后进入后台重新保存主题： 主题配置-选择default主题-主题设置-确定保存

合并xiao v2board有冲突？运行以下脚本手动解决冲突即可
```shell
    sh merge.sh
```

# **V2Board**

- PHP7.3+
- Composer
- MySQL5.5+
- Redis
- Laravel

## Document
[Click](https://v2board.com)

## Sponsors
Thanks to the open source project license provided by [Jetbrains](https://www.jetbrains.com/)

## Community
🔔Telegram Group: [@v3board_group](https://t.me/v3board_group)  

## How to Feedback
Follow the template in the issue to submit your question correctly, and we will have someone follow up with you.
