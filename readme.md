<img src="https://avatars.githubusercontent.com/u/56885001?s=200&v=4" alt="logo" width="130" height="130" align="right"/>

[![](https://img.shields.io/badge/TgChat-@UnOfficialV3Board讨论-blue.svg)](https://t.me/unofficialV3Board)

## 本分支支持的后端
 - [修改版V2bX](https://github.com/wyx2685/V2bX)

>- fork from [xiao佬版的V2board](https://github.com/wyx2685/v2board) 在此基础上增加一些功能

# 本仓库接下来日程

- [ ] 第三方登录 Google & Telegram
- [ ] 签到功能： 同时支持网站和TG签到 普通签到 & 运气签到
- [ ] 支付回调适配
- [ ] 节点掉线TG通知管理员


## 原版迁移步骤

按以下步骤进行面板代码文件迁移：

    git remote set-url origin https://github.com/codeman857/v3board.git  
    git checkout master  
    ./update.sh  


按以下步骤配置缓存驱动为redis，然后刷新设置缓存，重启队列:

    sed -i 's/^CACHE_DRIVER=.*/CACHE_DRIVER=redis/' .env
    php artisan config:clear
    php artisan config:cache
    php artisan horizon:terminate

最后进入后台重新保存主题： 主题配置-选择default主题-主题设置-确定保存

# **V3Board**

- PHP7.3+
- Composer
- MySQL5.5+
- Redis
- Laravel

## Demo
[Demo](https://demo.V3Board.com)

## Document
[Click](https://V3Board.com)

## Sponsors
Thanks to the open source project license provided by [Jetbrains](https://www.jetbrains.com/)

## Community
🔔Telegram Group: [@unofficialV3Board](https://t.me/unofficialV3Board)  

## How to Feedback
Follow the template in the issue to submit your question correctly, and we will have someone follow up with you.
