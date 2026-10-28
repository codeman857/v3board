<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,minimum-scale=1,user-scalable=no">
    <title>{{$title}}</title>
    {{-- 后台前端来自 codeman857/v2board-admin（React），产物由 build-admin.sh 放入 public/assets/admin。
         静态资源的 ?v= 取 admin.js 与 admin.css 的内容哈希：前端重新构建后自动换新，不依赖后端版本号。 --}}
    @php
        $adminScript = public_path('assets/admin/assets/admin.js');
        $adminStyle = public_path('assets/admin/assets/admin.css');
        // 入口 JS 不引用入口 CSS，只改样式时 admin.js 不变，所以版本号把两个文件的哈希都算进去
        $assetVersion = file_exists($adminScript) && file_exists($adminStyle)
            ? substr(md5(md5_file($adminScript) . md5_file($adminStyle)), 0, 8)
            : $version;
        $customCss = public_path('assets/admin/custom.css');
        $settings = [
            'title' => $title,
            'theme' => ['sidebar' => $theme_sidebar, 'header' => $theme_header, 'color' => $theme_color],
            'version' => $version,
            'background_url' => $background_url,
            'logo' => $logo,
            'secure_path' => $secure_path,
        ];
    @endphp
    <link rel="icon" type="image/png" href="/assets/admin/favicon.png?v={{$assetVersion}}">
    <link rel="stylesheet" href="/assets/admin/assets/admin.css?v={{$assetVersion}}">
    @if (file_exists($customCss))
    <link rel="stylesheet" href="/assets/admin/custom.css?v={{filemtime($customCss)}}">
    @endif
    <script>
        window.settings = @json($settings);
    </script>
</head>

<body>
<div id="root"></div>
<script type="module" crossorigin src="/assets/admin/assets/admin.js?v={{$assetVersion}}"></script>
</body>

</html>
