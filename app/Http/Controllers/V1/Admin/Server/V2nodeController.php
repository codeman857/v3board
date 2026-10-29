<?php

namespace App\Http\Controllers\V1\Admin\Server;

use App\Http\Controllers\Controller;
use App\Models\ServerV2node;
use Illuminate\Http\Request;
use ParagonIE_Sodium_Compat as SodiumCompat;
use App\Utils\Helper;

class V2nodeController extends Controller
{
    public function save(Request $request)
    {
        $params = $request->validate([
            'group_id' => 'required',
            'route_id' => 'nullable|array',
            'name' => 'required',
            'parent_id' => 'nullable|integer',
            'host' => 'required',
            'listen_ip' => 'nullable',
            'port' => 'required',
            'server_port' => 'required',
            'protocol' => 'required|in:shadowsocks,vmess,vless,trojan,tuic,hysteria2,anytls',
            'tls' => 'required|in:0,1,2',
            'tls_settings' => 'nullable|array',
            'flow' => 'nullable|in:xtls-rprx-vision',
            'network' => 'required|in:tcp,ws,grpc,http,httpupgrade,xhttp',
            'network_settings' => 'nullable|array',
            'trusted_x_forwarded_for' => 'nullable|array',
            'encryption' => 'nullable',
            'encryption_settings' => 'nullable|array',
            'disable_sni' => 'required|in:0,1',
            'udp_relay_mode' => 'nullable',
            'zero_rtt_handshake' => 'required|in:0,1',
            'congestion_control' => 'nullable',
            'cipher' => 'nullable',
            'up_mbps' => 'nullable|numeric',
            'down_mbps' => 'nullable|numeric',
            'obfs' => 'nullable',
            'obfs_password' => 'nullable',
            'padding_scheme' => 'nullable',
            'tags' => 'nullable|array',
            'rate' => 'required',
            'show' => 'nullable|in:0,1',
            'sort' => 'nullable'
        ]);
        if ($params['protocol'] == 'anytls' && $params['tls'] === 0) {
            $params['tls'] = 1;
        }
        if (in_array($params['protocol'], ['hysteria2', 'trojan', 'tuic'])) {
            $params['tls'] = 1;
        }
        if (isset($params['tls']) && (int)$params['tls'] === 2) {
            $keyPair = SodiumCompat::crypto_box_keypair();
            $params['tls_settings'] = $params['tls_settings'] ?? [];
            if (!isset($params['tls_settings']['public_key'])) {
                $params['tls_settings']['public_key'] = Helper::base64EncodeUrlSafe(SodiumCompat::crypto_box_publickey($keyPair));
            }
            if (!isset($params['tls_settings']['private_key'])) {
                $params['tls_settings']['private_key'] = Helper::base64EncodeUrlSafe(SodiumCompat::crypto_box_secretkey($keyPair));
            }
            if (!isset($params['tls_settings']['short_id'])) {
                $params['tls_settings']['short_id'] = substr(sha1($params['tls_settings']['private_key']), 0, 8);
            }
            if (!isset($params['tls_settings']['server_port'])) {
                $params['tls_settings']['server_port'] = "443";
            }
        }
        if (isset($params['tls_settings']) && !empty($params['tls_settings']['ech']) && $params['tls_settings']['ech'] === 'custom') {
            if (empty($params['tls_settings']['ech_server_name'])) {
                $params['tls_settings']['ech'] = '';
            } else {
                $outerSni = $params['tls_settings']['ech_server_name'];
                if (empty($params['tls_settings']['ech_key']) || empty($params['tls_settings']['ech_config'])) {
                    $echPair = Helper::generateEchKeyPair($outerSni);
                    if (empty($params['tls_settings']['ech_key'])) {
                        $params['tls_settings']['ech_key'] = $echPair['ech_key'];
                    }
                    if (empty($params['tls_settings']['ech_config'])) {
                        $params['tls_settings']['ech_config'] = $echPair['ech_config'];
                    }
                }
            }
        }
        if (isset($params['tls']) && !empty($params['tls_settings']['cert_mode']) && $params['tls_settings']['cert_mode'] === 'remote') {
            if (!isset($params['tls_settings']['pinned_peer_cert_sha256'])) {
                $sni = $params['tls_settings']['server_name'] ?? 'example.com';
                $key = openssl_pkey_new([
                    "private_key_type" => OPENSSL_KEYTYPE_EC,
                    "curve_name" => "prime256v1"
                ]);
                if ($key === false) {
                    abort(500, '创建失败');
                }

                $csr = openssl_csr_new([
                    'commonName' => $sni
                ], $key, [
                    'digest_alg' => 'sha256'
                ]);

                if ($csr === false) {
                    abort(500, '创建失败');
                }

                $cert = openssl_csr_sign(
                    $csr,
                    null,
                    $key,
                    3650,
                    [
                        'digest_alg' => 'sha256'
                    ]
                );

                if ($cert === false) {
                    abort(500, '创建失败');
                }

                if (!openssl_pkey_export($key, $tlsKey)) {
                    abort(500, '创建失败');
                }

                if (!openssl_x509_export($cert, $tlsCert)) {
                    abort(500, '创建失败');
                }

                $certDer = base64_decode(
                    preg_replace(
                        '/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/',
                        '',
                        $tlsCert
                    ),
                    true
                );

                if ($certDer === false) {
                    abort(500, '创建失败');
                }

                $tlsPin = hash('sha256', $certDer);
                $params['tls_settings']['tls_cert'] = $tlsCert;
                $params['tls_settings']['tls_key'] = $tlsKey;
                $params['tls_settings']['pinned_peer_cert_sha256'] = $tlsPin;
            }
            // v3board：证书路径没填（或是之前自动生成的）时，按 pin 给一个专属路径。v2node 后端在证书文件已存在时不会覆盖，
            // 各证书模式共用默认路径，从其它模式切过来时节点上残留的旧证书会和 pin 对不上，按 pin 校验的客户端就连不上；
            // pin 重新生成后前缀变了也会换成新路径。站长手填的路径不动；已有节点重新保存一次即可生效
            $pin = $params['tls_settings']['pinned_peer_cert_sha256'] ?? '';
            $pinPrefix = is_string($pin) ? substr($pin, 0, 16) : '';
            $certFile = $params['tls_settings']['cert_file'] ?? '';
            $keyFile = $params['tls_settings']['key_file'] ?? '';
            if (preg_match('/^[0-9a-f]{16}$/', $pinPrefix)
                && (empty($certFile) || self::isAutoCertPath($certFile))
                && (empty($keyFile) || self::isAutoCertPath($keyFile))) {
                $params['tls_settings']['cert_file'] = "/etc/v2node/remote-{$pinPrefix}.cer";
                $params['tls_settings']['key_file'] = "/etc/v2node/remote-{$pinPrefix}.key";
            }
        }
        // v3board：切出「自签名（面板下发）」时去掉自动生成的专属路径，退回各模式的默认路径，
        // 否则后端看到自签证书文件已存在，会一直用它而不去申请 / 生成新模式的证书
        if (isset($params['tls_settings']) && is_array($params['tls_settings'])
            && ($params['tls_settings']['cert_mode'] ?? '') !== 'remote') {
            foreach (['cert_file', 'key_file'] as $field) {
                if (self::isAutoCertPath($params['tls_settings'][$field] ?? '')) unset($params['tls_settings'][$field]);
            }
        }
        if (isset($params['network_settings'])) {
            $ns = $params['network_settings'];
            if (isset($ns['acceptProxyProtocol'])) {
                $ns['acceptProxyProtocol'] = filter_var($ns['acceptProxyProtocol'], FILTER_VALIDATE_BOOLEAN);
            }
            $params['network_settings'] = $ns;
        }
        if ($params['network'] != 'tcp' && isset($params['encryption']) && $params['encryption'] != 'mlkem768x25519plus') {
            $params['flow'] = null;
        }
        if ($params['network'] == 'xhttp' && isset($params['network_settings'])) {
            $ns = $params['network_settings'];
            if (isset($ns['extra']) && is_array($ns['extra'])) {
                $extra = $ns['extra'];
                if (isset($extra['xPaddingObfsMode'])) {
                    $extra['xPaddingObfsMode'] = filter_var($extra['xPaddingObfsMode'], FILTER_VALIDATE_BOOLEAN);
                }
                if (isset($extra['noGRPCHeader'])) {
                    $extra['noGRPCHeader'] = filter_var($extra['noGRPCHeader'], FILTER_VALIDATE_BOOLEAN);
                }
                if (isset($extra['noSSEHeader'])) {
                    $extra['noSSEHeader'] = filter_var($extra['noSSEHeader'], FILTER_VALIDATE_BOOLEAN);
                }
                if (isset($extra['scMaxBufferedPosts'])) {
                    $extra['scMaxBufferedPosts'] = (int)$extra['scMaxBufferedPosts'];
                }
                if (isset($extra['xmux']) && is_array($extra['xmux'])) {
                    $xmux = $extra['xmux'];
                    if (isset($xmux['hKeepAlivePeriod'])) {
                        $xmux['hKeepAlivePeriod'] = (int)$xmux['hKeepAlivePeriod'];
                    }
                    $extra['xmux'] = $xmux;
                }
                if (isset($extra['downloadSettings']) && is_array($extra['downloadSettings'])) {
                    $downloadSettings = $extra['downloadSettings'];
                    if (isset($downloadSettings['port'])) {
                        $downloadSettings['port'] = (int)$downloadSettings['port'];
                    }
                    $extra['downloadSettings'] = $downloadSettings;
                }
                $ns['extra'] = $extra;
            }
            $params['network_settings'] = $ns;
        }
        if (isset($params['encryption']) && $params['encryption'] == 'mlkem768x25519plus') {
            $keyPair = SodiumCompat::crypto_box_keypair();
            $params['encryption_settings'] = $params['encryption_settings'] ?? [];
            if (!isset($params['encryption_settings']['mode'])) {
                $params['encryption_settings']['mode'] = 'native';
            }
            if (isset($params['encryption_settings']['rtt'])) {
                if ($params['encryption_settings']['rtt'] == '1rtt') {
                    $params['encryption_settings']['ticket'] = '0s';
                }
            } else {
                $params['encryption_settings']['rtt'] = '0rtt';
                $params['encryption_settings']['ticket'] = '600s';
            }
            if (!isset($params['encryption_settings']['private_key'])) {
                $params['encryption_settings']['private_key'] = Helper::base64EncodeUrlSafe(SodiumCompat::crypto_box_secretkey($keyPair));
            }
            if (!isset($params['encryption_settings']['password'])) {
                $params['encryption_settings']['password'] = Helper::base64EncodeUrlSafe(SodiumCompat::crypto_box_publickey($keyPair));
            }
        }

        if (isset($params['padding_scheme'])) {
            $params['padding_scheme'] = json_decode($params['padding_scheme']);
        }

        if (!isset($params['up_mbps'])) {
            $params['up_mbps'] = 0;
        }
        if (!isset($params['down_mbps'])) {
            $params['down_mbps'] = 0;
        }

        if (isset($params['obfs'])) {
            if (!isset($params['obfs_password']))  $params['obfs_password'] = Helper::getServerKey($request->input('created_at'), 16);
        } else {
            $params['obfs_password'] = null;
        }

        if ($params['protocol'] == 'shadowsocks' && !isset($params['cipher'])) {
            $params['cipher'] = 'aes-128-gcm';
        }

        if ($request->input('id')) {
            $server = ServerV2node::find($request->input('id'));
            if (!$server) {
                abort(500, '服务器不存在');
            }
            try {
                $server->update($params);
            } catch (\Exception $e) {
                abort(500, '保存失败');
            }
            return response([
                'data' => true
            ]);
        }

        if (!ServerV2node::create($params)) {
            abort(500, '创建失败');
        }
        return response([
            'data' => true
        ]);
    }

    public function drop(Request $request)
    {
        if ($request->input('id')) {
            $server = ServerV2node::find($request->input('id'));
            if (!$server) {
                abort(500, '节点ID不存在');
            }
        }
        return response([
            'data' => $server->delete()
        ]);
    }

    public function update(Request $request)
    {
        $params = $request->validate([
            'show' => 'nullable|in:0,1',
        ]);

        $server = ServerV2node::find($request->input('id'));

        if (!$server) {
            abort(500, '该服务器不存在');
        }
        try {
            $server->update($params);
        } catch (\Exception $e) {
            abort(500, '保存失败');
        }
        return response([
            'data' => true
        ]);
    }

    public function copy(Request $request)
    {
        $server = ServerV2node::find($request->input('id'));
        $server->show = 0;
        if (!$server) {
            abort(500, '服务器不存在');
        }
        if (!ServerV2node::create($server->toArray())) {
            abort(500, '复制失败');
        }

        return response([
            'data' => true
        ]);
    }

    /** 是否是「自签名（面板下发）」模式自动生成的证书路径 /etc/v2node/remote-<pin 前 16 位>.cer|key */
    private static function isAutoCertPath($path): bool
    {
        return is_string($path) && preg_match('#^/etc/v2node/remote-[0-9a-f]{16}\.(cer|key)$#', $path) === 1;
    }
}
