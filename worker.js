/**
 * V2rayN 订阅转 Clash Meta (Mihomo) 转换器
 * 运行在 Cloudflare Workers
 * Fixed: TUIC Support Added
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    // 1. 获取目标订阅链接
    const targetUrl = url.searchParams.get('url') || url.searchParams.get('target') || env.V2RAY_URL;

    if (!targetUrl) {
      return new Response(helpText(url.origin), {
        status: 200,
        headers: { 'content-type': 'text/html;charset=UTF-8' },
      });
    }

    try {
      // 2. 请求原始订阅数据
      const subRes = await fetch(targetUrl, {
        headers: {
          'User-Agent': 'v2rayNG/1.8.5', // 模拟 v2rayNG 客户端
        },
      });

      if (!subRes.ok) {
        return new Response(`无法获取订阅内容: ${subRes.status} ${subRes.statusText}`, { status: 502 });
      }

      const subText = await subRes.text();
      
      // 3. 安全解码
      let decodedText;
      try {
        decodedText = safeBase64Decode(subText);
      } catch (e) {
        return new Response(`解析订阅内容失败: ${e.message}`, { status: 500 });
      }

      // 4. 按行分割
      const lines = decodedText.split(/\r?\n/).filter(l => l && l.trim() !== '');

      // 5. 解析节点
      const proxies = [];
      const names = [];

      for (const line of lines) {
        let proxy = null;
        try {
          const trimLine = line.trim();
          if (trimLine.startsWith('vmess://')) {
            proxy = parseVmess(trimLine);
          } else if (trimLine.startsWith('vless://')) {
            proxy = parseVless(trimLine);
          } else if (trimLine.startsWith('trojan://')) {
            proxy = parseTrojan(trimLine);
          } else if (trimLine.startsWith('ss://')) {
            proxy = parseSS(trimLine);
          } else if (trimLine.startsWith('hy2://') || trimLine.startsWith('hysteria2://')) {
            proxy = parseHysteria2(trimLine);
          } else if (trimLine.startsWith('tuic://')) {
            // 新增 TUIC 支持
            proxy = parseTuic(trimLine);
          }
        } catch (e) {
          console.error(`解析单行失败: ${line.substring(0, 50)}...`, e);
        }

        if (proxy) {
          // 处理重名
          let name = proxy.name;
          let counter = 1;
          while (names.includes(name)) {
            name = `${proxy.name} ${counter++}`;
          }
          proxy.name = name;
          names.push(name);
          proxies.push(proxy);
        }
      }

      if (proxies.length === 0) {
        return new Response("未找到有效的节点。请检查订阅链接是否正确，或订阅是否已过期。", { status: 400 });
      }

      // 6. 生成 Clash YAML
      const yaml = generateClashYaml(proxies, names);

      return new Response(yaml, {
        headers: {
          'content-type': 'text/yaml; charset=utf-8',
          'content-disposition': `attachment; filename="clash-meta-${Date.now()}.yaml"`,
          'profile-update-interval': '24',
        },
      });

    } catch (err) {
      return new Response(`服务器内部错误: ${err.message}`, { status: 500 });
    }
  },
};

// --- 解析逻辑 ---

function safeBase64Decode(str) {
  if (!str) return '';
  str = str.trim();
  // 检查是否是 HTML
  if (str.toLowerCase().startsWith('<!doctype') || str.toLowerCase().startsWith('<html')) {
    throw new Error("订阅链接返回了 HTML 页面而非订阅数据。");
  }
  // 检查是否已经是明文
  if (str.includes('vmess://') || str.includes('vless://') || str.includes('ss://') || str.includes('hy2://') || str.includes('tuic://')) {
    return str;
  }
  // 清洗
  str = str.replace(/\s/g, '');
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  try {
    const binaryStr = atob(str);
    try {
      const bytes = new Uint8Array(binaryStr.split('').map(c => c.charCodeAt(0)));
      return new TextDecoder('utf-8').decode(bytes);
    } catch (e) {
      return decodeURIComponent(escape(binaryStr));
    }
  } catch (e) {
    throw new Error("Base64 解码失败");
  }
}

function parseVmess(line) {
  const b64 = line.replace('vmess://', '');
  const jsonStr = safeBase64Decode(b64);
  const config = JSON.parse(jsonStr);

  const proxy = {
    name: config.ps || 'vmess-node',
    type: 'vmess',
    server: config.add,
    port: parseInt(config.port),
    uuid: config.id,
    alterId: parseInt(config.aid || 0),
    cipher: 'auto',
    udp: true,
    tls: config.tls === 'tls',
    'skip-cert-verify': true,
    network: config.net || 'tcp',
  };

  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: config.path || '/',
      headers: { Host: config.host || config.add },
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': config.path || 'public' };
  }

  if (proxy.tls) {
    proxy['servername'] = config.host || config.sni || config.add;
  }
  return proxy;
}

function parseVless(line) {
  let hash = '';
  const hashIndex = line.lastIndexOf('#');
  if (hashIndex !== -1) {
      hash = line.substring(hashIndex + 1);
      line = line.substring(0, hashIndex);
  }
  
  const url = new URL(line);
  const params = url.searchParams;

  const proxy = {
    name: decodeURIComponent(hash) || 'vless-node',
    type: 'vless',
    server: url.hostname,
    port: parseInt(url.port),
    uuid: url.username,
    udp: true,
    tls: params.get('security') === 'tls' || params.get('security') === 'reality',
    'skip-cert-verify': true,
    network: params.get('type') || 'tcp',
    flow: params.get('flow') || undefined,
  };

  if (params.get('security') === 'reality') {
    proxy['reality-opts'] = {
      'public-key': params.get('pbk'),
      'short-id': params.get('sid'),
    };
    if (params.get('fp')) proxy['client-fingerprint'] = params.get('fp');
    proxy['servername'] = params.get('sni');
  } else if (proxy.tls) {
    proxy['servername'] = params.get('sni') || params.get('host') || url.hostname;
  }

  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: params.get('path') || '/',
      headers: { Host: params.get('host') || params.get('sni') || url.hostname },
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': params.get('serviceName') || '' };
  }
  return proxy;
}

function parseTrojan(line) {
  let hash = '';
  const hashIndex = line.lastIndexOf('#');
  if (hashIndex !== -1) {
      hash = line.substring(hashIndex + 1);
      line = line.substring(0, hashIndex);
  }

  const url = new URL(line);
  const params = url.searchParams;

  const proxy = {
    name: decodeURIComponent(hash) || 'trojan-node',
    type: 'trojan',
    server: url.hostname,
    port: parseInt(url.port),
    password: url.username,
    udp: true,
    'skip-cert-verify': true,
    sni: params.get('sni') || params.get('peer') || url.hostname,
    network: params.get('type') || 'tcp',
  };

  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: params.get('path') || '/',
      headers: { Host: params.get('host') || proxy.sni },
    };
  } else if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': params.get('serviceName') || '' };
  }
  return proxy;
}

function parseSS(line) {
  let raw = line.replace('ss://', '');
  let name = '';
  const hashIndex = raw.lastIndexOf('#');
  if (hashIndex !== -1) {
      name = decodeURIComponent(raw.substring(hashIndex + 1));
      raw = raw.substring(0, hashIndex);
  }

  let userinfo, server, port;
  if (raw.includes('@')) {
    const parts = raw.split('@');
    userinfo = safeBase64Decode(parts[0]);
    const serverPart = parts[1].split(':');
    server = serverPart[0];
    port = parseInt(serverPart[1]);
  } else {
    const decoded = safeBase64Decode(raw);
    const parts = decoded.split('@');
    userinfo = parts[0];
    const serverPart = parts[1].split(':');
    server = serverPart[0];
    port = parseInt(serverPart[1]);
  }

  const [cipher, password] = userinfo.split(':');

  return {
    name: name || 'ss-node',
    type: 'ss',
    server: server,
    port: port,
    cipher: cipher,
    password: password,
    udp: true
  };
}

function parseHysteria2(line) {
  let name = 'hy2-node';
  const hashIndex = line.lastIndexOf('#');
  if (hashIndex !== -1) {
    name = decodeURIComponent(line.substring(hashIndex + 1));
    line = line.substring(0, hashIndex);
  }

  if (line.startsWith('hy2://')) {
  } else if (line.startsWith('hysteria2://')) {
     line = line.replace('hysteria2://', 'hy2://');
  }

  const url = new URL(line);
  const params = url.searchParams;

  const proxy = {
    name: name,
    type: 'hysteria2',
    server: url.hostname,
    port: parseInt(url.port),
    password: url.username || '',
    sni: params.get('sni') || url.hostname,
    'skip-cert-verify': params.get('insecure') === '1',
    udp: true
  };

  if (params.get('obfs')) {
    proxy.obfs = params.get('obfs');
    proxy['obfs-password'] = params.get('obfs-password');
  }
  
  if (params.get('alpn')) {
    proxy.alpn = params.get('alpn').split(',');
  }

  return proxy;
}

function parseTuic(line) {
  // TUIC v5 格式: tuic://uuid:password@host:port?params#name
  let name = 'tuic-node';
  const hashIndex = line.lastIndexOf('#');
  if (hashIndex !== -1) {
    name = decodeURIComponent(line.substring(hashIndex + 1));
    line = line.substring(0, hashIndex);
  }

  const url = new URL(line);
  const params = url.searchParams;

  const proxy = {
    name: name,
    type: 'tuic',
    server: url.hostname,
    port: parseInt(url.port),
    uuid: url.username,
    password: url.password,
    sni: params.get('sni') || url.hostname,
    'skip-cert-verify': params.get('allow_insecure') === '1',
    udp: true,
    'disable-sni': params.get('disable_sni') === '1',
    'reduce-rtt': true // 默认开启以优化延迟
  };

  // 可选参数映射
  if (params.get('alpn')) {
    proxy.alpn = params.get('alpn').split(',');
  }
  
  if (params.get('congestion_controller')) {
    proxy['congestion-controller'] = params.get('congestion_controller');
  }
  
  if (params.get('udp_relay_mode')) {
    proxy['udp-relay-mode'] = params.get('udp_relay_mode');
  }

  return proxy;
}

function generateClashYaml(proxies, names) {
  const yamlHead = `
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: :9090

proxies:
`;

  let yamlBody = '';
  proxies.forEach(p => {
    yamlBody += `  - ${JSON.stringify(p)}\n`;
  });

  const groups = `
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - 👋 手动选择
      - 🔯 故障转移
${names.map(n => `      - ${n}`).join('\n')}

  - name: 👋 手动选择
    type: select
    proxies:
${names.map(n => `      - ${n}`).join('\n')}

  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
${names.map(n => `      - ${n}`).join('\n')}

  - name: 🔯 故障转移
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
${names.map(n => `      - ${n}`).join('\n')}
`;

  const rules = `
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
`;

  return yamlHead + yamlBody + groups + rules;
}

function helpText(origin) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
    <title>SubConverter Lite</title>
    <style>
      body { font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; line-height: 1.6; }
      code { background: #f4f4f4; padding: 2px 5px; border-radius: 4px; }
      .box { border: 1px solid #ddd; padding: 20px; border-radius: 8px; background: #fafafa; }
      input { width: 100%; padding: 10px; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; }
      button { background: #0070f3; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
      button:hover { background: #005bb5; }
    </style>
  </head>
  <body>
    <h1>🔗 V2Ray -> Clash Meta 转换器</h1>
    <p>这是一个运行在 Cloudflare Workers 上的轻量级订阅转换工具。</p>
    
    <div class="box">
      <label>输入你的 V2Ray/Trojan/Hy2/TUIC 订阅链接:</label>
      <input type="text" id="subUrl" placeholder="https://example.com/subscribe/...">
      <button onclick="convert()">生成 Clash 订阅</button>
      
      <div id="result" style="margin-top: 20px; display:none;">
        <strong>你的 Clash Meta 订阅链接:</strong>
        <p><code id="outputUrl" style="word-break: break-all;"></code></p>
        <button onclick="copy()">复制</button>
      </div>
    </div>

    <script>
      function convert() {
        const input = document.getElementById('subUrl').value;
        if(!input) return alert('请输入链接');
        
        const workerUrl = "${origin}";
        const finalUrl = workerUrl + "/?url=" + encodeURIComponent(input);
        
        document.getElementById('outputUrl').innerText = finalUrl;
        document.getElementById('result').style.display = 'block';
      }
      function copy() {
        navigator.clipboard.writeText(document.getElementById('outputUrl').innerText);
        alert('已复制');
      }
    </script>
  </body>
  </html>
  `;
}
