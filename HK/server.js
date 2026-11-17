const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const db = require('./data/db');
const interceptor = require('./src/engine/packet_interceptor');
const gameTunnel = require('./src/engine/game_tunnel');

gameTunnel.start();
interceptor.setFeatures(db.get().global_features);

const PORT = process.env.PORT || 3001;
const ROOT_DIR = __dirname;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'powerup-admin-2026';
const DEFAULT_UUID = process.env.UUID || 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf'
};

const sseClients = new Set();

function broadcastEvent(eventName, data) {
  for (const client of sseClients) {
    try {
      client.write(`event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(data));
}

function parseJsonBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch (e) {
        resolve({});
      }
    });
  });
}

function generateRandomKey(prefix = 'PHTM') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const chunk = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `${prefix}-${chunk()}-${chunk()}-${chunk()}`;
}

function detectServerDevice(ua = '') {
  let os = 'Unknown OS';
  let model = 'Unknown Device';

  if (/Windows NT 10.0/i.test(ua)) {
    os = 'Windows 10/11 64-bit';
    model = 'Windows PC';
  } else if (/Windows NT 6.3/i.test(ua)) {
    os = 'Windows 8.1';
    model = 'Windows PC';
  } else if (/Windows NT 6.1/i.test(ua)) {
    os = 'Windows 7';
    model = 'Windows PC';
  } else if (/iPhone/i.test(ua)) {
    const v = ua.match(/OS (\d+[_\.]\d+)/);
    os = v ? `iOS ${v[1].replace('_', '.')}` : 'iOS';
    model = `iPhone (${os})`;
  } else if (/iPad/i.test(ua)) {
    const v = ua.match(/OS (\d+[_\.]\d+)/);
    os = v ? `iPadOS ${v[1].replace('_', '.')}` : 'iPadOS';
    model = `iPad (${os})`;
  } else if (/Macintosh|Mac OS X/i.test(ua)) {
    const v = ua.match(/Mac OS X (\d+[_\.]\d+)/);
    os = v ? `macOS ${v[1].replace('_', '.')}` : 'macOS';
    model = `Mac (${os})`;
  } else if (/Android/i.test(ua)) {
    const v = ua.match(/Android (\d+(\.\d+)?)/);
    os = v ? `Android ${v[1]}` : 'Android';
    const m = ua.match(/;\s*([A-Za-z0-9\-\s\_]+)\s+Build\//);
    model = m ? `${m[1].trim()} (${os})` : `Android Device (${os})`;
  } else if (/Linux/i.test(ua)) {
    os = 'Linux';
    model = 'Linux Desktop';
  }

  let browser = 'Browser';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/Chrome\//i.test(ua)) browser = 'Chrome';
  else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';

  if (model === 'Windows PC' || model === 'Linux Desktop') {
    model = `${model} (${browser})`;
  }

  return { os, model };
}

// دالة لجلب IP الشبكة المحلية تلقائياً
function getLocalNetworkIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

function nodeToLink(n, fallbackHost) {
  if (n.link) return n.link;
  if (n.uri) return n.uri;
  const uuid = n.uuid || DEFAULT_UUID;
  const host = n.host || n.address || fallbackHost || '127.0.0.1';
  const port = n.port || 443;
  const name = encodeURIComponent(`${n.flag || ''} ${n.name || host}`.trim());
  const security = port === 443 ? 'tls' : 'none';
  const type = n.type || 'ws';
  return `vless://${uuid}@${host}:${port}?encryption=none&security=${security}&type=${type}&host=${host}&path=%2F#${name}`;
}

function buildSubscriptionPayload(reqHost) {
  // جلب الـ IP المحلي للشبكة أو استخدام اسم المضيف كاحتياط
  const networkIP = getLocalNetworkIP();
  const cleanHost = (reqHost && reqHost !== 'localhost' && !reqHost.startsWith('127.0.0.1')) 
    ? reqHost.split(':')[0] 
    : networkIP;

  const nodes = db.get().nodes || [];
  let links = nodes.map(n => nodeToLink(n, cleanHost)).filter(Boolean);
  
  if (links.length === 0) {
    links.push(`vless://${DEFAULT_UUID}@${cleanHost}:443?encryption=none&security=tls&type=ws&host=${cleanHost}&path=%2F#${encodeURIComponent('AlliFF Server')}`);
  }
  return Buffer.from(links.join('\n')).toString('base64');
}

function isProxyClient(ua = '') {
  return /Happ|v2ray|Clash|Shadowrocket|SFA|SFM|Sing-box|NekoBox|Streisand|Hiddify|Quantumult| Loon|Surge/i.test(ua);
}

function isAdminAuthorized(req) {
  const auth = req.headers['authorization'];
  if (!auth) return false;
  const [type, creds] = auth.split(' ');
  if (type !== 'Basic') return false;
  const decoded = Buffer.from(creds, 'base64').toString();
  const colonIndex = decoded.indexOf(':');
  if (colonIndex === -1) return false;
  const user = decoded.slice(0, colonIndex);
  const pass = decoded.slice(colonIndex + 1);
  return user === 'admin' && pass === ADMIN_PASSWORD;
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (pathname.startsWith('/api/admin/') || pathname === '/admin' || pathname === '/admin/') {
    if (!isAdminAuthorized(req)) {
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Admin Panel"' });
      res.end('Unauthorized');
      return;
    }
  }

  if ((pathname === '/sub' || pathname === '/api/sub') && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': '12',
      'Subscription-Userinfo': 'upload=0; download=0; total=10737418240000; expire=2524608000'
    });
    res.end(buildSubscriptionPayload(req.headers.host));
    return;
  }

  const subMatch = pathname.match(/^\/api\/sub\/([^/]+)$/);
  if (subMatch && req.method === 'GET') {
    const k = decodeURIComponent(subMatch[1]).trim().toUpperCase();
    const special = ['OWNER', 'ADMIN', 'TEST', 'PHTM-TEST-1234-5678'].includes(k);
    const rec = special ? null : db.findKey(k);
    if (!special && rec && (rec.status === 'revoked' || new Date(rec.expires_at).getTime() < Date.now())) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': '12',
      'Subscription-Userinfo': 'upload=0; download=0; total=10737418240000; expire=2524608000'
    });
    res.end(buildSubscriptionPayload(req.headers.host));
    return;
  }

  if (pathname === '/' && req.method === 'GET' && (isProxyClient(req.headers['user-agent']) || parsedUrl.searchParams.has('sub'))) {
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': '12',
      'Subscription-Userinfo': 'upload=0; download=0; total=10737418240000; expire=2524608000'
    });
    res.end(buildSubscriptionPayload(req.headers.host));
    return;
  }

  if (pathname === '/api/maintenance' && req.method === 'GET') {
    return sendJson(res, 200, db.getMaintenance());
  }

  if (pathname === '/api/redeem' && req.method === 'POST') {
    const body = await parseJsonBody(req);
    const rawKey = (body.key || '').trim();
    const key = rawKey.toUpperCase();

    if (!rawKey) {
      return sendJson(res, 400, { error: 'enter your full key' });
    }

    const ua = req.headers['user-agent'] || '';
    const serverDev = detectServerDevice(ua);
    const clientHwid = (body.hwid || '').trim() || `PHTM-${crypto.createHash('md5').update(ua + (req.socket.remoteAddress || '')).digest('hex').slice(0, 8).toUpperCase()}`;
    const clientDeviceModel = (body.device_model || '').trim() || serverDev.model;
    const clientDeviceOs = (body.device_os || '').trim() || serverDev.os;

    const maintenance = db.getMaintenance();
    const isSpecialLogin = ['OWNER', 'ADMIN', 'TEST'].includes(key);

    if (maintenance.enabled) {
      const isAllowed = maintenance.allowed_logins.some(
        item => item.toUpperCase() === key || (isSpecialLogin && item.toUpperCase() === key)
      );
      if (!isAllowed) {
        return sendJson(res, 403, { 
          error: maintenance.blocked 
            ? 'your account is paused during maintenance. back soon.' 
            : 'maintenance in progress. only allowed test logins are currently permitted.' 
        });
      }
    }

    if (isSpecialLogin) {
      return sendJson(res, 200, {
        ok: true,
        me: {
          status: 'active',
          bound_hwid: clientHwid,
          device_model: clientDeviceModel,
          device_os: clientDeviceOs,
          expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
          features: db.get().global_features
        }
      });
    }

    let keyRecord = db.findKey(key);

    if (!keyRecord) {
      return sendJson(res, 400, { error: 'invalid license key' });
    }

    if (keyRecord.status === 'revoked') {
      return sendJson(res, 400, { error: 'this license key has been revoked' });
    }

    if (new Date(keyRecord.expires_at).getTime() < Date.now()) {
      return sendJson(res, 400, { error: 'this license key has expired' });
    }

    if (!keyRecord.bound_hwid) {
      keyRecord.bound_hwid = clientHwid;
      keyRecord.device_model = clientDeviceModel;
      keyRecord.device_os = clientDeviceOs;
      db.updateKey(key, {
        bound_hwid: clientHwid,
        device_model: clientDeviceModel,
        device_os: clientDeviceOs
      });
    } else {
      if (keyRecord.bound_hwid !== clientHwid) {
        return sendJson(res, 403, { 
          error: `key is locked to another device (${keyRecord.device_model || 'other device'}). reset device lock from the site first.` 
        });
      }
      if (clientDeviceModel && clientDeviceModel !== 'Unknown Device' && clientDeviceModel !== keyRecord.device_model) {
        keyRecord.device_model = clientDeviceModel;
        keyRecord.device_os = clientDeviceOs;
        db.updateKey(key, { device_model: clientDeviceModel, device_os: clientDeviceOs });
      }
    }

    return sendJson(res, 200, {
      ok: true,
      me: {
        status: 'active',
        bound_hwid: keyRecord.bound_hwid,
        device_model: keyRecord.device_model,
        device_os: keyRecord.device_os,
        expires_at: keyRecord.expires_at,
        features: keyRecord.features && Object.keys(keyRecord.features).length > 0 
          ? keyRecord.features 
          : db.get().global_features
      }
    });
  }

  if (pathname === '/api/features') {
    if (req.method === 'GET') {
      return sendJson(res, 200, { features: db.get().global_features });
    }
    if (req.method === 'PATCH') {
      const body = await parseJsonBody(req);
      if (body.features) {
        db.update(data => {
          data.global_features = { ...data.global_features, ...body.features };
        });
        interceptor.setFeatures(db.get().global_features);
        if (body.key) {
          db.updateKey(body.key, { features: body.features });
        }
      }
      return sendJson(res, 200, { ok: true, features: db.get().global_features });
    }
  }

  if (pathname === '/api/engine/tunnel-stats' && req.method === 'GET') {
    return sendJson(res, 200, gameTunnel.getStats());
  }

  if (pathname === '/api/happ' && req.method === 'POST') {
    const body = await parseJsonBody(req);
    const key = body.key || 'PHTM-TEST-1234-5678';
    const nodes = db.get().nodes;

    const configData = {
      version: '1.7',
      client: 'POWER UP',
      key: key,
      created_at: new Date().toISOString(),
      nodes: nodes.map(n => ({
        name: `${n.flag} ${n.name}`,
        address: n.host,
        port: n.port,
        ping: `${n.ping}ms`,
        status: n.status
      })),
      active_features: db.get().global_features,
      routing: {
        rules: [{ domain_suffix: ['freefiremobile.com', 'garena.com'], outbound: 'phantom-tunnel' }]
      }
    };

    // جلب IP الشبكة المحلية
    const networkIP = getLocalNetworkIP();
    const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
    const subUrl = `${proto}://${networkIP}:${PORT}/api/sub/${encodeURIComponent(key)}`;
    
    const deepLink = `happ://add/${subUrl}`;
    const iosDeepLink = deepLink;

    return sendJson(res, 200, {
      ok: true,
      href: 'https://apps.apple.com/us/app/happ-proxy-utility/id6504287215',
      deepLink: deepLink,
      iosDeepLink: iosDeepLink,
      config: configData
    });
  }

  if ((pathname === '/api/unbind-hwid' || pathname === '/api/reset-hwid') && req.method === 'POST') {
    const body = await parseJsonBody(req);
    if (body.key) {
      db.updateKey(body.key, { bound_hwid: null, device_model: null, device_os: null });
      return sendJson(res, 200, {
        ok: true,
        message: 'Device lock removed. Next login will bind your current device.'
      });
    }
    return sendJson(res, 400, { error: 'key required' });
  }

  if (pathname === '/api/config/export') {
    const nodes = db.get().nodes;
    const configData = {
      version: '1.7',
      client: 'POWER UP',
      created_at: new Date().toISOString(),
      nodes: nodes,
      features: db.get().global_features
    };
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Disposition': 'attachment; filename="phantom-happ-config.json"'
    });
    res.end(JSON.stringify(configData, null, 2));
    return;
  }

  if (pathname === '/api/logout' && req.method === 'POST') {
    return sendJson(res, 200, { ok: true });
  }

  if (pathname === '/api/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });
    res.write('event: connected\ndata: {}\n\n');
    sseClients.add(res);

    req.on('close', () => {
      sseClients.delete(res);
    });
    return;
  }

  if (pathname === '/api/admin/overview' && req.method === 'GET') {
    const data = db.get();
    const totalKeys = data.keys.length;
    const activeKeys = data.keys.filter(k => k.status === 'active' && new Date(k.expires_at) > Date.now()).length;
    const unboundKeys = data.keys.filter(k => !k.bound_hwid).length;
    const expiredKeys = data.keys.filter(k => new Date(k.expires_at) <= Date.now()).length;
    const revokedKeys = data.keys.filter(k => k.status === 'revoked').length;
    const totalUsers = data.nodes.reduce((acc, n) => acc + (n.users || 0), 0);

    return sendJson(res, 200, {
      totalKeys,
      activeKeys,
      unboundKeys,
      expiredKeys,
      revokedKeys,
      totalUsers,
      maintenance: data.maintenance,
      nodes: data.nodes
    });
  }

  if (pathname === '/api/admin/keys' && req.method === 'GET') {
    const data = db.get();
    return sendJson(res, 200, { keys: data.keys });
  }

  if (pathname === '/api/admin/keys/generate' && req.method === 'POST') {
    const body = await parseJsonBody(req);
    const count = Math.min(Math.max(parseInt(body.count, 10) || 1, 1), 50);
    const durationDays = parseInt(body.days, 10) || 30;
    const note = body.note || 'Generated from Admin Panel';
    const prefix = (body.prefix || 'PHTM').trim().toUpperCase();

    const createdKeys = [];
    for (let i = 0; i < count; i++) {
      const newKeyStr = generateRandomKey(prefix);
      const newKeyObj = {
        key: newKeyStr,
        status: 'active',
        bound_hwid: null,
        device_model: null,
        created_at: new Date().toISOString(),
        expires_at: durationDays > 999 
          ? new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000).toISOString()
          : new Date(Date.now() + durationDays * 24 * 3600 * 1000).toISOString(),
        note: note,
        features: db.get().global_features
      };
      db.addKey(newKeyObj);
      createdKeys.push(newKeyObj);
    }

    return sendJson(res, 200, { ok: true, keys: createdKeys });
  }

  const keyActionMatch = pathname.match(/^\/api\/admin\/keys\/([^/]+)\/(unbind|toggle-status|extend)$/);
  if (keyActionMatch && req.method === 'POST') {
    const targetKey = decodeURIComponent(keyActionMatch[1]);
    const action = keyActionMatch[2];

    const keyObj = db.findKey(targetKey);
    if (!keyObj) {
      return sendJson(res, 404, { error: 'Key not found' });
    }

    if (action === 'unbind') {
      db.updateKey(targetKey, { bound_hwid: null, device_model: null });
      return sendJson(res, 200, { ok: true, message: `Unbound HWID for ${targetKey}` });
    }

    if (action === 'toggle-status') {
      const newStatus = keyObj.status === 'active' ? 'revoked' : 'active';
      db.updateKey(targetKey, { status: newStatus });
      if (newStatus === 'revoked') {
        broadcastEvent('logout', { key: targetKey });
      }
      return sendJson(res, 200, { ok: true, status: newStatus });
    }

    if (action === 'extend') {
      const body = await parseJsonBody(req);
      const addDays = parseInt(body.days, 10) || 30;
      const currentExpiry = new Date(keyObj.expires_at).getTime();
      const base = currentExpiry > Date.now() ? currentExpiry : Date.now();
      const newExpiry = new Date(base + addDays * 24 * 3600 * 1000).toISOString();
      db.updateKey(targetKey, { expires_at: newExpiry, status: 'active' });
      return sendJson(res, 200, { ok: true, expires_at: newExpiry });
    }
  }

  const deleteKeyMatch = pathname.match(/^\/api\/admin\/keys\/([^/]+)$/);
  if (deleteKeyMatch && req.method === 'DELETE') {
    const targetKey = decodeURIComponent(deleteKeyMatch[1]);
    db.deleteKey(targetKey);
    broadcastEvent('logout', { key: targetKey });
    return sendJson(res, 200, { ok: true });
  }

  if (pathname === '/api/admin/maintenance' && req.method === 'POST') {
    const body = await parseJsonBody(req);
    const updated = db.setMaintenance({
      enabled: typeof body.enabled === 'boolean' ? body.enabled : false,
      blocked: typeof body.blocked === 'boolean' ? body.blocked : false,
      allowed_logins: Array.isArray(body.allowed_logins) 
        ? body.allowed_logins 
        : (body.allowed_logins || '').split(',').map(s => s.trim()).filter(Boolean),
      title: body.title || 'maintenance',
      message: body.message || "we're doing maintenance. everything is paused until we're back."
    });

    broadcastEvent('maintenance', updated.maintenance);
    return sendJson(res, 200, { ok: true, maintenance: updated.maintenance });
  }

  let filePath;

  if (pathname === '/admin' || pathname === '/admin/' || pathname === '/admin/index.html') {
    filePath = path.join(ROOT_DIR, 'public', 'admin.html');
  } else if (pathname === '/admin/admin.js' || pathname === '/admin.js') {
    filePath = path.join(ROOT_DIR, 'public', 'admin.js');
  } else if (pathname === '/' || pathname === '/index.html') {
    filePath = path.join(ROOT_DIR, 'index.html');
  } else if (pathname.startsWith('/src/')) {
    filePath = path.join(ROOT_DIR, pathname);
  } else {
    const cleanPath = pathname.startsWith('/') ? pathname.slice(1) : pathname;
    const pubPath = path.join(ROOT_DIR, 'public', cleanPath);
    const rootPath = path.join(ROOT_DIR, cleanPath);
    
    if (cleanPath === '' || cleanPath === 'index.html') {
      filePath = path.join(ROOT_DIR, 'index.html');
    } else if (fs.existsSync(pubPath)) {
      filePath = pubPath;
    } else if (fs.existsSync(rootPath)) {
      filePath = rootPath;
    } else {
      filePath = path.join(ROOT_DIR, 'index.html');
    }
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Internal Server Error');
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n==============================================`);
  console.log(`🚀 POWER UP Core System running on:`);
  console.log(`👉 Client Portal: http://localhost:${PORT}/`);
  console.log(`👉 Admin Panel:   http://localhost:${PORT}/admin`);
  console.log(`==============================================\n`);
});