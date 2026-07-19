/**
 * HTTP Analyzer Pro - Ultimate Merged Edition (Cloudflare Pages Edge Serverless)
 * 自动双语 / 深度真实指纹采集 / 工业级风控检测全面融合版
 * 
 * Version: v1.9.46 (Physical Layer Accuracy & Anti-Spoofing Edition)
 * Deployment: Cloudflare Workers / Pages (_worker.js)
 * Changelog: 
 * - [v1.9.46] Extreme Proxy Accuracy / L4 TCP RTT Heuristics / TLS-UA Mismatch / Probe Latency Profiling
 * - [v1.9.45] Chunked WAF GC / Idle-Frame Scheduler / Deep Proxy SandBox Detection
 */

// ==================== 0. Military-Grade Core (Isolate Edge WAF) ====================
const wafCache = new Map();

// Optimized Background GC: Chunked execution to prevent V8 main thread blocking during mass CC attacks
async function cleanupWafBackground() {
    const now = Date.now();
    let deletedCount = 0;
    
    // Chunked iteration (Max 1000 items per GC cycle to keep CPU < 10ms)
    for (const [ip, record] of wafCache.entries()) {
        if (now - record.ts > 60000) {
            wafCache.delete(ip);
            deletedCount++;
        }
        if (deletedCount >= 1000) break;
    }
    
    // Absolute brute-force fallback for extreme bloating
    if (wafCache.size > 10000) wafCache.clear();
}

function wafCheck(ip, ctx) {
    const now = Date.now();
    const limit = 150; // Enterprise max requests per minute

    // Non-blocking WAF eviction via ctx.waitUntil (Offloaded to Edge microtasks)
    if (wafCache.size > 3000) {
        ctx.waitUntil(cleanupWafBackground());
    }

    const record = wafCache.get(ip);
    if (!record || now - record.ts > 60000) {
        wafCache.set(ip, { hits: 1, ts: now });
        return true;
    } 
    
    record.hits++;
    return record.hits <= limit;
}

// Crypto hashing for backend (Optimized ArrayBuffer transformation)
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    let result = '';
    for (let i = 0; i < hashArray.length; i++) {
        result += hashArray[i].toString(16).padStart(2, '0');
    }
    return result;
}

// ==================== 1. IP 分析与代理处理 (CF Native Optimized) ====================
function getAllClientIPs(request) {
    const headers = request.headers;
    const realClientIP = headers.get('cf-connecting-ip') || headers.get('x-real-ip') || 'Unknown';
    
    const ipSources = [
        ['X-Forwarded-For', headers.get('x-forwarded-for')],
        ['X-Real-IP', headers.get('x-real-ip')],
        ['True-Client-IP', headers.get('true-client-ip')],
        ['Proxy-Client-IP', headers.get('proxy-client-ip')],
        ['WL-Proxy-Client-IP', headers.get('wl-proxy-client-ip')],
        ['HTTP_X_CLUSTER_CLIENT_IP', headers.get('x-cluster-client-ip')],
        ['Forwarded', headers.get('forwarded')]
    ];

    let allIPs = {};
    let headerSpoofingSuspected = false;
    let proxyHopsDetected = false;

    // Fast loop replacing forEach for V8 optimization
    for (let i = 0; i < ipSources.length; i++) {
        const header = ipSources[i][0];
        const value = ipSources[i][1];
        if (!value) continue;
        
        let ips = [];
        if (header === 'Forwarded') {
            const matches = value.match(/for=(?:"?\[?([^\];",]+)\]?"?)/ig);
            if (matches) {
                for (let j = 0; j < matches.length; j++) {
                    ips.push(matches[j].replace(/for=/i, '').replace(/["[\]]/g, '').trim());
                }
            }
        } else {
            const parts = value.split(',');
            for (let j = 0; j < parts.length; j++) {
                ips.push(parts[j].trim());
            }
        }

        for (let j = 0; j < ips.length; j++) {
            const ip = ips[j];
            if (ip) {
                if (!allIPs[header]) allIPs[header] = [];
                allIPs[header].push(ip);
                
                // CF Edge Adaptation: Ignore exact match with CF-Connecting-IP
                // If any IP in the chain differs from the real IP, there is an external proxy hop before CF.
                if (ip !== realClientIP) {
                    proxyHopsDetected = true;
                }
            }
        }
    }

    // Detect if CF-Connecting-IP is missing but X-Forwarded-For exists (Edge Gateway Spoofing)
    if (!headers.has('cf-connecting-ip') && headers.has('x-forwarded-for')) {
        headerSpoofingSuspected = true;
    }

    return {
        real_client_ip: realClientIP,
        all_sources: allIPs,
        remote_addr: realClientIP,
        is_header_spoofed: headerSpoofingSuspected,
        proxy_hops: proxyHopsDetected
    };
}

function detectAdvancedProxy(request) {
    // Exclude standard CF Headers, rigorously expanded for cloud/microservices leak detection (v1.9.46)
    const proxyHeaders = [
        'via', 'proxy-connection', 'x-proxy-id', 'surrogate-capability', 
        'x-bluecoat-via', 'x-squid-error', 'x-proxyuser-ip', 'x-arr-log-id', 
        'x-router', 'x-cache-lookup', 'x-gateway-domain', 'x-network-info', 
        'x-forwarded-server', 'x-forwarded-host', 'max-forwards', 
        'x-proxy-authorization', 'x-original-url', 'x-original-forwarded-for',
        'x-amzn-trace-id', 'x-b3-traceid', 'x-host', 'x-originating-ip', 'x-client-ip'
    ];
    let detected = [];
    for (let i = 0; i < proxyHeaders.length; i++) {
        if (request.headers.has(proxyHeaders[i])) {
            detected.push(proxyHeaders[i].toUpperCase());
        }
    }
    return detected;
}

async function getIpContextClassification(ip, cfData, ctx) {
    let result = {
        type: 'Unknown', ptr: 'N/A', is_datacenter: false,
        is_mobile: false, is_proxy: false, isp: 'Unknown', 
        country_code: 'Unknown', asn: 'Unknown', timezone: 'Unknown'
    };

    if (cfData) {
        if (cfData.country) result.country_code = cfData.country;
        if (cfData.asn) result.asn = 'AS' + cfData.asn;
        if (cfData.timezone) result.timezone = cfData.timezone;
        if (cfData.asOrganization) result.isp = cfData.asOrganization;
    }

    const cacheUrl = `https://ipwho.is/${ip}`;
    const cacheKey = new Request(cacheUrl, { headers: { 'Accept': 'application/json' } });
    const cache = caches.default;
    let response = await cache.match(cacheKey);

    if (!response) {
        try {
            // Hard timeout via AbortSignal to guarantee Edge TTFB
            response = await fetch(cacheKey, { 
                cf: { cacheTtl: 86400 },
                signal: AbortSignal.timeout(300) 
            });
            if (response.ok) {
                ctx.waitUntil(cache.put(cacheKey, response.clone()));
            }
        } catch (e) {
            response = null; // Graceful degradation to cfData
        }
    }

    if (response && response.ok) {
        try {
            const data = await response.json();
            if (data.success) {
                result.isp = data.connection?.isp || result.isp;
                result.country_code = data.country_code || result.country_code;
                result.asn = data.connection?.asn ? 'AS' + data.connection.asn : result.asn;
                result.timezone = data.timezone?.id || result.timezone;
                
                const org = (data.connection?.org || '').toLowerCase();
                const domain = (data.connection?.domain || '').toLowerCase();
                
                const dcKeywords = ['cloud', 'datacenter', 'hosting', 'vps', 'amazon', 'google', 'microsoft', 'digitalocean', 'linode', 'hetzner', 'ovh', 'alibaba', 'tencent', 'cdn', 'icloud private relay', 'palo alto', 'fastly', 'akamai', 'choopa', 'leaseweb', 'squarespace', 'myrepublic', 'tzulo', 'vultr', 'dedi', 'colocrossing', 'quadranet'];
                
                for (let i = 0; i < dcKeywords.length; i++) {
                    if (org.includes(dcKeywords[i]) || domain.includes(dcKeywords[i])) {
                        result.is_datacenter = true; break;
                    }
                }
                if (data.security) {
                    result.is_proxy = data.security.proxy || data.security.vpn || data.security.tor;
                }
                const typeLower = (data.connection?.type || '').toLowerCase();
                if (typeLower.includes('cellular') || typeLower.includes('mobile')) {
                    result.is_mobile = true;
                }
            }
        } catch(e) {}
    }

    if (result.is_proxy) { result.type = 'VPN / Proxy / TOR Node'; } 
    else if (result.is_datacenter) { result.type = 'Datacenter / Hosting / CDN'; } 
    else if (result.is_mobile) { result.type = 'Cellular / Mobile Network'; } 
    else { result.type = 'ISP / Residential (Broadband)'; }

    return result;
}

function evaluateProxyRiskMatrix(ipInfo, advancedProxies, ipContext, request) {
    let dimensions = {
        'headers': {level: 'safe', en: 'HTTP Headers Clean', zh: '未发现代理应用层特征头'},
        'network': {level: 'safe', en: 'IP/ASN Ownership Clean', zh: 'IP归属无数据中心/代理记录'},
        'routing': {level: 'safe', en: 'Direct Routing Node', zh: '请求源直接到达无中继迹象'}
    };
    
    let score = 0;

    // Smart Gateway Exemption Logic for CF Pages
    if (ipInfo.is_header_spoofed) {
        dimensions['headers'] = {level: 'danger', en: 'CRITICAL: Header Spoofing / Untrusted Gateway', zh: '高危：检测到边缘节点请求源伪造 (非受信网关透传)'};
        score += 55;
    } else if (ipInfo.proxy_hops || advancedProxies.length > 0) {
        dimensions['headers'] = {level: 'warning', en: 'Proxy Gateway / Multi-Hop Headers Detected', zh: '检测到代理网关/多层转发头特征'};
        score += 35;
    } else if (!request.headers.get('accept-language') || !request.headers.get('user-agent')) {
        dimensions['headers'] = {level: 'warning', en: 'Anomalous Request Headers', zh: '头部缺失标准浏览器标识(高疑)'};
        score += 15;
    }

    if (ipContext.is_proxy) {
        dimensions['network'] = {level: 'danger', en: 'Known VPN/TOR/Proxy DB Match', zh: '情报库确认此IP为高匿名代理/Tor/VPN'};
        score += 45;
    } else if (ipContext.is_datacenter) {
        dimensions['network'] = {level: 'warning', en: 'Datacenter / Cloud Provider IP', zh: '流量来源于机房/云服务器 (疑似搭建节点)'};
        score += 25;
    }

    if (ipInfo.real_client_ip !== ipInfo.remote_addr && ipInfo.remote_addr !== 'Unknown') {
        dimensions['routing'] = {level: 'danger', en: 'IP Topology / Tunneling Mismatch', zh: '穿透识别：真实IP与直连握手IP不符'};
        score += 30;
    }
    
    const forwardedProto = request.headers.get('x-forwarded-proto') || '';
    if (forwardedProto.toLowerCase() === 'https' && !request.url.startsWith('https://')) {
        dimensions['tls_term'] = {level: 'warning', en: 'TLS Proxy Termination Detected', zh: '协议中止：内网为HTTP且外层为HTTPS (反向代理)'};
        score += 20;
    }

    // [v1.9.46] Physical Layer RTT Anomaly Detection (Defeats L7 spoofers)
    const tcpRtt = request.cf?.clientTcpRtt || 0;
    if (tcpRtt > 0 && tcpRtt <= 15 && !ipContext.is_datacenter && (ipContext.is_mobile || ipContext.type.includes('Residential'))) {
        dimensions['rtt'] = {level: 'warning', en: 'L4 TCP RTT Anomaly (Proxy Tunnel)', zh: '延时异动：家庭/移动网络测得极低底层TCP RTT(疑似同城代理中转)'};
        score += 25;
    }

    // [v1.9.46] TLS vs User-Agent Mismatch Heuristics
    const tlsVersion = request.cf?.tlsVersion || '';
    const ua = request.headers.get('user-agent') || '';
    if (tlsVersion === 'TLSv1.2' && /Chrome\/(1[1-9][0-9]|2[0-9]{2})/.test(ua) && !ua.includes('Mobile')) {
        dimensions['tls_ua'] = {level: 'warning', en: 'TLS Downgrade / UA Mismatch', zh: '特征异常：极新版现代浏览器发生底层TLS降级(高度疑似MITM代理/指纹伪装)'};
        score += 20;
    }

    return { score: Math.min(score, 100), matrix: dimensions };
}

// Escaper helper (Optimized Dictionary RegExp mapping)
const escapeHTML = (str) => {
    if (!str) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' };
    return String(str).replace(/[&<>'"]/g, match => map[match]);
};

// ==================== EDGE HTML TEMPLATE ====================
// Utilizing safe replacement tokens to guarantee 100% downstream JS compatibility
const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Analyzer</title>
    <!-- Resource Hint & Preload Optimizations (v1.9.46 Edge) -->
    <link rel="preconnect" href="https://cdn.tailwindcss.com" crossorigin>
    <link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin>
    <link rel="dns-prefetch" href="https://cdn.tailwindcss.com">
    <link rel="dns-prefetch" href="https://cdnjs.cloudflare.com">

    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js" integrity="sha512-ElRFoEQdI5Ht6kZvyzXhYG9NqjtkmlkfYkOwlVN80214E9qOEq1Oos3aM6Pz26Bv2B11wK/81xU2pA8bL+BwQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script>tailwind.config = { darkMode: 'class', theme: { extend: { colors: { darkbg: '#0f172a', cardbg: '#1e293b', bordercol: '#334155' } } } }</script>
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; }
        body.lang-zh .en-only { display: none !important; } body.lang-en .zh-only { display: none !important; }
        
        #ha-preloader { position: fixed; inset: 0; z-index: 99999; background: #0f172a; display: flex; flex-direction: column; align-items: center; justify-content: center; transition: opacity 0.6s cubic-bezier(0.4, 0, 0.2, 1), visibility 0.6s; backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
        #ha-preloader.loaded { opacity: 0; visibility: hidden; pointer-events: none; }
        .loader-spinner { width: 56px; height: 56px; border: 4px solid #1e293b; border-top-color: #38bdf8; border-bottom-color: #818cf8; border-radius: 50%; animation: spin 1s linear infinite; }
        .loader-text { margin-top: 1.5rem; color: #38bdf8; font-family: ui-monospace, monospace; font-size: 0.875rem; letter-spacing: 0.15em; animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; font-weight: 600; text-shadow: 0 0 10px rgba(56, 189, 248, 0.3); }
        @keyframes spin { 100% { transform: rotate(360deg); } }

        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; padding: 1.25rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); transition: transform 0.2s ease, box-shadow 0.2s ease; }
        .card:hover { box-shadow: 0 10px 15px -3px rgba(0,0,0,0.2); }
        .card-header { font-size: 1.125rem; font-weight: 600; color: #38bdf8; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center; }
        .kv-row { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px dashed #334155; font-size: 0.875rem; transition: background-color 0.2s; }
        .kv-row:hover { background-color: rgba(30, 41, 59, 0.5); }
        .kv-row:last-child { border-bottom: none; }
        .kv-key { color: #94a3b8; flex-shrink: 0; padding-right: 12px; }
        .kv-val { color: #e2e8f0; font-family: ui-monospace, monospace; word-break: break-all; text-align: right; max-width: 75%; line-height: 1.5; }
        .badge { padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 600; display: inline-block; margin: 2px 4px 2px 0; word-break: keep-all; }
        .badge-green { background-color: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }
        .badge-red { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
        .badge-yellow { background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }
        .badge-purple { background-color: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
        .badge-indigo { background-color: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.4); }
        .badge-sky { background-color: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }
        .lang-btn { background: #334155; border-radius: 0.5rem; padding: 0.25rem 0.75rem; cursor: pointer; font-size: 0.875rem; transition: background 0.2s; }
        .lang-btn:hover { background: #475569; }

        .network-card { background: rgba(30, 41, 59, 0.7); border: 1px solid #334155; border-radius: 0.75rem; padding: 1rem; position: relative; overflow: hidden; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        .network-card:hover { transform: translateY(-3px); border-color: #38bdf8; box-shadow: 0 6px 16px rgba(56, 189, 248, 0.15); }
        .network-card.has-flag-badge::after { content: ''; position: absolute; bottom: -15px; right: -10px; width: 100px; height: 70px; background-image: var(--flag-badge-url); background-size: cover; background-position: center; filter: blur(4px) opacity(0.15); transform: rotate(15deg); pointer-events: none; z-index: 0; }
        .status-indicator { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; transition: background-color 0.3s; }
        .status-loading { background: #fbbf24; box-shadow: 0 0 5px #fbbf24; animation: pulse 1.5s infinite; }
        .status-success { background: #10b981; box-shadow: 0 0 5px #10b981; }
        .status-error { background: #ef4444; box-shadow: 0 0 5px #ef4444; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

        #ipDetailModal { display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.65); backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px); z-index: 50; align-items: center; justify-content: center; padding: 1rem; transition: opacity 0.3s ease; }
        #ipDetailModal.show { display: flex; animation: modalFadeIn 0.3s ease-out forwards; }
        @keyframes modalFadeIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
        .ip-modal-content { background: #1e293b; border: 1px solid #334155; border-radius: 1rem; width: 100%; max-width: 800px; max-height: 90vh; overflow-y: auto; position: relative; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6); }
        .ip-modal-header { padding: 1.25rem 1.5rem; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; background: #1e293b; z-index: 10; }
        .ip-modal-body { padding: 0; display: flex; flex-direction: column; }
        .ip-modal-map { height: 250px; background: #0f172a; width: 100%; border-bottom: 1px solid #334155; }
        .ip-modal-grid { display: grid; grid-template-columns: 1fr; gap: 1.5rem; padding: 1.5rem; }
        @media (min-width: 768px) { .ip-modal-grid { grid-template-columns: 1fr 1fr; } }
        .ip-detail-card { background: rgba(15, 23, 42, 0.5); border-radius: 0.75rem; padding: 1rem; border: 1px solid #334155; transition: border-color 0.2s; }
        .ip-detail-card:hover { border-color: #475569; }
        .ip-detail-row { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px dashed #334155; font-size: 0.85rem; }
        .ip-detail-row:last-child { border-bottom: none; }
        
        .leaflet-popup-content-wrapper, .leaflet-popup-tip { background: #1e293b !important; color: #f8fafc !important; border: 1px solid #334155; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5) !important; }
        .leaflet-container { background: #0f172a !important; }
        .leaflet-tile-pane { filter: invert(100%) hue-rotate(180deg) brightness(0.85) contrast(1.1) !important; }
    </style>
</head>
<body class="lang-en" id="app-body">

<div id="ha-preloader">
    <div class="loader-spinner"></div>
    <div class="loader-text">
        <span class="en-only">INITIALIZING HTTP ANALYZER CORE...</span>
        <span class="zh-only">正在初始化指纹侦测引擎...</span>
    </div>
</div>

<div class="p-4 md:p-8 max-w-[1400px] mx-auto space-y-6">

    <div class="flex flex-col md:flex-row justify-between items-center bg-gradient-to-r from-blue-900 to-indigo-900 p-6 rounded-xl border border-blue-700 shadow-lg relative">
        <div>
            <h1 class="text-3xl font-bold text-white tracking-tight">
                <span class="en-only">HTTP Analyzer</span><span class="zh-only">HTTP 指纹分析</span>
            </h1>
            <p class="text-blue-200 mt-1">
                <span class="en-only">Routing Intelligence Ready</span>
                <span class="zh-only">客户端分流探测</span>
            </p>
        </div>
        <div class="mt-4 md:mt-0 text-right flex flex-col items-end gap-2">
            <button onclick="toggleLang()" class="lang-btn text-white mb-1">🌐 EN / 中文</button>
            <div class="text-sm text-blue-200 flex items-center gap-2">
                <span class="en-only">Device Profile ID (SHA-256):</span><span class="zh-only">设备统一画像 (SHA-256):</span> 
                <span class="font-mono text-emerald-400 bg-slate-800 px-2 py-1 rounded min-w-[280px] text-center" id="unified-profile-id"><span class="animate-pulse">Hashing...</span></span>
            </div>
        </div>
    </div>

    <div id="proxy-radar-container" class="flex flex-col md:flex-row justify-between items-center p-5 rounded-xl border bg-slate-800 border-slate-700 shadow-sm transition-colors duration-500">
        <div class="flex items-start md:items-center gap-4 flex-col md:flex-row">
            <div class="p-3 rounded-full bg-slate-700 hidden md:block">
                <svg id="proxy-radar-icon" class="w-7 h-7 text-sky-400 transition-colors duration-500 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"></path>
                </svg>
            </div>
            <div>
                <h2 class="text-lg font-bold text-sky-400 transition-colors duration-500" id="proxy-radar-state-title">
                    <span class="en-only animate-pulse">Endpoint–Cloud Bidirectional Proxy Intelligence: Evaluating...</span>
                    <span class="zh-only animate-pulse">端云双向代理雷达：评估中...</span>
                </h2>
                <div class="text-sm mt-1 flex gap-x-4 gap-y-2 flex-wrap" id="proxy-radar-matrix">
                    __PROXY_RADAR_MATRIX__
                </div>
            </div>
        </div>
        <div class="mt-4 md:mt-0 text-left md:text-right border-t border-slate-700/50 md:border-0 pt-3 md:pt-0 w-full md:w-auto">
            <div class="text-3xl font-black text-sky-400 tracking-tighter transition-colors duration-500" id="proxy-radar-score-display">__RADAR_SCORE__<span class="text-lg font-normal text-slate-500">/100</span></div>
            <div class="text-[0.75rem] font-bold text-slate-400 uppercase tracking-widest mt-1"><span class="en-only">Fusion Threat Index</span><span class="zh-only">端云融合穿透指数</span></div>
        </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div class="card flex flex-col justify-center">
            <p class="text-sm text-slate-400"><span class="en-only">Client HTTP IP</span><span class="zh-only">HTTP 客户端 IP</span></p>
            <div class="flex justify-between items-center mt-1">
                <p class="text-xl font-mono font-bold text-white" id="main-client-ip">__CLIENT_IP__</p>
                <span class="badge __IPV6_BADGE_CLASS__">__IPV6_TEXT__</span>
            </div>
            <hr class="border-[#334155] my-3">
            <p class="text-sm text-slate-400"><span class="en-only">Network Intelligence (ASN)</span><span class="zh-only">网络智能与 ASN</span></p>
            <div class="flex justify-between items-center mt-1 mb-1">
                <p class="text-[0.95rem] font-bold text-white">
                    <span class="en-only">__IP_TYPE_EN__</span>
                    <span class="zh-only">__IP_TYPE_ZH__</span>
                </p>
                <span class="badge __PROXY_BADGE_CLASS__"><span class="en-only">__PROXY_TEXT_EN__</span><span class="zh-only">__PROXY_TEXT_ZH__</span></span>
            </div>
            <p class="text-xs text-blue-300 font-mono truncate" title="__ISP__">__ASN__ | __ISP__</p>
        </div>
        
        <div class="card flex flex-col items-center justify-center relative">
            <h3 class="card-header w-full"><span class="en-only">ML Behavior Risk Score</span><span class="zh-only">非线性行为风控评分</span></h3>
            <div class="w-32 h-32 relative">
                <canvas id="riskChart"></canvas>
                <div class="absolute inset-0 flex flex-col items-center justify-center pt-5 pointer-events-none"><span id="risk-chart-number" class="text-2xl font-bold animate-pulse">...</span></div>
            </div>
            <div id="risk-level-badge" class="badge bg-slate-700 mt-2 border-0">...</div>
        </div>

        <div class="card col-span-1 md:col-span-2">
            <h3 class="card-header text-red-400">
                <span class="en-only">Correlation Engine Trigger Details</span><span class="zh-only">多维特征风控触发详情</span>
            </h3>
            <div id="risk-details-container" class="max-h-36 overflow-y-auto pr-2 custom-scrollbar">
                __RISK_DETAILS__
            </div>
        </div>
    </div>
    
    <div class="card col-span-1 md:col-span-4" id="client-routing-module">
        <h3 class="card-header text-blue-400">
            <span>🌍 <span class="en-only">Client-Side Routing Intelligence (Split Tunneling)</span><span class="zh-only">当前网络信息 (客户端分流探测)</span></span>
        </h3>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-2">
            <div class="network-card bg-slate-800 border border-slate-700 rounded-xl p-4 relative overflow-hidden" id="card-ipip">
                <div class="relative z-10 flex flex-col h-full">
                    <div class="flex items-center gap-2 mb-3">
                        <span class="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse status-indicator" id="status-ipip"></span>
                        <span class="font-bold text-sm text-slate-200"><span class="en-only">Domestic Test</span><span class="zh-only">国内测试</span></span>
                        <span class="text-[0.7rem] text-sky-400 ml-auto" id="prov-ipip"><span class="animate-pulse">Detecting...</span></span>
                    </div>
                    <div class="font-mono font-bold text-[1.05rem] text-sky-400 cursor-pointer flex items-center group" id="val-ipip" data-type="ip" onclick="ClientRouteProber.showDetails(this)">
                        <span class="animate-pulse">Loading...</span>
                        <span class="text-sm opacity-50 group-hover:opacity-100 transition-opacity ml-2">🔍</span>
                    </div>
                    <div class="flex items-center gap-2 mt-2 text-sm text-slate-400 h-5" id="loc-ipip" data-type="location">---</div>
                    <div class="mt-auto pt-4 text-[0.65rem] text-slate-500">
                        <span class="en-only">· IP used for mainland China sites</span><span class="zh-only">· 您访问国内站点所使用的IP</span>
                    </div>
                </div>
            </div>
            <div class="network-card bg-slate-800 border border-slate-700 rounded-xl p-4 relative overflow-hidden" id="card-overseas">
                <div class="relative z-10 flex flex-col h-full">
                    <div class="flex items-center gap-2 mb-3">
                        <span class="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse status-indicator" id="status-overseas"></span>
                        <span class="font-bold text-sm text-slate-200"><span class="en-only">Overseas Test</span><span class="zh-only">国外测试</span></span>
                        <span class="text-[0.7rem] text-sky-400 ml-auto" id="prov-overseas"><span class="animate-pulse">Detecting...</span></span>
                    </div>
                    <div class="font-mono font-bold text-[1.05rem] text-sky-400 cursor-pointer flex items-center group" id="val-overseas" data-type="ip" onclick="ClientRouteProber.showDetails(this)">
                        <span class="animate-pulse">Loading...</span>
                        <span class="text-sm opacity-50 group-hover:opacity-100 transition-opacity ml-2">🔍</span>
                    </div>
                    <div class="flex items-center gap-2 mt-2 text-sm text-slate-400 h-5" id="loc-overseas" data-type="location">---</div>
                    <div class="mt-auto pt-4 text-[0.65rem] text-slate-500">
                        <span class="en-only">· IP used for global unblocked sites</span><span class="zh-only">· 您访问没有被封的国外站点所使用的IP</span>
                    </div>
                </div>
            </div>
            <div class="network-card bg-slate-800 border border-slate-700 rounded-xl p-4 relative overflow-hidden" id="card-cf">
                <div class="relative z-10 flex flex-col h-full">
                    <div class="flex items-center gap-2 mb-3">
                        <span class="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse status-indicator" id="status-cf"></span>
                        <span class="font-bold text-sm text-slate-200">Cloudflare</span>
                        <span class="text-[0.7rem] text-emerald-400 ml-auto" id="prov-cf">ProxyIP / v4</span>
                    </div>
                    <div class="font-mono font-bold text-[1.05rem] text-sky-400 cursor-pointer flex items-center group" id="val-cf" data-type="ip" onclick="ClientRouteProber.showDetails(this)">
                        <span class="animate-pulse">Loading...</span>
                        <span class="text-sm opacity-50 group-hover:opacity-100 transition-opacity ml-2">🔍</span>
                    </div>
                    <div class="flex items-center gap-2 mt-2 text-sm text-slate-400 h-5" id="loc-cf" data-type="location">---</div>
                    <div class="mt-auto pt-4 text-[0.65rem] text-slate-500">
                        <span class="en-only">· Landing IP for CF CDN sites</span><span class="zh-only">· 您访问CFCDN站点所使用的落地IP</span>
                    </div>
                </div>
            </div>
            <div class="network-card bg-slate-800 border border-slate-700 rounded-xl p-4 relative overflow-hidden" id="card-outside">
                <div class="relative z-10 flex flex-col h-full">
                    <div class="flex items-center gap-2 mb-3">
                        <span class="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse status-indicator" id="status-outside"></span>
                        <span class="font-bold text-sm text-slate-200"><span class="en-only">Outside GFW</span><span class="zh-only">墙外测试</span></span>
                        <span class="text-[0.7rem] text-sky-400 ml-auto" id="prov-outside">Google/X</span>
                    </div>
                    <div class="font-mono font-bold text-[1.05rem] text-sky-400 cursor-pointer flex items-center group" id="val-outside" data-type="ip" onclick="ClientRouteProber.showDetails(this)">
                        <span class="animate-pulse">Loading...</span>
                        <span class="text-sm opacity-50 group-hover:opacity-100 transition-opacity ml-2">🔍</span>
                    </div>
                    <div class="flex items-center gap-2 mt-2 text-sm text-slate-400 h-5" id="loc-outside" data-type="location">---</div>
                    <div class="mt-auto pt-4 text-[0.65rem] text-slate-500">
                        <span class="en-only">· IP used for blocked sites (e.g., Google)</span><span class="zh-only">· 您访问墙外站点所使用的IP</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <h3 class="card-header text-emerald-400">
            <span><span class="en-only">Proxy Topology & Geo-Routing Graph</span><span class="zh-only">代理层拓扑与全景路由图谱</span></span>
            <span class="badge bg-slate-700 text-xs text-white border-0">Multi-Node Consensus</span>
        </h3>
        <div id="egress-info-container" class="space-y-3 max-h-64 overflow-y-auto pr-2 custom-scrollbar">
            <div class="text-sm text-slate-500 animate-pulse">
                <span class="en-only">Probing Deep Egress Tunnels & Topology...</span>
                <span class="zh-only">正在深层探测隧道出口与拓扑...</span>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div class="card p-4"><h3 class="card-header text-xs mb-2">Canvas FP</h3><div class="text-[0.65rem] font-mono text-center text-emerald-400 break-all" id="hash-canvas"><span class="animate-pulse opacity-75">Wait..</span></div></div>
        <div class="card p-4"><h3 class="card-header text-xs mb-2">WebGL FP</h3><div class="text-[0.65rem] font-mono text-center text-purple-400 break-all" id="hash-webgl"><span class="animate-pulse opacity-75">Wait..</span></div></div>
        <div class="card p-4"><h3 class="card-header text-xs mb-2 border-amber-400 text-amber-300">AudioContext FP</h3><div class="text-[0.65rem] font-mono text-center text-amber-400 break-all" id="hash-audio"><span class="animate-pulse opacity-75">Wait..</span></div></div>
        <div class="card p-4"><h3 class="card-header text-xs mb-2 border-pink-400 text-pink-300">FontMetrics FP</h3><div class="text-[0.65rem] font-mono text-center text-pink-400 break-all" id="hash-font"><span class="animate-pulse opacity-75">Wait..</span></div></div>
        <div class="card p-4"><h3 class="card-header text-xs mb-2 border-sky-400 text-sky-300">DOMRect FP</h3><div class="text-[0.65rem] font-mono text-center text-sky-400 break-all" id="hash-domrect"><span class="animate-pulse opacity-75">Wait..</span></div></div>
        <div class="card p-4"><h3 class="card-header text-xs mb-2 border-indigo-400 text-indigo-300">Pseudo-TLS FP</h3><div class="text-[0.65rem] font-mono text-center text-indigo-400 break-all" title="__PSEUDO_TLS_STR__">__PSEUDO_TLS_HASH__</div></div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="card"><h3 class="card-header"><span class="en-only">Hardware & Display</span><span class="zh-only">硬件与显示探针</span><span class="badge bg-slate-700 text-xs border-0">JS</span></h3><div id="hardware-info-container"><div class="text-sm text-slate-500 animate-pulse">Initializing...</div></div></div>
        <div class="card"><h3 class="card-header"><span class="en-only">WebRTC & Network Leak</span><span class="zh-only">WebRTC 与底层网络泄漏</span><span class="badge badge-purple text-xs">Deep</span></h3><div id="sensor-info-container"><div class="text-sm text-slate-500 animate-pulse">Initializing...</div></div></div>
        <div class="card"><h3 class="card-header"><span class="en-only">Consistency Matrix</span><span class="zh-only">一致性校验矩阵</span><span class="badge badge-indigo text-xs">Calibration</span></h3><div id="browser-info-container"><div class="text-sm text-slate-500 animate-pulse">Initializing...</div></div></div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="card">
            <h3 class="card-header"><span class="en-only">Behavior & Anti-Tampering (Zero Trust)</span><span class="zh-only">行为特征与防伪造沙盒</span></h3>
            <div id="behavior-info-container">
                <div class="text-sm text-slate-500 animate-pulse"><span class="en-only">Collecting Behavioral Biometrics...</span><span class="zh-only">正在采集中...</span></div>
            </div>
        </div>
        <div class="card">
            <h3 class="card-header"><span class="en-only">HTTP Headers (Layer 7)</span><span class="zh-only">应用层 HTTP 请求头</span><span class="badge bg-slate-700 text-xs border-0">__HEADERS_COUNT__</span></h3>
            <div class="max-h-64 overflow-y-auto pr-2 custom-scrollbar">
                __HEADERS_LIST__
            </div>
        </div>
    </div>
    
    <div class="mt-8 text-center text-xs text-slate-500 border-t border-slate-800 pt-4 pb-8 space-y-1">
        <div><span class="en-only">Compliance: Data collected is strictly used for security & anti-fraud purposes in accordance with GDPR/CCPA. No PII is permanently stored.</span><span class="zh-only">合规声明：本系统采集之底层网络、设备指纹及生物行为特征仅用于高级风控与反欺诈安全校验，严格遵守数据保护法案，不持久化存储个人隐私数据。</span></div>
        <div class="text-slate-600"><span class="en-only">💡 All information displayed above is provided for reference only and should not be considered definitive.</span><span class="zh-only">💡 以上所获取信息仅供参考！</span></div>
    </div>

</div>

<div id="ipDetailModal" onclick="ClientRouteProber.closeModal(event)">
    <div class="ip-modal-content" onclick="event.stopPropagation()">
        <div class="ip-modal-header">
            <h2 class="text-lg font-bold text-sky-400">🔍 <span class="en-only">IP Detailed Profile</span><span class="zh-only">IP 详细信息</span></h2>
            <button onclick="ClientRouteProber.closeModal()" class="text-slate-400 hover:text-white hover:bg-red-500 rounded-full w-8 h-8 flex items-center justify-center transition-all text-xl">✕</button>
        </div>
        <div class="ip-modal-body">
            <div class="ip-modal-map" id="ip-detail-map"></div>
            <div class="ip-modal-grid">
                <div class="ip-detail-card" id="ip-modal-basic">Loading...</div>
                <div class="ip-detail-card" id="ip-modal-security">Loading...</div>
            </div>
        </div>
    </div>
</div>

<script>
    const removePreloader = () => {
        const preloader = document.getElementById('ha-preloader');
        if (preloader && !preloader.classList.contains('loaded')) {
            preloader.classList.add('loaded');
        }
    };
    
    // Ensure Preloader doesn't permanently lock screen on weak network
    window.addEventListener('load', removePreloader);
    setTimeout(removePreloader, 4000); // 4s ultimate fallback

    const P_CLIENT_IP = document.getElementById('main-client-ip').innerText;
    const SERVER_CC = __JSON_SERVER_CC__;
    const SERVER_TZ = __JSON_SERVER_TZ__;
    const SERVER_ASN = __JSON_SERVER_ASN__;
    const SERVER_DETECTED_IPS = __JSON_DETECTED_IPS__;
    const SERVER_IP_DETAILS = __JSON_IP_DETAILS__;
    const SERVER_BASE_RISK_FACTORS = __JSON_RISK_FACTORS__;
    const SERVER_RTT = parseInt(__JSON_SERVER_RTT__); // [v1.9.46] Physical Layer TCP RTT
    
    let globalRadarScore = parseInt(__JSON_RADAR_SCORE__);
    
    const bodyLang = document.getElementById('app-body');
    const uaGlobal = navigator.userAgent || "";
    
    if(navigator.language.startsWith('zh')) bodyLang.classList.replace('lang-en', 'lang-zh');
    function toggleLang() { bodyLang.classList.replace(bodyLang.classList.contains('lang-en') ? 'lang-en' : 'lang-zh', bodyLang.classList.contains('lang-en') ? 'lang-zh' : 'lang-en'); }

    const escapeHTML = str => { if (!str) return ''; const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }; return String(str).replace(/[&<>'"]/g, m => map[m]); };
    
    // Idle Frame Scheduler to prevent UI locking during heavy biometrics processing
    const executeAsync = (fn) => new Promise(resolve => {
        const wrap = () => { try { resolve(fn()); } catch(e) { resolve('Blocked'); } };
        if (window.requestIdleCallback) requestIdleCallback(wrap, { timeout: 1500 });
        else setTimeout(wrap, 0);
    });

    const sha256 = async (str) => {
        try {
            if (crypto && crypto.subtle) {
                const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
                return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
            }
        } catch(e) {}
        return cyrb53(str);
    };

    const cyrb53 = (str, seed = 0) => { let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed; for (let i = 0, ch; i < str.length; i++) { ch = str.charCodeAt(i); h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677); } h1 = Math.imul(h1 ^ (h1>>>16), 2246822507) ^ Math.imul(h2 ^ (h2>>>13), 3266489909); h2 = Math.imul(h2 ^ (h2>>>16), 2246822507) ^ Math.imul(h1 ^ (h1>>>13), 3266489909); return (4294967296 * (2097151 & h2) + (h1>>>0)).toString(16); };

    const isSameSubnet = (ip1, ip2) => {
        if (!ip1 || !ip2) return false;
        if (ip1 === ip2) return true;
        if (ip1.includes('.') && ip2.includes('.')) {
            const p1 = ip1.split('.'); const p2 = ip2.split('.');
            if (p1.length === 4 && p2.length === 4) return p1[0] === p2[0] && p1[1] === p2[1] && p1[2] === p2[2];
        } else if (ip1.includes(':') && ip2.includes(':')) {
            const p1 = ip1.split(':'); const p2 = ip2.split(':');
            if (p1.length > 2 && p2.length > 2) return p1[0] === p2[0] && p1[1] === p2[1] && p1[2] === p2[2];
        }
        return false;
    };

    const checkNativeTampering = (obj, method) => {
        try {
            if (!obj) return false;
            const desc = Object.getOwnPropertyDescriptor(obj, method);
            if (!desc) return false;
            
            if (desc.get) {
                const str = Function.prototype.toString.call(desc.get);
                if (str.indexOf('[native code]') === -1) return true;
                if (desc.get.toString !== Function.prototype.toString) return true;
            }
            if (desc.value) {
                const str = Function.prototype.toString.call(desc.value);
                if (str.indexOf('[native code]') === -1) return true;
                if (desc.value.toString !== Function.prototype.toString) return true;
            }
            return false;
        } catch (e) { return true; }
    };

    const behaviorEngine = { mouseEvents: 0, mouseTrajectory: [], keyEvents: 0, touchEvents: 0, startTime: Date.now(), anomalies: 0 };
    
    document.addEventListener('mousemove', (e) => {
        behaviorEngine.mouseEvents++;
        if(behaviorEngine.mouseTrajectory.length < 20) {
            behaviorEngine.mouseTrajectory.push({x: e.clientX, y: e.clientY, t: Date.now() - behaviorEngine.startTime});
        }
    }, {passive: true});
    document.addEventListener('keydown', () => behaviorEngine.keyEvents++, {passive: true});
    document.addEventListener('touchstart', () => behaviorEngine.touchEvents++, {passive: true});

    const refreshProxyRadarUI = () => {
        let enText = 'Endpoint–Cloud Bidirectional Proxy Intelligence: Clean (Native)';
        let zhText = '端云双向代理雷达：未检测到代理 (原生直连)';
        let color = 'text-green-400', bg = 'bg-green-900/20 border-green-700';
        
        if (globalRadarScore >= 60) {
            enText = 'Endpoint–Cloud Bidirectional Proxy Intelligence: Confirmed Proxy / VPN / Relay';
            zhText = '端云双向代理雷达：已确认使用 代理 / VPN / 转发';
            color = 'text-red-400'; bg = 'bg-red-900/30 border-red-700';
        } else if (globalRadarScore >= 25) {
            enText = 'Endpoint–Cloud Bidirectional Proxy Intelligence: Suspected Proxy / Relay Node';
            zhText = '端云双向代理雷达：疑似存在 代理 / 数据中心转发';
            color = 'text-amber-400'; bg = 'bg-amber-900/30 border-amber-700';
        }
        
        const titleEl = document.getElementById('proxy-radar-state-title');
        const iconEl = document.getElementById('proxy-radar-icon');
        const scoreEl = document.getElementById('proxy-radar-score-display');
        const containerEl = document.getElementById('proxy-radar-container');
        
        if(titleEl) {
            titleEl.className = \`text-lg font-bold \${color} transition-colors duration-500\`;
            titleEl.innerHTML = \`<span class="en-only">\${escapeHTML(enText)}</span><span class="zh-only">\${escapeHTML(zhText)}</span>\`;
        }
        if(iconEl) iconEl.className = \`w-7 h-7 \${color} transition-colors duration-500\`;
        if(scoreEl) scoreEl.className = \`text-3xl font-black \${color} tracking-tighter transition-colors duration-500\`;
        if(containerEl) containerEl.className = \`flex flex-col md:flex-row justify-between items-center p-5 rounded-xl border \${bg} shadow-sm transition-colors duration-500\`;
    };

    const updateProxyRadar = (scoreAdd, dimId, dimEn, dimZh, level = 'danger') => {
        globalRadarScore = Math.min(globalRadarScore + scoreAdd, 100);
        const matrixEl = document.getElementById('proxy-radar-matrix');
        const colorClass = level === 'danger' ? 'text-red-400' : (level === 'warning' ? 'text-amber-400' : (level === 'sky' ? 'text-sky-400' : 'text-green-400'));
        
        if(matrixEl) {
            matrixEl.innerHTML += \`
                <span class="bg-slate-800/50 px-2 py-1 rounded border border-slate-700/50">
                    <span class="text-slate-400 font-mono">[\${escapeHTML(dimId)}]</span> 
                    <span class="\${colorClass} font-medium">
                        <span class="en-only">\${escapeHTML(dimEn)}</span>
                        <span class="zh-only">\${escapeHTML(dimZh)}</span>
                    </span>
                </span>
            \`;
        }
        const scoreEl = document.getElementById('proxy-radar-score-display');
        if(scoreEl) scoreEl.innerHTML = \`\${globalRadarScore}<span class="text-lg font-normal text-slate-500">/100</span>\`;
        refreshProxyRadarUI();
    };

    const renderData = (containerId, data) => { 
        let htmlBuffer = ''; 
        for (const [key, val] of Object.entries(data)) { 
            let displayKey = key;
            if (key.includes('||')) {
                const parts = key.split('||');
                displayKey = \`<span class="en-only">\${escapeHTML(parts[0])}</span><span class="zh-only">\${escapeHTML(parts[1])}</span>\`;
            } else {
                displayKey = escapeHTML(key);
            }
            htmlBuffer += \`<div class="kv-row"><span class="kv-key">\${displayKey}</span><span class="kv-val">\${val}</span></div>\`; 
        } 
        document.getElementById(containerId).innerHTML = htmlBuffer;
    };

    const isPublicIP = (ip) => {
        if (!ip || ip.includes('.local') || ip === '0.0.0.0' || ip.startsWith('127.') || ip === '::1') return false;
        if (ip.startsWith('192.168.') || ip.startsWith('10.')) return false;
        if (/^172\\.(1[6-9]|2[0-9]|3[0-1])\\./.test(ip)) return false;
        if (/^f[cd][0-9a-f]{2}:/i.test(ip) || /^fe80:/i.test(ip)) return false;
        return true;
    };

    const fetchGeoIP = async (ip) => {
        try { 
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            const res = await fetch(\`https://ip-api.com/json/\${ip}?fields=status,country,regionName,city,org,as\`, { signal: controller.signal });
            clearTimeout(timeoutId);
            if (!res.ok) return null;
            const data = await res.json();
            if (data.status === 'success') {
                return {
                    success: true,
                    country: data.country, region: data.regionName, city: data.city,
                    connection: { org: data.org, asn: data.as ? data.as.split(' ')[0].replace('AS', '') : '' }
                };
            }
        } catch(e) {}
        
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            const res = await fetch(\`https://ipwho.is/\${ip}\`, { signal: controller.signal });
            clearTimeout(timeoutId);
            if (res.ok) return await res.json();
        } catch (e) {}
        return null;
    };

    const fetchWithTimeout = (url, options, timeout = 2500) => Promise.race([fetch(url, options), new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeout))]);
    const fetchTextRace = (urls) => Promise.any(urls.map(u => fetchWithTimeout(u, {}, 2500).then(r => { if(!r.ok) throw 'e'; return r.text(); })));

    const runApiCalibration = async () => {
        const results = { cf: { ip: null, cc: null, asn: null }, geojs: { ip: null, cc: null, asn: null } };
        const [cfRaw, geoRaw] = await Promise.all([
            fetchWithTimeout('https://cloudflare.com/cdn-cgi/trace').then(r => r.text()).catch(() => null),
            fetchWithTimeout('https://get.geojs.io/v1/ip/geo.json').then(r => r.json()).catch(() => null)
        ]);

        if (cfRaw) {
            results.cf.ip = cfRaw.match(/ip=(.+)/)?.[1] || null; 
            results.cf.cc = cfRaw.match(/loc=(.+)/)?.[1] || null;
        }
        if (geoRaw) {
            results.geojs.ip = geoRaw.ip || null; 
            results.geojs.cc = geoRaw.country_code || null;
            if (geoRaw.asn) results.geojs.asn = 'AS' + geoRaw.asn;
        }
        
        if (results.cf.ip && !results.cf.asn) {
            const geo = await fetchGeoIP(results.cf.ip);
            if (geo && geo.connection && geo.connection.asn) results.cf.asn = 'AS' + geo.connection.asn;
        }
        return results;
    };

    const fetchIpifyTunnels = async () => {
        const v4Urls = ['https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://api.ip.sb/ip'];
        const v6Urls = ['https://api6.ipify.org', 'https://ipv6.icanhazip.com', 'https://api-ipv6.ip.sb/ip'];
        const [v4Res, v6Res] = await Promise.all([
            fetchTextRace(v4Urls).catch(() => null),
            fetchTextRace(v6Urls).catch(() => null)
        ]);
        return { v4: v4Res ? v4Res.trim() : null, v6: v6Res ? v6Res.trim() : null };
    };

    const getWebRTCLeakedIPs = async () => {
        return Promise.race([
            new Promise(resolve => {
                const ips = new Set();
                let meta = { blocked: false, udp: false, tcp: false, srflx: false, host: false, relay: false };
                
                try {
                    const RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
                    if (!RTCPeerConnection) {
                        meta.blocked = true;
                        return resolve({ ips: "Unsupported", meta });
                    }
                    
                    const pc = new RTCPeerConnection({ iceServers: [
                        { urls: "stun:stun.qq.com:3478" },           
                        { urls: "stun:stun.cloudflare.com:3478" },   
                        { urls: "stun:stun.l.google.com:19302" }     
                    ]});
                    pc.createDataChannel(""); 
                    
                    const processCandidateStr = (candidateStr) => {
                        const parts = candidateStr.split(' ');
                        if (parts.length >= 8) {
                            const proto = parts[2].toLowerCase();
                            if (proto === 'udp') meta.udp = true;
                            if (proto === 'tcp') meta.tcp = true;
                            
                            const typIdx = parts.indexOf('typ');
                            if (typIdx !== -1) {
                                const typ = parts[typIdx + 1].toLowerCase();
                                if (typ === 'host') meta.host = true;
                                if (typ === 'srflx') meta.srflx = true;
                                if (typ === 'relay') meta.relay = true;
                            }
                            
                            const ip = parts[4];
                            if (ip.endsWith('.local')) { ips.add('mDNS Protected (' + ip + ')'); } 
                            else { ips.add(ip.trim()); }
                        }
                    };

                    pc.onicecandidate = (e) => { 
                        if (e && e.candidate && e.candidate.candidate) {
                            processCandidateStr(e.candidate.candidate);
                        }
                    };
                    
                    pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(() => {
                        meta.blocked = true;
                        resolve({ ips: "Blocked", meta });
                    });
                    
                    pc.createOffer().then(offer => {
                        offer.sdp.split('\\n').forEach(line => {
                            if (line.indexOf('a=candidate:') === 0) {
                                processCandidateStr(line.substring(12));
                            }
                        });
                    }).catch(e => {});

                    setTimeout(() => { 
                        if (ips.size > 0) {
                            resolve({ ips: Array.from(ips), meta }); 
                        } else {
                            resolve({ ips: "None / Obfuscated", meta });
                        }
                    }, 2000);
                } catch (err) { 
                    meta.blocked = true;
                    resolve({ ips: "Blocked", meta }); 
                }
            }),
            new Promise(resolve => setTimeout(() => resolve({ ips: "Timeout / Blocked", meta: { blocked: true, timeout: true } }), 2500))
        ]);
    };

    const runTopologyAnalysis = async (rtcIPsRaw, calib, tunnels, globalAsnMap) => {
        const egressContainer = document.getElementById('egress-info-container');
        const ipNodes = new Map(); 

        const addNode = (ip, tagEn, tagZh, styleClass) => {
            if (!ip || ip === 'Unknown' || ip === 'N/A') return;
            if (!ipNodes.has(ip)) ipNodes.set(ip, new Map());
            const keyJson = JSON.stringify({en: tagEn, zh: tagZh});
            ipNodes.get(ip).set(keyJson, styleClass);
        };

        const checkProxyByAsn = (ip, defaultEn, defaultZh, defaultClass) => {
            const isSubnetMatch = SERVER_DETECTED_IPS.some(sIp => isSameSubnet(ip, sIp));
            if (!isSubnetMatch && isPublicIP(ip) && globalAsnMap[ip] && globalAsnMap[ip] !== 'Unknown' && SERVER_ASN !== 'Unknown' && globalAsnMap[ip] !== SERVER_ASN) {
                return { en: defaultEn + ' (Proxy Divergence)', zh: defaultZh + ' (ASN 代理穿透)', css: 'badge-red' };
            }
            return { en: defaultEn, zh: defaultZh, css: defaultClass };
        };

        for (const [ip, sources] of Object.entries(SERVER_IP_DETAILS)) {
            sources.forEach(src => addNode(ip, src, src, 'badge-slate'));
        }
        
        let hasMatchGlobal = Array.isArray(rtcIPsRaw) && rtcIPsRaw.some(ip => isPublicIP(ip) && (SERVER_DETECTED_IPS.includes(ip) || SERVER_DETECTED_IPS.some(sIp => isSameSubnet(ip, sIp))));

        if (Array.isArray(rtcIPsRaw)) {
            rtcIPsRaw.forEach(ip => {
                if (ip.includes('mDNS Protected')) {
                    addNode(ip, 'Local Obfuscation', '本地 mDNS 混淆', 'badge-purple');
                } else if (isPublicIP(ip)) { 
                    let isMatch = SERVER_DETECTED_IPS.includes(ip) || SERVER_DETECTED_IPS.some(sIp => isSameSubnet(ip, sIp));
                    let asnMismatch = false;
                    
                    if (globalAsnMap[ip]) {
                        const rtcAsn = globalAsnMap[ip];
                        const isSubnetMatch = SERVER_DETECTED_IPS.some(sIp => isSameSubnet(ip, sIp));
                        if (!isSubnetMatch && rtcAsn !== 'Unknown' && SERVER_ASN !== 'Unknown' && rtcAsn !== SERVER_ASN) {
                            asnMismatch = true;
                            isMatch = false; 
                        }
                    }
                    
                    if (asnMismatch) {
                        addNode(ip, 'WebRTC ASN Divergence (Proxy)', 'WebRTC ASN 路由断层 (代理穿透)', 'badge-red');
                    } else if (isMatch) {
                        addNode(ip, 'WebRTC Confirmed', 'WebRTC 真实匹配', 'badge-green'); 
                    } else {
                        if (hasMatchGlobal) {
                            addNode(ip, 'Secondary IP (Dual-Stack)', '辅助 IP (多拨/双栈)', 'badge-sky');
                        } else {
                            addNode(ip, 'WebRTC Leak (Bypass)', 'WebRTC 穿透泄露', 'badge-red');
                        }
                    }
                } else if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip.includes('::1')) {
                    addNode(ip, 'Spoofed Local IP', '伪造本地 IP', 'badge-yellow');
                } else { 
                    addNode(ip, 'Local/LAN', '局域网/内网', 'badge-slate'); 
                }
            });
        }

        if (calib.cf && calib.cf.ip) {
            const t = checkProxyByAsn(calib.cf.ip, 'CF Trace Exit', 'CF 边缘探测节点', 'badge-sky');
            addNode(calib.cf.ip, t.en, t.zh, t.css);
        }
        if (calib.geojs && calib.geojs.ip) {
            const t = checkProxyByAsn(calib.geojs.ip, 'GeoJS Probe Exit', 'GeoJS 探测节点', 'badge-sky');
            addNode(calib.geojs.ip, t.en, t.zh, t.css);
        }
        if (tunnels && tunnels.v4) {
            const t = checkProxyByAsn(tunnels.v4, 'IPv4 Tunnel Exit', 'IPv4 隧道探测出口', 'badge-yellow');
            addNode(tunnels.v4, t.en, t.zh, t.css);
        }
        if (tunnels && tunnels.v6) {
            const t = checkProxyByAsn(tunnels.v6, 'IPv6 Tunnel Exit', 'IPv6 隧道探测出口', 'badge-green');
            addNode(tunnels.v6, t.en, t.zh, t.css);
        }

        let resultHtmlStr = '';
        for (const [ip, tagsMap] of ipNodes.entries()) {
            let tagsHtml = '';
            for (const [tagJson, tagClass] of tagsMap.entries()) {
                let css = tagClass;
                if (tagClass === 'badge-slate') css = 'bg-slate-700 text-slate-300 border border-slate-600';
                
                let tagObj = {en: tagJson, zh: tagJson};
                try { tagObj = JSON.parse(tagJson); } catch(e) {}
                tagsHtml += \`<span class="badge \${css}"><span class="en-only">\${escapeHTML(tagObj.en)}</span><span class="zh-only">\${escapeHTML(tagObj.zh)}</span></span>\`;
            }

            const isMDNS = ip.includes('mDNS');
            const rowId = 'egress-row-' + cyrb53(ip).substring(0, 10);
            
            const enResolving = isMDNS ? '↳ 📍 Local Device Protected' : 'Resolving BGP Topology...';
            const zhResolving = isMDNS ? '↳ 📍 本地设备受隐私保护' : '正在解析 BGP 拓扑路由...';
            
            resultHtmlStr += \`
                <div class="kv-row flex-col items-start border-b border-[#334155] pb-3 mb-3 last:border-0 last:pb-0 last:mb-0">
                    <div class="flex flex-wrap items-center w-full mb-1 gap-y-1">
                        <span class="font-mono text-white font-bold text-[1.05rem] mr-4 max-w-full break-all">\${escapeHTML(ip)}</span>
                        <div class="flex flex-wrap flex-1 items-center">\${tagsHtml}</div>
                    </div>
                    <div class="text-slate-400 text-sm" id="\${rowId}">
                        <span class="\${!isMDNS ? 'animate-pulse' : ''}">
                            <span class="en-only">\${escapeHTML(enResolving)}</span>
                            <span class="zh-only">\${escapeHTML(zhResolving)}</span>
                        </span>
                    </div>
                </div>
            \`;
            
            if (!isMDNS) {
                fetchGeoIP(ip).then(geo => {
                    const geoNode = document.getElementById(rowId);
                    if (!geoNode) return;
                    if (geo && geo.success) {
                        const asn = geo.connection && geo.connection.asn ? \`AS\${geo.connection.asn}\` : (globalAsnMap[ip] && globalAsnMap[ip] !== 'Unknown' ? globalAsnMap[ip] : '');
                        const org = geo.connection && geo.connection.org ? geo.connection.org : '';
                        
                        let asnHtm = \`\${asn} \${org}\`;
                        if (asn && SERVER_ASN !== 'Unknown' && asn !== SERVER_ASN) {
                            const isSubnetMatch = SERVER_DETECTED_IPS.some(sIp => isSameSubnet(ip, sIp));
                            if (!isSubnetMatch) {
                                asnHtm = \`<span class="text-red-400 font-bold">\${asn} \${org} [ASN Mismatch / 跨域代理]</span>\`;
                            } else {
                                asnHtm = \`<span class="text-green-400">\${asn} \${org} [Subnet Match / 同段]</span>\`;
                            }
                        } else if (asn && SERVER_ASN !== 'Unknown' && asn === SERVER_ASN) {
                            asnHtm = \`<span class="text-green-400">\${asn} \${org} [ASN Match / 同源]</span>\`;
                        }
                        
                        geoNode.innerHTML = \`↳ 📍 \${escapeHTML(geo.country || '')} \${escapeHTML(geo.region || '')} \${escapeHTML(geo.city || '')} | 🏢 \${asnHtm}\`;
                    } else if (!isPublicIP(ip)) {
                        geoNode.innerHTML = '<span class="en-only">↳ 📍 Private / LAN Interface</span><span class="zh-only">↳ 📍 内网 / 局域网接口</span>';
                    } else { 
                        const asnFallback = globalAsnMap[ip] && globalAsnMap[ip] !== 'Unknown' ? globalAsnMap[ip] : '';
                        if (asnFallback) {
                            let asnHtm = asnFallback;
                            if (SERVER_ASN !== 'Unknown' && asnFallback !== SERVER_ASN) {
                                const isSubnetMatch = SERVER_DETECTED_IPS.some(sIp => isSameSubnet(ip, sIp));
                                if (!isSubnetMatch) {
                                    asnHtm = \`<span class="text-red-400 font-bold">\${asnFallback} [ASN Mismatch / 跨域代理]</span>\`;
                                } else {
                                    asnHtm = \`<span class="text-green-400">\${asnFallback} [Subnet Match / 同段]</span>\`;
                                }
                            } else if (SERVER_ASN !== 'Unknown' && asnFallback === SERVER_ASN) {
                                asnHtm = \`<span class="text-green-400">\${asnFallback} [ASN Match / 同源]</span>\`;
                            }
                            geoNode.innerHTML = \`↳ 📍 BGP Partial Info | 🏢 \${asnHtm}\`;
                        } else {
                            geoNode.innerHTML = '<span class="en-only">↳ 📍 BGP Resolving Error</span><span class="zh-only">↳ 📍 BGP 解析失败</span>'; 
                        }
                    }
                });
            }
        }
        egressContainer.innerHTML = ipNodes.size === 0 ? '<div class="text-sm text-slate-500"><span class="en-only">No network nodes detected.</span><span class="zh-only">未探测到任何网络节点。</span></div>' : resultHtmlStr;
    };

    const getCanvasFingerprint = () => { const canvas = document.createElement('canvas'); const ctx = canvas.getContext('2d'); ctx.textBaseline = "alphabetic"; ctx.font = "14px 'Arial'"; ctx.fillStyle = "#f60"; ctx.fillRect(125,1,62,20); ctx.fillStyle = "#069"; ctx.fillText("AnalyzerPro \\ud83d\\ude03", 2, 15); ctx.fillStyle = "rgba(102, 204, 0, 0.7)"; ctx.fillText("AnalyzerPro \\ud83d\\ude03", 4, 17); return canvas.toDataURL(); };
    const getWebGLFingerprint = () => { const gl = document.createElement('canvas').getContext('webgl'); const debugInfo = gl.getExtension('WEBGL_debug_renderer_info'); return debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) + gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'NoDebugInfo'; };
    const getAudioFingerprint = async () => { try { const ctx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100); const osc = ctx.createOscillator(); osc.type = 'triangle'; osc.frequency.setValueAtTime(10000, ctx.currentTime); const comp = ctx.createDynamicsCompressor(); [['threshold', -50], ['knee', 40], ['ratio', 12], ['reduction', -20], ['attack', 0], ['release', 0.25]].forEach(p => { if (comp[p[0]] !== undefined) comp[p[0]].value = p[1]; }); osc.connect(comp); comp.connect(ctx.destination); osc.start(0); const buffer = await ctx.startRendering(); const sum = buffer.getChannelData(0).slice(4500, 5000).reduce((acc, val) => acc + Math.abs(val), 0); return sum.toString(); } catch(e) { return 'Blocked'; } };
    const getFontFingerprint = () => { const fonts = ["Arial", "Courier New", "Georgia", "Impact", "Tahoma", "Times New Roman", "Verdana", "Ubuntu", "Roboto", "Consolas"]; const canvas = document.createElement('canvas'); const ctx = canvas.getContext('2d'); let fontBits = ""; ctx.font = \`72px monospace\`; const baseline = ctx.measureText("mmmmmmmmmmlli").width; fonts.forEach(f => { ctx.font = \`72px "\${f}", monospace\`; fontBits += (ctx.measureText("mmmmmmmmmmlli").width !== baseline) ? "1" : "0"; }); return fontBits; };
    const getDOMRectFingerprint = () => { const el = document.createElement('div'); el.innerHTML = "rects"; el.style.fontSize = "100px"; el.style.position = "absolute"; el.style.top = "-9999px"; document.body.appendChild(el); const rect = el.getBoundingClientRect(); document.body.removeChild(el); return \`\${rect.width}x\${rect.height}x\${rect.x}x\${rect.y}\`; };

    const extractHardwareGPU = () => {
        let gpu = "Unknown / Blocked";
        try { 
            const gl = document.createElement('canvas').getContext('webgl'); 
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) gpu = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            else gpu = gl.getParameter(gl.RENDERER);
        } catch(e){}
        return gpu;
    };

    const extractDeepHardware = async () => {
        let arch = "Unknown", bitness = "", platform = "";
        try {
            if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
                const hints = await navigator.userAgentData.getHighEntropyValues(['architecture', 'bitness', 'model', 'platformVersion']);
                if (hints.architecture) arch = hints.architecture;
                if (hints.bitness) bitness = hints.bitness;
                if (hints.platformVersion) platform = \`v\${hints.platformVersion}\`;
            }
        } catch(e) {}

        const storageInfo = \`<span class="en-only">Sandboxed / Volume Protected</span><span class="zh-only">沙盒受限 / 卷保护</span> <span class="text-[0.65rem] text-green-400 font-bold">(Safe Mode)</span>\`;

        let sensors = [];
        try { if (window.DeviceOrientationEvent) sensors.push("Gyro"); } catch(e){}
        try { if (window.DeviceMotionEvent) sensors.push("Accel"); } catch(e){}
        try { if ('AmbientLightSensor' in window) sensors.push("ALS"); } catch(e){}

        let glExts = "Unknown";
        try { 
            const gl = document.createElement('canvas').getContext('webgl'); 
            const exts = gl.getSupportedExtensions(); 
            if (exts) glExts = exts.length + " Exts"; 
        } catch(e){}

        return { arch, bitness, platform, storageInfo, sensors: sensors.length ? sensors.join('/') : "None", glExts };
    };

    const extractAdvancedHardware = () => {
        let gamut = "sRGB", hdr = "SDR", pointer = "Unknown";
        try {
            if (window.matchMedia) {
                if (window.matchMedia('(color-gamut: p3)').matches) gamut = "Display P3";
                else if (window.matchMedia('(color-gamut: rec2020)').matches) gamut = "Rec.2020";
                if (window.matchMedia('(dynamic-range: high)').matches) hdr = "HDR";
                if (window.matchMedia('(pointer: fine)').matches) pointer = "Fine (Mouse/Stylus)";
                else if (window.matchMedia('(pointer: coarse)').matches) pointer = "Coarse (Touch)";
                else pointer = "None/Unsupported";
            }
        } catch(e) {}
        
        let gp = "No", bt = "No", usb = "No", vr = "No";
        if(navigator.getGamepads) gp = "Yes";
        if(navigator.bluetooth) bt = "Yes";
        if(navigator.usb) usb = "Yes";
        if(navigator.xr) vr = "Yes";

        return { gamut, hdr, pointer, gp, bt, usb, vr };
    };

    const buildHardwareData = (gpu, deepHw) => {
        const adv = extractAdvancedHardware();
        const memory = navigator.deviceMemory || 0;
        const cores = navigator.hardwareConcurrency || 0;
        
        let cpuDisplay = cores ? cores + " Threads" : "Unknown";
        let spoofFlag = false;
        
        if (cores > 0 && memory > 0) {
            if (cores <= 2 && memory >= 8) spoofFlag = true; 
        }
        
        if (deepHw.arch !== "Unknown") {
            cpuDisplay += \` <span class="text-sky-300 text-[0.7rem]">(\${deepHw.arch.toUpperCase()} \${deepHw.bitness}-bit)</span>\`;
        } else if (navigator.oscpu || navigator.cpuClass) {
            cpuDisplay += \` <span class="text-sky-300 text-[0.7rem]">(\${navigator.oscpu || navigator.cpuClass})</span>\`;
        }
        
        if (spoofFlag) {
            cpuDisplay += \` <span class="text-red-400 font-bold text-[0.7rem] ml-1" title="Core count unnaturally low for RAM size">[Spoof Suspected]</span>\`;
        }

        return {
            "CPU (Threads/Arch)||处理器 (线程/架构)": cpuDisplay,
            "RAM / Storage Quota||运行内存 / 存储配额": \`\${memory ? memory + ' GB' : 'Unknown'} <span class="text-slate-400 text-[0.7rem]">| Disk: \${deepHw.storageInfo}</span>\`,
            "Screen / Viewport||屏幕 / 视口尺寸": \`\${screen.width} x \${screen.height} <span class="text-slate-400 text-[0.7rem]">| View: \${window.innerWidth}x\${window.innerHeight}</span>\`,
            "Color Engine||色彩引擎 / 深度": \`<span class="text-sky-300 text-[0.8rem]">\${adv.gamut} / \${adv.hdr} / \${screen.colorDepth}-bit</span>\`,
            "Input Vector||触控 / 指针输入": \`\${adv.pointer} / Max \${navigator.maxTouchPoints || 0} pts\`,
            "Deep Sensors||深层硬件传感器": \`<span class="text-[0.7rem] text-slate-300">HW: \${deepHw.sensors}</span>\`,
            "Hw. Interfaces||底层硬件接口": \`<span class="text-[0.65rem] text-slate-400">BT:\${adv.bt} | USB:\${adv.usb} | VR:\${adv.vr} | GP:\${adv.gp}</span>\`,
            "OS / Platform||操作系统 / 平台": \`\${navigator.platform || 'Unknown'} <span class="text-[0.7rem] text-slate-400">\${deepHw.platform}</span>\`,
            "GPU Renderer||显卡渲染引擎": \`<span class="text-purple-400 text-xs">\${escapeHTML(gpu)}</span> <span class="text-[0.65rem] text-slate-500">(\${deepHw.glExts})</span>\`
        };
    };

    const buildSensorNetworkData = async (rtcIPsRaw, globalAsnMap) => {
        let mediaDevs = "Blocked / 0", batteryStr = "Unsupported";
        try { const devs = await navigator.mediaDevices.enumerateDevices(); mediaDevs = devs.length; } catch(e){}
        try { if(navigator.getBattery) { const b = await navigator.getBattery(); batteryStr = \`\${b.level * 100}% (\${b.charging ? 'Charging' : 'Unplugged'})\`; } } catch(e){}
        const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        
        let rtcDisplay = "Blocked/Obfuscated"; 
        let isTunnelBypass = false;
        let isMatch = false;
        let isSpoofed = false;
        let hasAsnMismatch = false;
        
        if (Array.isArray(rtcIPsRaw)) { 
            rtcDisplay = rtcIPsRaw.join(', '); 
            let hasPublic = false;
            
            rtcIPsRaw.forEach(ip => { 
                if (isPublicIP(ip)) {
                    hasPublic = true;
                    if (SERVER_DETECTED_IPS.includes(ip) || SERVER_DETECTED_IPS.some(sIp => isSameSubnet(ip, sIp))) {
                        isMatch = true;
                    }
                    if (globalAsnMap && globalAsnMap[ip]) {
                        const rtcAsn = globalAsnMap[ip];
                        const isSubnetMatch = SERVER_DETECTED_IPS.some(sIp => isSameSubnet(ip, sIp));
                        if (!isSubnetMatch && rtcAsn !== 'Unknown' && SERVER_ASN !== 'Unknown' && rtcAsn !== SERVER_ASN) {
                            hasAsnMismatch = true;
                        }
                    }
                } else if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip.includes('::1')) {
                    isSpoofed = true;
                }
            }); 
            
            if (hasAsnMismatch) {
                isTunnelBypass = true;
                isMatch = false;
            } else if (hasPublic && !isMatch) {
                isTunnelBypass = true;
            }
        } else if (typeof rtcIPsRaw === 'string') { rtcDisplay = rtcIPsRaw; }
        
        let ipLeakHtml = \`<span class='text-amber-400 font-mono'>\${escapeHTML(rtcDisplay)}</span>\`;
        if (hasAsnMismatch) {
            ipLeakHtml = \`<span class='text-red-500 font-bold'>\${escapeHTML(rtcDisplay)} <span class="en-only">(ASN Divergence!)</span><span class="zh-only">(ASN 断层泄露!)</span></span>\`;
        } else if (isTunnelBypass) {
            ipLeakHtml = \`<span class='text-red-500 font-bold'>\${escapeHTML(rtcDisplay)} <span class="en-only">(Tunnel Bypass / Mismatch!)</span><span class="zh-only">(隧道穿透 / 不匹配!)</span></span>\`;
        } else if (isMatch) {
            ipLeakHtml = \`<span class='text-green-400 font-mono'>\${escapeHTML(rtcDisplay)} <span class="en-only">(Match/Clean)</span><span class="zh-only">(原生 / 一致)</span></span>\`;
        } else if (isSpoofed) {
            ipLeakHtml = \`<span class='text-amber-300 font-mono'>\${escapeHTML(rtcDisplay)} <span class="en-only">(Spoofed/Masked)</span><span class="zh-only">(掩盖 / 伪造)</span></span>\`;
        }

        const dataSaverOutput = conn && conn.saveData ? 
            "<span class='text-red-400'><span class='en-only'>Enabled</span><span class='zh-only'>已开启代理压缩</span></span>" : 
            "<span class='en-only'>Disabled</span><span class='zh-only'>未启用</span>";
            
        // [v1.9.46] Physical TCP RTT vs Application RTT Logic
        let rttHtml = conn ? conn.rtt + ' ms (L7 App)' : "Unknown";
        if (SERVER_RTT > 0) {
            let rttClass = "text-sky-400";
            if (conn && conn.rtt && Math.abs(conn.rtt - SERVER_RTT) >= 150) {
                rttClass = "text-red-400 font-bold"; // High differential indicates likely proxy tunneling
            }
            rttHtml += ` / <span class="${rttClass}" title="Server Layer-4 TCP Round Trip Time">L4 TCP: ${SERVER_RTT} ms</span>`;
        }

        return {
            "WebRTC IP Leak||WebRTC 底层 IP 泄漏": ipLeakHtml,
            "Media Devices||多媒体设备数": mediaDevs,
            "Battery Status||电池 / 充电状态": batteryStr,
            "Network Type||底层网络类型": conn ? conn.effectiveType : "Unknown",
            "Data Saver Proxy||流量节点 (Data Saver)": dataSaverOutput,
            "Est. Downlink||下行带宽估算": conn ? conn.downlink + ' Mbps' : "Unknown",
            "RTT (Latency)||链路延迟 (RTT)": rttHtml,
            "Timezone (Local)||系统底层时区": Intl.DateTimeFormat().resolvedOptions().timeZone,
            "UTC Offset||格林威治偏移": \`GMT \${new Date().getTimezoneOffset() / -60}\`
        };
    };

    const buildBrowserData = async (calib, rtcIPsRaw) => {
        let notifPerm = "Unknown";
        try { const p = await navigator.permissions.query({name: 'notifications'}); notifPerm = p.state; } catch(e){}
        
        let osConflict = "<span class='en-only'>Consistent</span><span class='zh-only'>一致 / 原生</span>";
        if (navigator.platform.includes('Win') && !uaGlobal.includes('Windows')) osConflict = "<span class='text-red-400'><span class='en-only'>Spoofed (Win Platform)</span><span class='zh-only'>伪装 (Win系统特征)</span></span>";
        if (navigator.platform.includes('Mac') && !uaGlobal.includes('Mac')) osConflict = "<span class='text-red-400'><span class='en-only'>Spoofed (Mac Platform)</span><span class='zh-only'>伪装 (Mac系统特征)</span></span>";
        if (navigator.platform.includes('Linux') && (!uaGlobal.includes('Linux') && !uaGlobal.includes('Android'))) osConflict = "<span class='text-red-400'><span class='en-only'>Spoofed (Linux Platform)</span><span class='zh-only'>伪装 (Linux系统特征)</span></span>";

        let apiIpMatch = '';
        let apiGeoMatch = "";

        const validApis = [calib.cf, calib.geojs].filter(a => a && a.ip);
        const serverIps = [P_CLIENT_IP, ...SERVER_DETECTED_IPS];
        
        let hasApiConflict = false;
        let dualStack = false;
        let subnetMatch = false;
        let asnMatch = false;
        let conflictIp = '';

        validApis.forEach(api => {
            const ip = api.ip;
            if (!serverIps.includes(ip)) {
                const inWebRTC = Array.isArray(rtcIPsRaw) && rtcIPsRaw.includes(ip);
                if (!inWebRTC) {
                    if (serverIps.some(sIp => isSameSubnet(ip, sIp))) {
                        subnetMatch = true;
                    } else if (SERVER_ASN !== 'Unknown' && api.asn === SERVER_ASN) {
                        asnMatch = true;
                    } else {
                        const family = ip.includes(':') ? 'IPv6' : 'IPv4';
                        const serverFamily = P_CLIENT_IP.includes(':') ? 'IPv6' : 'IPv4';
                        if (family !== serverFamily) {
                            dualStack = true;
                        } else {
                            hasApiConflict = true;
                            conflictIp = ip;
                        }
                    }
                }
            }
        });

        if (hasApiConflict) {
            apiIpMatch = \`<span class='text-amber-400'><span class="en-only">Egress Divergence</span><span class="zh-only">出口分流/异常</span> (\${escapeHTML(conflictIp)})</span>\`;
        } else if (asnMatch) {
            apiIpMatch = \`<span class='text-green-400'><span class="en-only">ASN Match (ISP CGNAT Safe)</span><span class="zh-only">ASN 匹配 (基站CGNAT安全)</span></span>\`;
        } else if (subnetMatch) {
            apiIpMatch = \`<span class='text-green-400'><span class="en-only">Subnet Match (Safe ISP Shift)</span><span class="zh-only">子网匹配 (动态IP分配安全)</span></span>\`;
        } else if (dualStack) {
            apiIpMatch = \`<span class='text-sky-400'><span class="en-only">Dual-Stack Consistent</span><span class="zh-only">双栈网络一致</span></span>\`;
        } else if (validApis.length > 0) {
            apiIpMatch = \`<span class='text-green-400'><span class="en-only">Consistent Match</span><span class="zh-only">IP 完全匹配</span></span>\`;
        } else {
            apiIpMatch = \`<span class='text-slate-500'><span class="en-only">Blocked / Unavailable</span><span class="zh-only">接口阻断 / 无数据</span></span>\`;
        }

        // Tri-Point Geo Consensus Logic
        const validCcs = validApis.map(a => a.cc).filter(Boolean);
        let uniqueCcs = [...new Set(validCcs)];
        
        if (uniqueCcs.length > 1) {
            apiGeoMatch = \`<span class='text-red-400 font-bold'><span class="en-only">API Geo Divergence</span><span class="zh-only">物理定位多点分歧</span> (\${escapeHTML(uniqueCcs.join('/'))})</span>\`;
        } else if (uniqueCcs.length > 0 && SERVER_CC !== 'Unknown' && uniqueCcs[0] !== SERVER_CC) {
            apiGeoMatch = \`<span class='text-red-400 font-bold'><span class="en-only">Edge vs API Conflict</span><span class="zh-only">端云跨域冲突</span> (\${escapeHTML(SERVER_CC)} vs \${escapeHTML(uniqueCcs[0])})</span>\`;
        } else if (uniqueCcs.length === 0) { 
            apiGeoMatch = \`<span class='text-slate-500'><span class="en-only">Blocked / Unavailable</span><span class="zh-only">接口阻断 / 无数据</span></span>\`; 
        } else {
            apiGeoMatch = \`<span class='text-green-400'><span class="en-only">Consensus Reached</span><span class="zh-only">物理定位完全一致</span></span>\`;
        }

        const cookiesStatus = navigator.cookieEnabled ? 
            "<span class='en-only'>Yes</span><span class='zh-only'>允许</span>" : 
            "<span class='en-only'>No</span><span class='zh-only'>阻止</span>";

        return {
            "API IP Consensus||多维 IP 一致性": apiIpMatch,
            "API Geo Consensus||定位物理一致性": apiGeoMatch,
            "Language (Locale)||系统默认语言": navigator.language,
            "Cookies Enabled||Cookie 状态": cookiesStatus,
            "Plugins Count||系统插件数量": navigator.plugins.length,
            "Notif. Permission||通知推送权限": notifPerm,
            "OS / UA Conflict||系统/UA 欺骗检测": osConflict
        };
    };

    const runBotChecks = (serverScoreFactors, rtcIPsRaw, calib, gpu, rtcMeta, tunnels, globalAsnMap) => {
        let networkScore = 0; let browserScore = 0; let hardwareScore = 0; let behaviorScore = 0;
        const riskDetails = document.getElementById('risk-details-container');
        let injectedRiskHtml = riskDetails.innerHTML;
        
        const addRisk = (cat, enName, zhName, weight) => {
            if (cat === 'Network') networkScore += weight;
            else if (cat === 'Browser') browserScore += weight;
            else if (cat === 'Hardware') hardwareScore += weight;
            else if (cat === 'Behavior') behaviorScore += weight;
            injectedRiskHtml += \`<div class="kv-row"><span class="kv-key text-red-400">[\${escapeHTML(cat)}]</span><span class="kv-val text-red-400"><span class="en-only">\${escapeHTML(enName)} (+\${weight})</span><span class="zh-only">\${escapeHTML(zhName)} (+\${weight})</span></span></div>\`;
        };

        serverScoreFactors.forEach(f => {
            if (f.c === 'Network') networkScore += f.s; else browserScore += f.s;
        });

        const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(uaGlobal);
        const isAppleDevice = /Mac|iPhone|iPad|iPod/i.test(navigator.platform);

        // Advanced Proxy Object / Navigator override detection
        try { if (Object.getOwnPropertyNames(navigator).includes('webdriver')) addRisk("Behavior", "WebDriver Property Override", "原生 WebDriver 属性被强制覆盖保护", 40); } catch(e){}

        if (checkNativeTampering(Navigator.prototype, 'webdriver')) {
            addRisk("Behavior", "Prototype Tampering (Stealth)", "检测到浏览器底层原型链伪造 (隐身防关联插件)", 40);
        } else if (navigator.webdriver) {
            addRisk("Behavior", "WebDriver Active", "检测到原生 WebDriver 自动化标识", 40);
        }
        
        if (!!window.cdc_adoQpoasnfa76pfcZLmcfl_ || !!window.cdc_adoQpoasnfa76pfcZLmcfl_Array) addRisk("Behavior", "Puppeteer Variables", "发现 Puppeteer (CDP) 注入特征", 50);
        if (!!window._selenium || !!window.document.__webdriver_script_fn) addRisk("Behavior", "Selenium Signatures", "发现 Selenium 注入特征", 50);
        
        if (window.callPhantom || window._phantom || window.phantom) addRisk("Behavior", "PhantomJS Detected", "检测到 PhantomJS 无头自动化环境", 50);
        if (window.__nightmare) addRisk("Behavior", "NightmareJS Detected", "检测到 NightmareJS 自动化框架", 50);
        if (document.documentElement.getAttribute("webdriver") !== null) addRisk("Behavior", "DOM WebDriver Attribute", "文档根节点暴露 webdriver 属性", 40);
        
        if (typeof process !== 'undefined' && process.versions && process.versions.node) {
            addRisk("Behavior", "NodeJS/Electron Host", "检测到 NodeJS/Electron 宿主环境 (高疑自动化)", 50);
        }
        
        if (window.Cypress) addRisk("Behavior", "Cypress Framework Detected", "检测到 Cypress 自动化测试框架", 50);
        if (window._Selenium_IDE_Recorder || document.__selenium_unwrapped || window.calledSelenium) addRisk("Behavior", "Selenium WebDriver Traces", "检测到 Selenium 深度注入痕迹", 50);
        if (window.domAutomation || window.domAutomationController) addRisk("Behavior", "DOM Automation Traces", "检测到自动化控制引擎 (DOM Automation)", 50);
        
        if (typeof WebGLRenderingContext !== 'undefined' && checkNativeTampering(WebGLRenderingContext.prototype, 'getParameter')) {
            addRisk("Behavior", "WebGL getParameter Hooked", "底层 WebGL API 被劫持代理 (指纹伪装/掩饰)", 40);
        }
        if (checkNativeTampering(window, 'eval')) {
            addRisk("Behavior", "eval Hooked", "全局 eval 函数被拦截劫持 (防伪造沙盒报警)", 30);
        }
        if (typeof Date !== 'undefined' && checkNativeTampering(Date.prototype, 'getTimezoneOffset')) {
            addRisk("Behavior", "Timezone Spoofing Hook", "时区偏移函数被拦截伪造 (防关联对抗)", 35);
        }
        
        if (Function.prototype.bind.toString().indexOf('[native code]') === -1) {
            addRisk("Behavior", "Function.bind Hooked", "底层 Function.bind 被劫持代理 (指纹掩饰)", 40);
        }
        if (Function.prototype.toString.toString().indexOf('[native code]') === -1) {
            addRisk("Behavior", "toString Hooked", "原型链 toString 被重写 (防关联隐身对抗)", 40);
        }
        if (Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent') && Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get) {
            if (checkNativeTampering(Navigator.prototype, 'userAgent')) {
                addRisk("Behavior", "User-Agent Spoofing Hook", "UA 原型链 getter 被拦截伪造", 35);
            }
        }

        if (window.outerWidth === 0 && window.outerHeight === 0) addRisk("Behavior", "Zero Window Size (Headless)", "窗口尺寸为 0 (无头模式)", 30);
        if (window.innerWidth === 800 && window.innerHeight === 600 && window.outerWidth === 800) addRisk("Behavior", "Default Headless Viewport", "符合默认无头浏览器视口尺寸", 30);
        
        if (checkNativeTampering(Navigator.prototype, 'deviceMemory')) addRisk("Hardware", "Hardware Spoofing API", "设备硬件内存接口被劫持伪造 (指纹对抗)", 35);
        if (checkNativeTampering(Navigator.prototype, 'hardwareConcurrency')) addRisk("Hardware", "CPU Thread Spoofing API", "CPU 逻辑核心数接口被劫持伪造 (指纹对抗)", 35);
        if (checkNativeTampering(HTMLCanvasElement.prototype, 'toDataURL') || checkNativeTampering(CanvasRenderingContext2D.prototype, 'getImageData')) {
            addRisk("Browser", "Canvas Fingerprint Defender", "检测到 Canvas 绘图 API 被劫持注入噪音 (指纹掩盖)", 30);
        }

        const memory = navigator.deviceMemory || 0; const cores = navigator.hardwareConcurrency || 0;
        if (cores > 0 && memory > 0 && cores <= 2 && memory >= 8) {
            addRisk("Hardware", "Hardware Concurrency Spoofed", "逻辑线程数与物理内存比例异常 (高危伪装)", 25);
        }
        if (cores > 0 && cores % 2 !== 0) {
            addRisk("Hardware", "Anomalous CPU Cores", "异常的逻辑处理器核心数", 15);
        }

        if (gpu && (gpu.toLowerCase().includes('swiftshader') || gpu.toLowerCase().includes('llvmpipe') || gpu.toLowerCase().includes('virtual'))) {
            addRisk("Hardware", "Software Renderer (VM/Headless)", "检测到软件模拟渲染器 (高疑云手机/虚拟机/无头)", 45);
        }

        if (navigator.plugins.length === 0 && !uaGlobal.includes("Mobile")) addRisk("Browser", "Zero Plugins (Desktop)", "桌面端零插件异常", 10);
        if (navigator.languages === "" || navigator.languages.length === 0) addRisk("Browser", "Languages Array Empty", "语言首选项为空 (高疑防关联伪装)", 20);
        
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; const lang = navigator.language || "";
        if (lang.startsWith("zh") && tz !== "" && !tz.includes("Asia/Shanghai") && !tz.includes("Asia/Chongqing") && !tz.includes("Asia/Taipei") && !tz.includes("Asia/Hong_Kong") && !tz.includes("Asia/Macau") && !tz.includes("Asia/Urumqi")) {
            addRisk("Behavior", "Timezone & Locale Mismatch", "时区与本地语言异常", 5); 
        }
        
        const validApis = [calib.cf, calib.geojs].filter(a => a && a.ip);
        const serverIps = [P_CLIENT_IP, ...SERVER_DETECTED_IPS];

        if (rtcMeta) {
            if (rtcMeta.blocked) {
                if (!isMobileUA && !uaGlobal.includes("Safari") && !uaGlobal.includes("Brave") && (uaGlobal.includes("Chrome") || uaGlobal.includes("Firefox"))) {
                    addRisk("Behavior", "WebRTC Hard Blocked", "WebRTC被强行阻断 (高疑防关联插件)", 10);
                    updateProxyRadar(10, 'WEBRTC_BLK', 'WebRTC Hard Blocked', '引擎特征：底层WebRTC被插件强制阻断', 'warning');
                }
            } else {
                if (rtcMeta.host && !rtcMeta.srflx && !rtcMeta.udp && rtcMeta.tcp) {
                    updateProxyRadar(30, 'UDP_DROP', 'WebRTC UDP Dropped', '协议异常：UDP被丢弃/代理网关不支持UDP转发');
                } else if (rtcMeta.host && !rtcMeta.srflx) {
                    updateProxyRadar(15, 'STUN_FAIL', 'WebRTC STUN Blocked', '穿透异常：STUN服务器无法返回公网IP(受限代理)');
                }
                
                if (Array.isArray(rtcIPsRaw)) { 
                    let hasPublicLeak = false;
                    let hasMatch = false;
                    let hasSpoof = false;
                    let hasAsnMismatch = false;
                    let mismatchDetails = [];

                    rtcIPsRaw.forEach(ip => { 
                        if (isPublicIP(ip)) {
                            hasPublicLeak = true;
                            if (serverIps.includes(ip) || serverIps.some(sIp => isSameSubnet(ip, sIp))) {
                                hasMatch = true;
                            }
                            
                            if (globalAsnMap && globalAsnMap[ip]) {
                                const rtcAsn = globalAsnMap[ip];
                                const isSubnetMatch = serverIps.some(sIp => isSameSubnet(ip, sIp));
                                if (!isSubnetMatch && rtcAsn !== 'Unknown' && SERVER_ASN !== 'Unknown' && rtcAsn !== SERVER_ASN) {
                                    hasAsnMismatch = true;
                                    mismatchDetails.push(\`\${ip} (\${rtcAsn})\`);
                                }
                            }
                        } else if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip.includes('::1')) {
                            hasSpoof = true;
                        }
                    }); 
                    
                    if (hasAsnMismatch) {
                        addRisk("Network", "WebRTC ASN Divergence", "WebRTC公网IP与出口IP不在同一自治系统(ASN)", 45);
                        updateProxyRadar(45, 'WEBRTC_ASN_DIVERGE', \`WebRTC ASN Divergence (\${mismatchDetails.join(', ')})\`, \`链路断层：WebRTC底层公网IP与出口不在同一ASN(确认为代理)\`, 'danger');
                    } else if (hasPublicLeak) {
                        if (hasMatch) {
                            updateProxyRadar(0, 'WEBRTC_MATCH', 'WebRTC IP/ASN Match', '一致性校验：WebRTC公网IP与检测IP/ASN匹配(无代理)', 'safe');
                        } else {
                            addRisk("Network", "WebRTC Tunnel Bypass Leak", "WebRTC 穿透暴露底层公网 IP", 40); 
                            updateProxyRadar(40, 'WEBRTC_LEAK', 'WebRTC Proxy Bypass Leak', '隧道穿透：WebRTC暴露真实底层公网IP跨网段', 'danger');
                        }
                    }
                    
                    if (hasSpoof) {
                        addRisk("Network", "WebRTC Local IP Spoofed", "检测到WebRTC虚假Local IP掩盖(警告)", 10);
                        updateProxyRadar(0, 'WEBRTC_SPOOF', 'WebRTC Spoofing (Warning Only)', '指纹提醒：伪造本地IP注入(无直接代理行为证据)', 'warning');
                    }
                }
            }
        }

        if (SERVER_TZ !== 'Unknown' && tz !== '' && SERVER_TZ !== tz) {
            updateProxyRadar(35, 'TZ_SPOOF', 'Timezone vs IP Geo Mismatch', '物理断层：浏览器底层时区与出口IP国家时区严重不符');
        }

        let externalAsnMismatch = false;
        let externalMismatchDetails = [];

        const checkExternalIp = (ip, sourceName) => {
            const isSubnetMatch = serverIps.some(sIp => isSameSubnet(ip, sIp));
            if (!isSubnetMatch && isPublicIP(ip) && globalAsnMap[ip] && globalAsnMap[ip] !== 'Unknown' && SERVER_ASN !== 'Unknown' && globalAsnMap[ip] !== SERVER_ASN) {
                externalAsnMismatch = true;
                externalMismatchDetails.push(\`\${ip} (\${sourceName}: \${globalAsnMap[ip]})\`);
            }
        };

        if (calib.cf && calib.cf.ip) checkExternalIp(calib.cf.ip, 'CF');
        if (calib.geojs && calib.geojs.ip) checkExternalIp(calib.geojs.ip, 'GeoJS');
        if (tunnels && tunnels.v4) checkExternalIp(tunnels.v4, 'IPv4 Probe');
        if (tunnels && tunnels.v6) checkExternalIp(tunnels.v6, 'IPv6 Probe');

        let hasApiConflict = false;
        let dualStackFlag = false;
        let subnetExempt = false;
        let asnExempt = false;
        
        validApis.forEach(api => {
            const ip = api.ip;
            if (!serverIps.includes(ip)) {
                const inWebRTC = Array.isArray(rtcIPsRaw) && rtcIPsRaw.includes(ip);
                if (!inWebRTC) {
                    if (serverIps.some(sIp => isSameSubnet(ip, sIp))) {
                        subnetExempt = true;
                    } else if (SERVER_ASN !== 'Unknown' && api.asn === SERVER_ASN) {
                        asnExempt = true;
                    } else {
                        const family = ip.includes(':') ? 'IPv6' : 'IPv4';
                        const serverFamily = P_CLIENT_IP.includes(':') ? 'IPv6' : 'IPv4';
                        if (family === serverFamily) {
                            hasApiConflict = true;
                        } else {
                            dualStackFlag = true;
                        }
                    }
                }
            }
        });

        if (externalAsnMismatch) {
            addRisk("Network", "External Node ASN Divergence", "探测节点公网IP与主干网络ASN不匹配", 45);
            updateProxyRadar(45, 'EXT_ASN_DIVERGE', \`External ASN Divergence (\${externalMismatchDetails.join(', ')})\`, \`链路断层：外部公网出口与主干网络不在同一ASN(确认为代理)\`, 'danger');
        } else if (hasApiConflict) { 
            updateProxyRadar(0, 'ROUTE_DIVERGE', 'Egress Route Divergence', '路由分流：API获取到跨网段出口IP(多线路动态负载均衡安全)', 'sky');
        } else if (asnExempt) {
            updateProxyRadar(0, 'ASN_SHIFT', 'ISP ASN Resonance Consistent', '同治载体：主干与API侧IP属同一自治系统(基站CGNAT安全)', 'safe');
        } else if (subnetExempt) {
            updateProxyRadar(0, 'SUBNET_SHIFT', 'ISP Subnet Shift Consistent', '宽带同段：主干与API侧IP在同一子网段(动态IP负载均衡安全)', 'safe');
        } else if (dualStackFlag) {
            updateProxyRadar(0, 'DUAL_STACK', 'Dual-Stack Protocol Consistent', '跨栈校对：主干与探测节点分别触达 IPv4/IPv6 双栈网络(安全)', 'sky');
        }
        
        const validCcs = validApis.map(a => a.cc).filter(Boolean);
        let uniqueCcs = [...new Set(validCcs)];
        if (uniqueCcs.length > 1) { 
            addRisk("Network", "API Geo-Location Divergence", "不同开放API探测到冲突的物理位置(高危)", 25); 
        } else if (uniqueCcs.length > 0 && SERVER_CC !== 'Unknown' && uniqueCcs[0] !== SERVER_CC) { 
            addRisk("Network", "Edge vs API Geo-Location Conflict", "端云(CF)节点定位与探测API定位物理跨域", 20); 
        }
        
        const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (conn && conn.saveData) {
            updateProxyRadar(15, 'DATASAVER', 'Data Saver Proxy Active', '隐蔽代理：检测到浏览器启用数据压缩中继服务');
        }

        if (isMobileUA && navigator.maxTouchPoints === 0) { addRisk("Hardware", "Mobile UA without Touch Points", "声明为移动端却无触摸屏特征", 25); }
        if (isAppleDevice && gpu.includes('ANGLE') && !gpu.includes('Apple')) { addRisk("Hardware", "Apple Platform vs Non-Apple GPU", "Apple 系统暴露非 Apple 显卡 (高疑虚拟机)", 25); }
        if (!isAppleDevice && gpu.includes('Apple')) { addRisk("Hardware", "Non-Apple Platform vs Apple GPU", "非 Apple 系统暴露 Apple 显卡特征", 25); }
        if ((navigator.platform.includes('Win') && !uaGlobal.includes('Windows')) || (navigator.platform.includes('Mac') && !uaGlobal.includes('Mac'))) { addRisk("Browser", "Platform / User-Agent Spoofing", "底层操作系统与UA声明严重不符", 25); }

        riskDetails.innerHTML = injectedRiskHtml;

        let totalRisk = networkScore + browserScore + hardwareScore + behaviorScore;
        if (networkScore > 0 && browserScore > 0) {
            totalRisk = (networkScore * 0.7) + (browserScore * 0.7) + (hardwareScore * 0.5) + (behaviorScore * 0.8) + 20;
        }
        totalRisk = Math.min(Math.round(totalRisk), 100);
        
        let riskLevel = { en: 'LOW', zh: '低风险' }, riskColor = '#4ade80', badgeClass = 'badge-green';
        if (totalRisk >= 30) { riskLevel = { en: 'MEDIUM', zh: '中等风险' }; riskColor = '#facc15'; badgeClass = 'badge-yellow'; }
        if (totalRisk >= 60) { riskLevel = { en: 'HIGH', zh: '高危环境' }; riskColor = '#ef4444'; badgeClass = 'badge-red'; }

        if(document.getElementById('risk-chart-number')) { 
            const rn = document.getElementById('risk-chart-number');
            rn.innerText = totalRisk; 
            rn.style.color = riskColor;
            rn.classList.remove('animate-pulse');
        }
        if(document.getElementById('risk-level-badge')) {
            document.getElementById('risk-level-badge').innerHTML = \`<span class="en-only">\${escapeHTML(riskLevel.en)}</span><span class="zh-only">\${escapeHTML(riskLevel.zh)}</span>\`;
            document.getElementById('risk-level-badge').className = \`badge \${badgeClass} mt-2 text-sm border-0\`;
        }
        return { finalScore: totalRisk, riskColor };
    };

    const ClientRouteProber = {
        dataMap: {},
        leafletLoaded: false,
        leafletMap: null,
        marker: null,
        
        async fetchTimeout(url, opts={}, ms=6000) {
            const controller = new AbortController();
            const id = setTimeout(() => controller.abort(), ms);
            try {
                const res = await fetch(url, { ...opts, signal: controller.signal });
                clearTimeout(id);
                if (!res.ok) throw new Error('HTTP ' + res.status);
                return res;
            } catch(e) {
                clearTimeout(id);
                throw e;
            }
        },

        jsonp(url, param='callback', ms=5000) {
            return new Promise((resolve, reject) => {
                const cb = 'jsonp_' + Math.round(Math.random()*1e9);
                const script = document.createElement('script');
                const tId = setTimeout(() => {
                    delete window[cb]; script.remove(); reject(new Error('JSONP Timeout'));
                }, ms);
                window[cb] = (data) => {
                    clearTimeout(tId); delete window[cb]; script.remove(); resolve(data);
                };
                script.src = url + (url.includes('?')?'&':'?') + param + '=' + cb;
                script.onerror = () => { clearTimeout(tId); delete window[cb]; script.remove(); reject(new Error('JSONP Error')); };
                document.head.appendChild(script);
            });
        },

        updateUI(id, status, ip, loc, provider='', countryCode='', asn='', rawTime=0) {
            this.dataMap[id] = { ip: ip, loc: loc, cc: countryCode, asn: asn, rawTime: rawTime };
            const statusEl = document.getElementById(\`status-\${id}\`);
            const valEl = document.getElementById(\`val-\${id}\`);
            const locEl = document.getElementById(\`loc-\${id}\`);
            const provEl = document.getElementById(\`prov-\${id}\`);
            const cardEl = document.getElementById(\`card-\${id}\`);
            
            if(statusEl) {
                statusEl.className = 'w-2.5 h-2.5 rounded-full status-indicator ' + (status==='loading' ? 'bg-amber-400 animate-pulse' : (status==='success'?'bg-emerald-400 shadow-[0_0_8px_#34d399]':'bg-red-500 shadow-[0_0_8px_#ef4444]'));
            }
            if(valEl) {
                let displayIp = status==='loading' ? '<span class="animate-pulse">Loading...</span>' : (status==='error' ? 'Failed' : ip);
                valEl.innerHTML = \`<span>\${displayIp}</span><span class="text-sm opacity-50 group-hover:opacity-100 transition-opacity ml-2">🔍</span>\`;
                valEl.dataset.raw = ip;
            }
            if(locEl) {
                let locHtml = status==='loading' ? '---' : (status==='error' ? '---' : escapeHTML(loc));
                if (countryCode && status==='success') {
                    locHtml = \`<img class="w-4 h-3 rounded-sm object-cover shadow-sm country-flag" src="https://ipdata.co/flags/\${countryCode.toLowerCase()}.png" onerror="this.style.display='none'"> \` + locHtml;
                    if(cardEl) {
                        cardEl.style.setProperty('--flag-badge-url', \`url("https://ipdata.co/flags/\${countryCode.toLowerCase()}.png")\`);
                        cardEl.classList.add('has-flag-badge');
                    }
                }
                locEl.innerHTML = locHtml;
                locEl.dataset.raw = loc;
            }
            if(provEl && provider) {
                provEl.innerText = provider;
            }
        },

        async getIpInfo(ip) {
            const res = await this.fetchTimeout(\`https://api.ipapi.is/?q=\${encodeURIComponent(ip)}\`, {}, 4000).then(r => r.json());
            if(!res || !res.ip) throw new Error('ipapi failed');
            const cc = res.location?.country_code || '';
            const asnStr = res.asn?.asn ? \`AS\${res.asn.asn}\` : '';
            const org = res.company?.name || res.asn?.org || '';
            return { ip: res.ip, loc: \`\${cc} \${asnStr} \${org}\`.trim(), cc: cc, asn: asnStr, raw: res };
        },

        async probeDomestic() {
            try {
                const t0 = performance.now();
                const req = (name, p) => p.then(d => { 
                    if(!d||!d.ip) throw 'e'; 
                    const t = Math.round(performance.now() - t0); 
                    return {ip: d.ip, prov: \`\${name} ⚡\${t}ms\`, rawTime: t}; 
                });
                const res = await Promise.any([
                    req('Tencent', this.jsonp('https://vv.video.qq.com/checktime?otype=json', 'callback', 3500)),
                    req('Baidu', this.fetchTimeout('https://qifu-api.baidubce.com/ip/local/geo/v1/district', {}, 3500).then(r=>r.json()).then(d=>d.data)),
                    req('ByteDance', this.fetchTimeout('https://perfops2.byte-test.com/500b-bench.jpg', {method:'HEAD'}, 3500).then(r => ({ip:r.headers.get('X-Request-Ip')}))),
                    req('PConline', this.jsonp('https://whois.pconline.com.cn/ipJson.jsp', 'callback', 3500))
                ]);
                const info = await this.getIpInfo(res.ip);
                this.updateUI('ipip', 'success', info.ip, info.loc, res.prov, info.cc, info.asn, res.rawTime);
            } catch(e) {
                this.updateUI('ipip', 'error', '', '');
            }
        },

        async probeOverseas() {
            try {
                const t0 = performance.now();
                const req = (name, p) => p.then(d => { 
                    if(!d.ip) throw 'e'; 
                    const t = Math.round(performance.now() - t0); 
                    d.prov = \`\${name} ⚡\${t}ms\`; 
                    d.rawTime = t; 
                    return d; 
                });
                const res = await Promise.any([
                    req('ipapi', this.fetchTimeout('https://api.ipapi.is', {}, 3500).then(r=>r.json()).then(d=>({ip:d.ip, cc:d.location?.country_code, asn:d.asn?.asn?\`AS\${d.asn.asn}\`:'', org:d.company?.name}))),
                    req('cmliussss', this.fetchTimeout('https://api.cmliussss.net/api/ipinfo', {}, 3500).then(r=>r.json()).then(d=>({ip:d.ip, cc:d.country_code, asn:d.asn?.replace('AS','')?\`AS\${d.asn.replace('AS','')}\`:'', org:d.as_name}))),
                    req('IPinfo', this.fetchTimeout('https://ipinfo.io/json', {}, 3500).then(r=>r.json()).then(d=>({ip:d.ip, cc:d.country, asn:d.org?d.org.split(' ')[0]:'', org:d.org?d.org.substring(d.org.indexOf(' ')+1):''}))),
                    req('Ifconfig', this.fetchTimeout('https://ifconfig.co/json', {}, 3500).then(r=>r.json()).then(d=>({ip:d.ip, cc:d.country_iso, asn:d.asn?\`AS\${d.asn}\`:'', org:d.asn_org})))
                ]);
                const loc = \`\${res.cc || ''} \${res.asn || ''} \${res.org || ''}\`.trim();
                this.updateUI('overseas', 'success', res.ip, loc, res.prov, res.cc, res.asn, res.rawTime);
            } catch(e) {
                this.updateUI('overseas', 'error', '', '');
            }
        },

        async probeCF() {
            try {
                const t0 = performance.now();
                const req = (name, p) => p.then(d => { 
                    const t = Math.round(performance.now() - t0); 
                    d.prov = \`\${name} ⚡\${t}ms\`; 
                    d.rawTime = t; 
                    return d; 
                });
                const res = await Promise.any([
                    req('CF Trace', this.fetchTimeout('https://cloudflare.com/cdn-cgi/trace').then(r=>r.text()).then(t => {
                        const m = t.match(/ip=(.+)/); const l = t.match(/loc=(.+)/);
                        if(!m) throw 'No CF IP'; return {ip:m[1], cc:l?l[1]:''};
                    })),
                    req('CF v4 API', this.fetchTimeout('https://ipv4.090227.xyz').then(r=>r.json()).then(d=>({ip:d.ip, cc:d.country})))
                ]);
                const info = await this.getIpInfo(res.ip).catch(() => ({ip: res.ip, loc: res.cc, cc: res.cc, asn: ''}));
                this.updateUI('cf', 'success', info.ip, info.loc, res.prov, info.cc, info.asn, res.rawTime);
            } catch(e) {
                this.updateUI('cf', 'error', '', '');
            }
        },

        async probeOutside() {
            try {
                const t0 = performance.now();
                const req = (name, p) => p.then(d => { 
                    if(!d.ip) throw 'e'; 
                    const t = Math.round(performance.now() - t0); 
                    d.prov = \`\${name} ⚡\${t}ms\`; 
                    d.rawTime = t; 
                    return d; 
                });
                const res = await Promise.any([
                    req('X.com', this.fetchTimeout('https://help.x.com/cdn-cgi/trace').then(r=>r.text()).then(t => {
                        const m = t.match(/ip=(.+)/); if(!m) throw 'No X IP'; return {ip:m[1]};
                    })),
                    req('Google', this.jsonp('https://jsonp-ip.appspot.com/', 'callback', 3500))
                ]);
                const info = await this.getIpInfo(res.ip).catch(() => ({ip: res.ip, loc: 'Unknown', cc: '', asn: ''}));
                this.updateUI('outside', 'success', info.ip, info.loc, res.prov, info.cc, info.asn, res.rawTime);
            } catch(e) {
                this.updateUI('outside', 'error', '', '');
            }
        },

        async init() {
            await Promise.allSettled([
                this.probeDomestic(),
                this.probeOverseas(),
                this.probeCF(),
                this.probeOutside()
            ]);
            
            const dom = this.dataMap['ipip'];
            const ovs = this.dataMap['overseas'];
            
            if (dom && ovs && dom.ip && ovs.ip) {
                if (dom.ip !== ovs.ip) {
                    const isV4 = (ip) => ip.includes('.');
                    const isV6 = (ip) => ip.includes(':');
                    
                    let networkMismatch = false;
                    
                    if ((isV4(dom.ip) && isV4(ovs.ip)) || (isV6(dom.ip) && isV6(ovs.ip))) {
                        if (!isSameSubnet(dom.ip, ovs.ip)) {
                            networkMismatch = true;
                        }
                    } else {
                        if (dom.cc && ovs.cc && dom.cc !== ovs.cc) {
                            setTimeout(() => {
                                updateProxyRadar(50, 'SPLIT_TUNNEL_GEO', \`Geo-Routing Divergence (\${dom.cc} vs \${ovs.cc})\`, '客户端跨域分流：国内与国外出口节点地理位置不一致 (绝对确认代理)', 'danger');
                            }, 500);
                        }
                    }
                    
                    if (dom.asn && ovs.asn && dom.asn !== ovs.asn) {
                        setTimeout(() => {
                            const addScore = networkMismatch ? 45 : 10;
                            updateProxyRadar(addScore, 'SPLIT_TUNNEL_ASN', \`ASN Routing Divergence (\${dom.asn} vs \${ovs.asn})\`, '客户端分流(ASN级别)：国内与国外出口隶属不同自治系统 (确认代理策略路由)', 'danger');
                        }, 600);
                    } else if (dom.asn && ovs.asn && dom.asn === ovs.asn && networkMismatch) {
                        setTimeout(() => {
                            updateProxyRadar(20, 'SPLIT_TUNNEL_SUBNET', \`Egress IP Divergence (\${dom.ip} vs \${ovs.ip})\`, '出口IP漂移：国内与国外出口IP不一致且跨网段但同属同一ASN (疑似透明代理/负载分流)', 'warning');
                        }, 650);
                    }
                }
            }

            // [v1.9.46] Core RTT Latency Inversion Check
            if (dom && ovs && dom.rawTime > 0 && ovs.rawTime > 0) {
                if (dom.rawTime > 250 && ovs.rawTime < 100) {
                    setTimeout(() => {
                        updateProxyRadar(20, 'LATENCY_INVERSION', \`Routing Latency Inversion (Dom:\${dom.rawTime}ms / Ovs:\${ovs.rawTime}ms)\`, '物理延时倒挂：国内节点响应极慢而海外极快 (高度疑似物理位置在海外或使用全局中转代理)', 'warning');
                    }, 800);
                }
            }
            
            if (SERVER_ASN !== 'Unknown') {
                if (dom && dom.asn && dom.asn !== SERVER_ASN) {
                    setTimeout(() => {
                        updateProxyRadar(25, 'DOM_SERVER_ASN_MISMATCH', \`Domestic Exit vs Server ASN (\${dom.asn} vs \${SERVER_ASN})\`, '国内探测出口与服务端握手节点跨ASN (疑似前置代理拦截)', 'warning');
                    }, 700);
                }
                if (ovs && ovs.asn && ovs.asn !== SERVER_ASN) {
                    setTimeout(() => {
                        updateProxyRadar(25, 'OVS_SERVER_ASN_MISMATCH', \`Overseas Exit vs Server ASN (\${ovs.asn} vs \${SERVER_ASN})\`, '国外探测出口与服务端握手节点跨ASN (疑似分流代理穿透)', 'warning');
                    }, 750);
                }
            }
        },

        async loadLeaflet() {
            if (this.leafletLoaded) return;
            return new Promise((resolve) => {
                const link = document.createElement('link');
                link.rel = 'stylesheet'; link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
                const script = document.createElement('script');
                script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
                script.onload = () => { this.leafletLoaded = true; resolve(); };
                document.head.appendChild(link);
                document.head.appendChild(script);
            });
        },

        async showDetails(el) {
            const rawIp = el.dataset.raw;
            if(!rawIp || rawIp.includes('...')) return;
            const modal = document.getElementById('ipDetailModal');
            modal.classList.add('show');
            document.getElementById('ip-modal-basic').innerHTML = '<div class="text-center text-slate-400 py-8">Fetching Deep IP Intel...</div>';
            document.getElementById('ip-modal-security').innerHTML = '';
            
            await this.loadLeaflet();
            try {
                const d = await this.getIpInfo(rawIp);
                const raw = d.raw;
                
                document.getElementById('ip-modal-basic').innerHTML = \`
                    <div class="text-sm font-bold text-emerald-400 mb-4 uppercase tracking-wider">📍 Basic Routing</div>
                    <div class="ip-detail-row"><span>IP Address</span><span class="font-mono font-bold text-white">\${raw.ip}</span></div>
                    <div class="ip-detail-row"><span>Location</span><span class="font-mono text-white">\${raw.location?.country || ''} \${raw.location?.city || ''}</span></div>
                    <div class="ip-detail-row"><span>Timezone</span><span class="font-mono text-white">\${raw.location?.timezone || ''}</span></div>
                    <div class="ip-detail-row"><span>ISP / ASN</span><span class="font-mono text-white">\${raw.company?.name || 'Unknown'} / AS\${raw.asn?.asn || ''}</span></div>
                \`;
                
                document.getElementById('ip-modal-security').innerHTML = \`
                    <div class="text-sm font-bold text-red-400 mb-4 uppercase tracking-wider">🛡️ Security Profile</div>
                    <div class="ip-detail-row"><span>Datacenter / Hosting</span><span class="font-bold \${raw.is_datacenter?'text-amber-400':'text-green-400'}">\${raw.is_datacenter?'⚠️ YES':'✅ NO'}</span></div>
                    <div class="ip-detail-row"><span>Proxy / VPN / Tor</span><span class="font-bold \${(raw.is_proxy||raw.is_vpn||raw.is_tor)?'text-red-400':'text-green-400'}">\${(raw.is_proxy||raw.is_vpn||raw.is_tor)?'⚠️ YES':'✅ NO'}</span></div>
                    <div class="ip-detail-row"><span>Abuser Record</span><span class="font-bold \${raw.is_abuser?'text-red-400':'text-green-400'}">\${raw.is_abuser?'⚠️ YES':'✅ NO'}</span></div>
                    <div class="ip-detail-row"><span>Mobile / Cellular</span><span class="font-bold text-sky-400">\${raw.is_mobile?'📱 YES':'NO'}</span></div>
                \`;

                const lat = raw.location?.latitude; const lng = raw.location?.longitude;
                if(lat && lng) {
                    if(!this.leafletMap) {
                        this.leafletMap = L.map('ip-detail-map', {zoomControl: false, attributionControl: false}).setView([lat, lng], 4);
                        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { subdomains: 'abcd', maxZoom: 19 }).addTo(this.leafletMap);
                        this.marker = L.marker([lat, lng]).addTo(this.leafletMap);
                    } else {
                        this.leafletMap.setView([lat, lng], 4);
                        this.marker.setLatLng([lat, lng]);
                    }
                    setTimeout(() => this.leafletMap.invalidateSize(), 100);
                }
            } catch(e) {
                document.getElementById('ip-modal-basic').innerHTML = '<div class="text-center text-red-400 py-8">Failed to fetch detailed profile.</div>';
            }
        },

        closeModal(e) {
            if(e && e.target.id !== 'ipDetailModal') return;
            document.getElementById('ipDetailModal').classList.remove('show');
        }
    };

    document.addEventListener("DOMContentLoaded", () => {
        toggleLang(); toggleLang(); 
        refreshProxyRadarUI();
        
        setTimeout(() => { ClientRouteProber.init(); }, 50);

        const fpPromise = Promise.all([
            executeAsync(getCanvasFingerprint),
            executeAsync(getWebGLFingerprint),
            executeAsync(getFontFingerprint),
            executeAsync(getDOMRectFingerprint),
            getAudioFingerprint(),
            executeAsync(extractHardwareGPU),
            extractDeepHardware()
        ]);

        fpPromise.then(async ([fRawCanvas, fRawWebGL, fRawFont, fRawDOM, fRawAudio, gpuStr, deepHw]) => {
            const [hCanvas, hWebGL, hFont, hDOM, hAudio] = await Promise.all([
                sha256(fRawCanvas), sha256(fRawWebGL), sha256(fRawFont), sha256(fRawDOM), sha256(fRawAudio)
            ]);

            document.getElementById('hash-canvas').innerText = hCanvas;
            document.getElementById('hash-webgl').innerText = hWebGL;
            document.getElementById('hash-font').innerText = hFont;
            document.getElementById('hash-domrect').innerText = hDOM;
            document.getElementById('hash-audio').innerText = hAudio;

            const combinedProfileString = fRawCanvas + fRawWebGL + fRawFont + fRawDOM + fRawAudio + gpuStr + screen.width + screen.colorDepth;
            const unifiedId = await sha256(combinedProfileString);
            
            const unifiedEl = document.getElementById('unified-profile-id');
            unifiedEl.innerText = unifiedId.substring(0, 32);
            unifiedEl.classList.remove('min-w-[280px]', 'text-center');

            renderData('hardware-info-container', buildHardwareData(gpuStr, deepHw));
        }).catch(err => console.error("Hardware probe error:", err));

        const netPromise = Promise.all([
            runApiCalibration(), 
            getWebRTCLeakedIPs(), 
            fetchIpifyTunnels()
        ]);

        Promise.all([fpPromise, netPromise]).then(async ([[ , , , , , gpuStr], [calib, rtcDataObj, tunnels]]) => {
            const rtcIPsRaw = rtcDataObj.ips;
            const rtcMeta = rtcDataObj.meta || {};
            
            const globalAsnMap = {};
            if (calib.cf && calib.cf.ip && calib.cf.asn) globalAsnMap[calib.cf.ip] = calib.cf.asn;
            if (calib.geojs && calib.geojs.ip && calib.geojs.asn) globalAsnMap[calib.geojs.ip] = calib.geojs.asn;

            const ipsToFetch = [];
            if (Array.isArray(rtcIPsRaw)) {
                rtcIPsRaw.filter(isPublicIP).forEach(ip => ipsToFetch.push(ip));
            }
            if (tunnels.v4 && isPublicIP(tunnels.v4)) ipsToFetch.push(tunnels.v4);
            if (tunnels.v6 && isPublicIP(tunnels.v6)) ipsToFetch.push(tunnels.v6);

            const uniqueIpsToFetch = [...new Set(ipsToFetch)].filter(ip => !globalAsnMap[ip]);
            
            const asnPromises = uniqueIpsToFetch.map(async ip => {
                const geo = await fetchGeoIP(ip);
                if (geo && geo.connection && geo.connection.asn) {
                    globalAsnMap[ip] = 'AS' + geo.connection.asn;
                } else {
                    globalAsnMap[ip] = 'Unknown';
                }
            });
            await Promise.all(asnPromises);
            
            renderData('browser-info-container', await buildBrowserData(calib, rtcIPsRaw));
            renderData('sensor-info-container', await buildSensorNetworkData(rtcIPsRaw, globalAsnMap));
            
            runTopologyAnalysis(rtcIPsRaw, calib, tunnels, globalAsnMap);
            
            const scoreData = runBotChecks(SERVER_BASE_RISK_FACTORS, rtcIPsRaw, calib, gpuStr, rtcMeta, tunnels, globalAsnMap);

            Chart.defaults.color = '#94a3b8';
            new Chart(document.getElementById('riskChart'), {
                type: 'doughnut',
                data: { datasets: [{ data: [scoreData.finalScore, 100 - scoreData.finalScore], backgroundColor: [scoreData.riskColor, '#334155'], borderWidth: 0, circumference: 240, rotation: 240 }] },
                options: { responsive: true, maintainAspectRatio: false, cutout: '80%', animation: false, plugins: { tooltip: { enabled: false } } }
            });
        }).catch(err => {
            console.error("Network probe error:", err);
        });

        setTimeout(() => {
            const bHtml = \`
                <div class="kv-row"><span class="kv-key">Mouse Events <span class="text-xs">(鼠标事件)</span></span><span class="kv-val">\${behaviorEngine.mouseEvents} recorded</span></div>
                <div class="kv-row"><span class="kv-key">Keystrokes <span class="text-xs">(按键频率)</span></span><span class="kv-val">\${behaviorEngine.keyEvents} recorded</span></div>
                <div class="kv-row"><span class="kv-key">Touch Events <span class="text-xs">(触控频次)</span></span><span class="kv-val">\${behaviorEngine.touchEvents} recorded</span></div>
                <div class="kv-row"><span class="kv-key">Session Duration <span class="text-xs">(停留时间)</span></span><span class="kv-val">\${Date.now() - behaviorEngine.startTime} ms</span></div>
                <div class="kv-row mt-2"><span class="kv-key text-emerald-400">ML Vector Payload</span><span class="kv-val text-xs text-slate-500 font-mono">Ready for Backend XGBoost Ingestion</span></div>
            \`;
            document.getElementById('behavior-info-container').innerHTML = bHtml;
        }, 1500);
    });
</script>
<style>
    .custom-scrollbar::-webkit-scrollbar { width: 6px; }
    .custom-scrollbar::-webkit-scrollbar-track { background: #1e293b; }
    .custom-scrollbar::-webkit-scrollbar-thumb { background: #475569; border-radius: 3px; }
    .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #64748b; }
</style>
</body>
</html>`;

export default {
    async fetch(request, env, ctx) {
        // HTTP Basic Protection Rules
        const securityHeaders = {
            'Content-Type': 'text/html; charset=utf-8',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        };

        const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
        const ua = request.headers.get('user-agent') || '';

        // 0. Defense Grade WAF active + Rapid Bot Header Pre-flight Checks
        if (!wafCheck(clientIp, ctx) || ua === '') {
            return new Response('{"error": "Defense-Grade WAF Active: Rate Limit Exceeded or Invalid Headers.", "code": 429}', {
                status: 429,
                headers: { 'Retry-After': '60', 'Content-Type': 'application/json' }
            });
        }

        // 1. IP Parsing
        const ipInfo = getAllClientIPs(request);
        const advancedProxies = detectAdvancedProxy(request);
        const ipContext = await getIpContextClassification(ipInfo.real_client_ip, request.cf, ctx);

        // 2. Risk Matrix & Scoring Port
        const proxyRadar = evaluateProxyRiskMatrix(ipInfo, advancedProxies, ipContext, request);
        
        let allDetectedIps = new Set();
        let serverIpDetails = {};

        if (ipInfo.real_client_ip !== 'Unknown') {
            allDetectedIps.add(ipInfo.real_client_ip);
            serverIpDetails[ipInfo.real_client_ip] = ['HTTP_REMOTE_ADDR (CF-Connecting-IP)'];
        }

        const ipSourceKeys = Object.keys(ipInfo.all_sources);
        for (let i = 0; i < ipSourceKeys.length; i++) {
            const header = ipSourceKeys[i];
            const ips = ipInfo.all_sources[header];
            for (let j = 0; j < ips.length; j++) {
                const ip = ips[j];
                allDetectedIps.add(ip);
                if (!serverIpDetails[ip]) serverIpDetails[ip] = [];
                if (!serverIpDetails[ip].includes(`Header: ${header}`)) {
                    serverIpDetails[ip].push(`Header: ${header}`);
                }
            }
        }
        allDetectedIps = Array.from(allDetectedIps);

        const isHttps = request.url.startsWith('https://');
        const tlsVersion = request.cf?.tlsVersion || (isHttps ? 'Unknown TLS' : 'Plain HTTP');
        const tlsCipher = request.cf?.tlsCipher || 'Unknown Cipher';
        const httpEncoding = request.headers.get('accept-encoding') || '';
        const httpLang = request.headers.get('accept-language') || '';
        
        const pseudoTlsStr = `${tlsVersion}|${tlsCipher}|${httpEncoding}|${httpLang}`;
        const pseudoTlsHash = await sha256(pseudoTlsStr);

        let serverNetScore = 0;
        let serverRiskFactors = [];
        
        if (ipInfo.is_header_spoofed) {
            serverNetScore += 55;
            serverRiskFactors.push({c: 'Network', en: 'Untrusted Gateway Headers Spoofed (+55)', zh: '非可信网关注入代理头/源IP伪造 (+55)', s: 55});
        }
        // Specific Proxy Hops evaluation (CF Exempted)
        if (ipInfo.proxy_hops) {
            serverNetScore += 10;
            serverRiskFactors.push({c: 'Network', en: 'X-Forwarded-For Multi-Hop Detected (+10)', zh: '检测到 X-Forwarded-For 多层代理转发 (+10)', s: 10});
        }
        if (request.headers.has('via')) {
            serverNetScore += 15;
            serverRiskFactors.push({c: 'Network', en: 'VIA Header Detected (+15)', zh: '检测到 VIA 代理头 (+15)', s: 15});
        }
        if (advancedProxies.length > 0 && !request.headers.has('via')) {
            serverNetScore += 20;
            serverRiskFactors.push({c: 'Network', en: 'Advanced Proxy Protocols (+20)', zh: '检测到隐蔽代理特征头 (+20)', s: 20});
        }
        if (ipContext.is_datacenter) {
            serverNetScore += 20;
            serverRiskFactors.push({c: 'Network', en: 'Datacenter/Hosting ASN (+20)', zh: 'ASN/IP 归属为机房云厂商 (+20)', s: 20});
        }
        if (ipContext.is_proxy) {
            serverNetScore += 40;
            serverRiskFactors.push({c: 'Network', en: 'Known Proxy/VPN/Tor in DB (+40)', zh: '威胁情报标记为已知代理节点 (+40)', s: 40});
        }
        
        if (ua.includes('Headless')) {
            serverNetScore += 50;
            serverRiskFactors.push({c: 'Browser', en: 'Headless Browser UA (+50)', zh: '无头浏览器 User-Agent (+50)', s: 50});
        }
        if (/(curl|python|wget|postman|go-http|java|nikto|nmap)/i.test(ua)) {
            serverNetScore += 40;
            serverRiskFactors.push({c: 'Browser', en: 'Scripting Tool/Scanner (+40)', zh: '检测到脚本工具/扫描器 (+40)', s: 40});
        }

        const isIPv6 = ipInfo.real_client_ip.includes(':');
        const isProxyDetected = (ipInfo.proxy_hops || advancedProxies.length > 0 || ipContext.is_datacenter || ipContext.is_proxy || ipInfo.is_header_spoofed);

        let zhType = '未知网络';
        if (ipContext.is_proxy) zhType = '已知代理 / VPN节点';
        else if (ipContext.is_datacenter) zhType = '数据中心 / 云厂商 / CDN';
        else if (ipContext.is_mobile) zhType = '移动蜂窝网络 (4G/5G)';
        else zhType = '家庭住宅宽带';

        // Matrix Render (Pre-compiled string)
        let matrixHtml = '';
        const matrixKeys = Object.keys(proxyRadar.matrix);
        for (let i = 0; i < matrixKeys.length; i++) {
            const dim = matrixKeys[i];
            const res = proxyRadar.matrix[dim];
            const colorClass = res.level === 'safe' ? 'text-green-400' : (res.level === 'warning' ? 'text-amber-400' : 'text-red-400');
            matrixHtml += `<span class="bg-slate-800/50 px-2 py-1 rounded border border-slate-700/50"><span class="text-slate-400 font-mono">[${dim.toUpperCase()}]</span> <span class="${colorClass} font-medium"><span class="en-only">${escapeHTML(res.en)}</span><span class="zh-only">${escapeHTML(res.zh)}</span></span></span>`;
        }

        // Risk details Render (Pre-compiled string)
        let riskDetailsHtml = '';
        for (let i = 0; i < serverRiskFactors.length; i++) {
            const factor = serverRiskFactors[i];
            riskDetailsHtml += `<div class="kv-row"><span class="kv-key text-red-400">[${escapeHTML(factor.c)}]</span><span class="kv-val text-red-400"><span class="en-only">${escapeHTML(factor.en)}</span><span class="zh-only">${escapeHTML(factor.zh)}</span></span></div>`;
        }

        // Headers Render (Pre-compiled string)
        let headersHtml = '';
        let headerCount = 0;
        for (const [name, value] of request.headers) {
            if(name.startsWith('cf-') && name !== 'cf-connecting-ip') continue; 
            headerCount++;
            headersHtml += `<div class="kv-row"><span class="kv-key text-xs">${escapeHTML(name)}</span><span class="kv-val text-xs text-slate-300">${escapeHTML(value)}</span></div>`;
        }

        // 3. Render HTML - V8 Dictionary Single-Pass Regex Replace
        const templateReplacements = {
            '__PROXY_RADAR_MATRIX__': matrixHtml,
            '__RADAR_SCORE__': proxyRadar.score,
            '__CLIENT_IP__': escapeHTML(ipInfo.real_client_ip),
            '__IPV6_BADGE_CLASS__': isIPv6 ? 'badge-green' : 'badge-yellow',
            '__IPV6_TEXT__': isIPv6 ? 'IPv6' : 'IPv4',
            '__IP_TYPE_EN__': escapeHTML(ipContext.type),
            '__IP_TYPE_ZH__': escapeHTML(zhType),
            '__PROXY_BADGE_CLASS__': isProxyDetected ? 'badge-red' : 'badge-green',
            '__PROXY_TEXT_EN__': isProxyDetected ? 'Proxy' : 'Clean',
            '__PROXY_TEXT_ZH__': isProxyDetected ? '代理特征' : '原生环境',
            '__ASN__': escapeHTML(ipContext.asn),
            '__ISP__': escapeHTML(ipContext.isp),
            '__RISK_DETAILS__': riskDetailsHtml,
            '__PSEUDO_TLS_STR__': escapeHTML(pseudoTlsStr),
            '__PSEUDO_TLS_HASH__': pseudoTlsHash,
            '__HEADERS_COUNT__': headerCount,
            '__HEADERS_LIST__': headersHtml,
            '__JSON_SERVER_CC__': JSON.stringify(ipContext.country_code),
            '__JSON_SERVER_TZ__': JSON.stringify(ipContext.timezone),
            '__JSON_SERVER_ASN__': JSON.stringify(ipContext.asn),
            '__JSON_DETECTED_IPS__': JSON.stringify(allDetectedIps),
            '__JSON_IP_DETAILS__': JSON.stringify(serverIpDetails),
            '__JSON_RISK_FACTORS__': JSON.stringify(serverRiskFactors),
            '__JSON_RADAR_SCORE__': JSON.stringify(proxyRadar.score),
            '__JSON_SERVER_RTT__': JSON.stringify(request.cf?.clientTcpRtt || 0)
        };

        const htmlRendered = HTML_TEMPLATE.replace(
            /__(PROXY_RADAR_MATRIX|RADAR_SCORE|CLIENT_IP|IPV6_BADGE_CLASS|IPV6_TEXT|IP_TYPE_EN|IP_TYPE_ZH|PROXY_BADGE_CLASS|PROXY_TEXT_EN|PROXY_TEXT_ZH|ASN|ISP|RISK_DETAILS|PSEUDO_TLS_STR|PSEUDO_TLS_HASH|HEADERS_COUNT|HEADERS_LIST|JSON_SERVER_CC|JSON_SERVER_TZ|JSON_SERVER_ASN|JSON_DETECTED_IPS|JSON_IP_DETAILS|JSON_RISK_FACTORS|JSON_RADAR_SCORE|JSON_SERVER_RTT)__/g,
            match => templateReplacements[match]
        );

        return new Response(htmlRendered, {
            headers: securityHeaders
        });
    }
};
