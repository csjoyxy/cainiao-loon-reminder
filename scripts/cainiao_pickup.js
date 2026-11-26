/**
 * 菜鸟驿站每日待取提醒（Loon 专用本地直连版）
 *
 * 安全设计说明：
 * 1. 零第三方服务器：所有网络请求仅发往官方 https://h5api.m.taobao.com 且强制 node: "DIRECT" 直连。
 * 2. 日常零 MitM 零额外耗电：仅首次配置开启 10 秒抓一次淘宝 H5 Cookie，抓完即可关闭开关与插件 MitM。
 * 3. 本地存储加密隔离：使用插件私有参数 vault_pin 派生随机存储键名并加密 Cookie（优先 AES-256-GCM，兼容流式混淆），
 *    防止 Loon 内其他第三方脚本跨脚本遍历 $persistentStore 偷取凭证。
 */

const HOST = "https://h5api.m.taobao.com";
const APP_KEY = "12574478";
const JSV = "2.7.4";
const REFERER = "https://h5.m.taobao.com/";
const ORIGIN = "https://h5.m.taobao.com";
const UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

const API_PDS_LIST = "mtop.cainiao.lpc.packageservice.queryPdsPackageDataList";
const NEED_DYN_INFO = "{'needFindTemporality':true,'needAppointment':true}";
const RETRY_MARKERS = ["TOKEN_EMPTY", "TOKEN_EXPIRED", "TOKEN_EXOIRED", "ILLEGAL_ACCESS"];
const SESSION_EXPIRED_MARKERS = [
  "SESSION_EXPIRED",
  "FAIL_SYS_SESSION_EXPIRED",
  "NOT_LOGIN",
  "USER_NOT_LOGIN",
  "NEED_LOGIN",
];
const RISK_MARKERS = ["RGV587_ERROR", "TRAFFIC_LIMIT", "FAIL_BIZ_SYS_LIMIT"];
const DONE_STATUS = new Set(["SIGN", "CANCEL", "REJECT", "RETURN", "LOST"]);
const MAX_PAGES = 5;

// ───────────────────────── UTF-8 & RFC 1321 MD5 ─────────────────────────

function utf8ToBytes(str) {
  const s = String(str == null ? "" : str);
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const c2 = s.charCodeAt(i + 1);
      if (c2 >= 0xdc00 && c2 <= 0xdfff) {
        const cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
        out.push(
          0xf0 | (cp >> 18),
          0x80 | ((cp >> 12) & 0x3f),
          0x80 | ((cp >> 6) & 0x3f),
          0x80 | (cp & 0x3f)
        );
        i++;
      } else {
        out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      }
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return new Uint8Array(out);
}

function bytesToUtf8(bytes) {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i++];
    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
    } else if ((b0 & 0xe0) === 0xc0) {
      const b1 = bytes[i++] & 0x3f;
      out += String.fromCharCode(((b0 & 0x1f) << 6) | b1);
    } else if ((b0 & 0xf0) === 0xe0) {
      const b1 = bytes[i++] & 0x3f;
      const b2 = bytes[i++] & 0x3f;
      out += String.fromCharCode(((b0 & 0x0f) << 12) | (b1 << 6) | b2);
    } else {
      const b1 = bytes[i++] & 0x3f;
      const b2 = bytes[i++] & 0x3f;
      const b3 = bytes[i++] & 0x3f;
      const cp = (((b0 & 0x07) << 18) | (b1 << 12) | (b2 << 6) | b3) - 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    }
  }
  return out;
}

function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
  }
  return hex;
}

function hexToBytes(hex) {
  const clean = String(hex || "").trim();
  if (!clean || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    return new Uint8Array(0);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const MD5_K = new Int32Array(64);
const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
for (let i = 0; i < 64; i++) {
  MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
}

function md5Bytes(inputBytes) {
  const len = inputBytes.length;
  const bitLenLo = (len * 8) >>> 0;
  const bitLenHi = Math.floor((len * 8) / 4294967296) >>> 0;
  const totalLen = (((len + 8) >>> 6) + 1) << 6;
  const buf = new Uint8Array(totalLen);
  buf.set(inputBytes);
  buf[len] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(totalLen - 8, bitLenLo, true);
  view.setUint32(totalLen - 4, bitLenHi, true);

  let a0 = 0x67452301 | 0;
  let b0 = 0xefcdab89 | 0;
  let c0 = 0x98badcfe | 0;
  let d0 = 0x10325476 | 0;
  const M = new Int32Array(16);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let j = 0; j < 16; j++) {
      M[j] = view.getInt32(offset + j * 4, true);
    }
    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;

    for (let i = 0; i < 64; i++) {
      let F = 0;
      let g = 0;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      const sum = (A + F + MD5_K[i] + M[g]) | 0;
      A = D;
      D = C;
      C = B;
      const s = MD5_S[i];
      B = (B + ((sum << s) | (sum >>> (32 - s)))) | 0;
    }

    a0 = (a0 + A) | 0;
    b0 = (b0 + B) | 0;
    c0 = (c0 + C) | 0;
    d0 = (d0 + D) | 0;
  }

  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  outView.setInt32(0, a0, true);
  outView.setInt32(4, b0, true);
  outView.setInt32(8, c0, true);
  outView.setInt32(12, d0, true);
  return out;
}

function md5(str) {
  return bytesToHex(md5Bytes(utf8ToBytes(str)));
}

// ───────────────────────── 本地隔离加密存储 ─────────────────────────

function deriveKey32(vaultPin) {
  const p = String(vaultPin || "cn-local-v1");
  const k1 = md5Bytes(utf8ToBytes("cainiao-k1:" + p));
  const k2 = md5Bytes(utf8ToBytes("cainiao-k2:" + p));
  const key = new Uint8Array(32);
  key.set(k1, 0);
  key.set(k2, 16);
  return key;
}

function storageKeys(vaultPin) {
  const suffix = md5("cainiao-slot-v1:" + String(vaultPin || "cn-local-v1")).slice(0, 16);
  return {
    vaultKey: "cn_vault_" + suffix,
    metaKey: "cn_meta_" + suffix,
  };
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  let seed = Date.now() ^ Math.floor(Math.random() * 0xffffffff);
  for (let i = 0; i < n; i++) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    b[i] = (seed ^ Math.floor(Math.random() * 256)) & 0xff;
  }
  return b;
}

function ctrTransform(dataBytes, key32, nonce8) {
  const out = new Uint8Array(dataBytes.length);
  let blockIndex = 0;
  for (let offset = 0; offset < dataBytes.length; offset += 16) {
    const blockInput = new Uint8Array(44);
    blockInput.set(key32, 0);
    blockInput.set(nonce8, 32);
    new DataView(blockInput.buffer).setUint32(40, blockIndex++, true);
    const stream = md5Bytes(blockInput);
    const end = Math.min(16, dataBytes.length - offset);
    for (let j = 0; j < end; j++) {
      out[offset + j] = dataBytes[offset + j] ^ stream[j];
    }
  }
  return out;
}

function encryptText(plainText, vaultPin) {
  const plainBytes = utf8ToBytes(plainText);
  const key32 = deriveKey32(vaultPin);

  if (
    typeof $crypto !== "undefined" &&
    $crypto &&
    $crypto.aes &&
    typeof $crypto.aes.encrypt === "function"
  ) {
    try {
      const iv = randomBytes(12);
      const enc = $crypto.aes.encrypt(plainBytes, {
        mode: "gcm",
        key: key32,
        iv: iv,
      });
      if (enc && enc.ciphertext && enc.tag) {
        return "gcm1:" + bytesToHex(iv) + ":" + bytesToHex(enc.tag) + ":" + bytesToHex(enc.ciphertext);
      }
    } catch (_) {
      // 降级到流式混淆
    }
  }

  const nonce = randomBytes(8);
  const cipher = ctrTransform(plainBytes, key32, nonce);
  const mac = md5Bytes(
    utf8ToBytes("mac:" + bytesToHex(key32) + ":" + bytesToHex(nonce) + ":" + bytesToHex(cipher))
  ).slice(0, 8);
  return "ctr1:" + bytesToHex(nonce) + ":" + bytesToHex(mac) + ":" + bytesToHex(cipher);
}

function decryptText(payload, vaultPin) {
  if (!payload || typeof payload !== "string") return "";
  const key32 = deriveKey32(vaultPin);
  const parts = payload.split(":");

  if (parts[0] === "gcm1" && parts.length === 4) {
    if (
      typeof $crypto !== "undefined" &&
      $crypto &&
      $crypto.aes &&
      typeof $crypto.aes.decrypt === "function"
    ) {
      try {
        const iv = hexToBytes(parts[1]);
        const tag = hexToBytes(parts[2]);
        const ciphertext = hexToBytes(parts[3]);
        const plain = $crypto.aes.decrypt(ciphertext, {
          mode: "gcm",
          key: key32,
          iv: iv,
          tag: tag,
        });
        return bytesToUtf8(plain);
      } catch (_) {
        return "";
      }
    }
    return "";
  }

  if (parts[0] === "ctr1" && parts.length === 4) {
    const nonce = hexToBytes(parts[1]);
    const macHex = parts[2];
    const cipher = hexToBytes(parts[3]);
    if (nonce.length !== 8) return "";
    const expectedMac = bytesToHex(
      md5Bytes(
        utf8ToBytes("mac:" + bytesToHex(key32) + ":" + parts[1] + ":" + parts[3])
      ).slice(0, 8)
    );
    if (expectedMac !== macHex) return "";
    return bytesToUtf8(ctrTransform(cipher, key32, nonce));
  }

  return "";
}

function readCookieJar(cfg) {
  if (cfg.manualCookie) {
    return parseCookieHeader(cfg.manualCookie);
  }
  if (typeof $persistentStore === "undefined") return {};
  const { vaultKey } = storageKeys(cfg.vaultPin);
  const raw = $persistentStore.read(vaultKey);
  if (!raw) return {};
  const jsonText = decryptText(raw, cfg.vaultPin);
  if (!jsonText) return {};
  try {
    const parsed = JSON.parse(jsonText);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (_) {
    return {};
  }
}

function writeCookieJar(jar, cfg) {
  if (typeof $persistentStore === "undefined") return false;
  const { vaultKey } = storageKeys(cfg.vaultPin);
  const enc = encryptText(JSON.stringify(jar), cfg.vaultPin);
  return Boolean($persistentStore.write(enc, vaultKey));
}

// ───────────────────────── Cookie 解析与合并 ─────────────────────────

function parseCookieHeader(rawHeader) {
  const jar = {};
  if (!rawHeader || typeof rawHeader !== "string") return jar;
  const parts = rawHeader.split(";");
  for (let i = 0; i < parts.length; i++) {
    const item = parts[i].trim();
    if (!item) continue;
    const eq = item.indexOf("=");
    if (eq <= 0) continue;
    const name = item.slice(0, eq).trim();
    const value = item.slice(eq + 1).trim();
    if (name && value) {
      jar[name] = value;
    }
  }
  return jar;
}

function serializeCookieJar(jar) {
  const pairs = [];
  const keys = Object.keys(jar || {});
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    const v = jar[k];
    if (k && v != null && String(v) !== "") {
      pairs.push(k + "=" + String(v));
    }
  }
  return pairs.join("; ");
}

/**
 * 兼容 iOS NSHTTPURLResponse 将多条 Set-Cookie 用 ", " 拼接的情况，
 * 避免把 Expires=Thu, 03-Dec-2026 里的逗号误切开。
 */
function splitSetCookieHeader(rawSetCookie) {
  if (!rawSetCookie) return [];
  const items = Array.isArray(rawSetCookie) ? rawSetCookie : [String(rawSetCookie)];
  const out = [];
  for (let i = 0; i < items.length; i++) {
    const s = String(items[i] || "").trim();
    if (!s) continue;
    const segments = s.split(/,(?=\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/);
    for (let j = 0; j < segments.length; j++) {
      const trimmed = segments[j].trim();
      if (trimmed) out.push(trimmed);
    }
  }
  return out;
}

function absorbSetCookiesFromHeaders(headers, jar) {
  if (!headers || typeof headers !== "object") return false;
  let changed = false;
  const keys = Object.keys(headers);
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() !== "set-cookie") continue;
    const lines = splitSetCookieHeader(headers[keys[i]]);
    for (let j = 0; j < lines.length; j++) {
      const segs = lines[j].split(";");
      const nv = segs[0].trim();
      const eq = nv.indexOf("=");
      if (eq <= 0) continue;
      const name = nv.slice(0, eq).trim();
      const value = nv.slice(eq + 1).trim();
      if (!name) continue;
      const deleted =
        !value ||
        value === "deleted" ||
        segs.some((attr) => /^max-age\s*=\s*0$/i.test(attr.trim()));
      if (deleted) {
        if (name in jar) {
          delete jar[name];
          changed = true;
        }
      } else if (jar[name] !== value) {
        jar[name] = value;
        changed = true;
      }
    }
  }
  return changed;
}

function isAuthenticatedTaobaoJar(jar) {
  if (!jar || typeof jar !== "object") return false;
  const hasUserMarker = Boolean(jar.unb || jar.sgcookie || jar.lgc || jar.tracknick || jar._nk_);
  const hasSessionMarker = Boolean(jar.cookie2 || jar._tb_token_ || jar._samesite_flag_ || jar.uc1);
  return hasUserMarker && hasSessionMarker;
}

function accountLabelFromJar(jar) {
  const rawNick = jar.tracknick || jar.lgc || jar._nk_ || "";
  if (rawNick) {
    try {
      const unescaped = decodeURIComponent(
        rawNick.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
      );
      if (unescaped) return unescaped;
    } catch (_) {
      return rawNick;
    }
  }
  if (jar.unb) {
    const u = String(jar.unb);
    return u.length > 4 ? "UID ***" + u.slice(-4) : "UID " + u;
  }
  return "已登录淘宝账号";
}

// ───────────────────────── 参数与运行环境 ─────────────────────────

function parseConfig(rawArg) {
  let obj = {};
  if (rawArg && typeof rawArg === "object") {
    obj = rawArg;
  } else if (typeof rawArg === "string" && rawArg.trim()) {
    const s = rawArg.trim();
    if (s.startsWith("{")) {
      try {
        obj = JSON.parse(s);
      } catch (_) {}
    } else {
      s.split("&").forEach((pair) => {
        const eq = pair.indexOf("=");
        if (eq > 0) {
          obj[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1));
        }
      });
    }
  }

  const toBool = (v, def) => {
    if (typeof v === "boolean") return v;
    if (typeof v === "string") {
      if (v.toLowerCase() === "true" || v === "1") return true;
      if (v.toLowerCase() === "false" || v === "0") return false;
    }
    return def;
  };

  return {
    captureCookie: toBool(obj.capture_cookie, false),
    notifyEmpty: toBool(obj.notify_empty, false),
    openTarget: String(obj.open_target || "cainiao://desktop/station_code").trim(),
    vaultPin: String(obj.vault_pin || "cn-local-v1").trim() || "cn-local-v1",
    manualCookie: String(obj.manual_cookie || "").trim(),
  };
}

function isManualTrigger() {
  if (typeof $script !== "undefined" && $script && typeof $script.name === "string") {
    if ($script.name.indexOf("立即检测") !== -1) return true;
  }
  return false;
}

function sendNotification(title, subtitle, content, attach) {
  if (typeof $notification !== "undefined" && $notification && typeof $notification.post === "function") {
    $notification.post(title || "", subtitle || "", content || "", attach || undefined);
  } else {
    console.log("[通知] " + [title, subtitle, content].filter(Boolean).join(" | "));
  }
}

// ───────────────────────── 1. 请求阶段：捕获 Cookie ─────────────────────────

function handleCaptureRequest(cfg, done) {
  try {
    const headers = ($request && $request.headers) || {};
    let cookieHeader = "";
    const hKeys = Object.keys(headers);
    for (let i = 0; i < hKeys.length; i++) {
      if (hKeys[i].toLowerCase() === "cookie") {
        cookieHeader = String(headers[hKeys[i]] || "");
        break;
      }
    }

    if (!cookieHeader) {
      done({});
      return;
    }

    const incoming = parseCookieHeader(cookieHeader);
    if (!isAuthenticatedTaobaoJar(incoming)) {
      console.log("[菜鸟提醒] 检测到匿名请求，等待完成淘宝登录...");
      done({});
      return;
    }

    const merged = Object.assign({}, readCookieJar({ vaultPin: cfg.vaultPin, manualCookie: "" }), incoming);
    const saved = writeCookieJar(merged, cfg);
    const sig = md5((merged.unb || "") + "|" + (merged.cookie2 || "") + "|" + (merged.sgcookie || ""));
    const { metaKey } = storageKeys(cfg.vaultPin);

    let lastMeta = {};
    if (typeof $persistentStore !== "undefined") {
      try {
        lastMeta = JSON.parse($persistentStore.read(metaKey) || "{}");
      } catch (_) {}
    }

    const now = Date.now();
    if (saved && (lastMeta.sig !== sig || now - Number(lastMeta.at || 0) > 60000)) {
      if (typeof $persistentStore !== "undefined") {
        $persistentStore.write(JSON.stringify({ sig: sig, at: now }), metaKey);
      }
      sendNotification(
        "✅ 菜鸟/淘宝登录态捕获成功",
        "账号：" + accountLabelFromJar(merged),
        "请回到 Loon 插件设置关闭「抓取Cookie临时开关」及插件右上角「MitM」，随后可点「立即检测一次待取快递」验证。",
        { openUrl: "loon://" }
      );
      console.log("[菜鸟提醒] 已加密保存登录 Cookie（键数：" + Object.keys(merged).length + "）");
    }
  } catch (e) {
    console.log("[菜鸟提醒] 捕获 Cookie 异常: " + String(e));
  }
  done({});
}

// ───────────────────────── 2. MTOP H5 网关客户端 ─────────────────────────

function buildMtopUrl(api, version, dataObj, jar) {
  const dataStr = JSON.stringify(dataObj);
  const t = String(Date.now());
  const rawTk = String((jar && jar._m_h5_tk) || "");
  const token = rawTk.split("_")[0] || "";
  const sign = md5(token + "&" + t + "&" + APP_KEY + "&" + dataStr);
  const params = [
    ["jsv", JSV],
    ["appKey", APP_KEY],
    ["t", t],
    ["sign", sign],
    ["api", api],
    ["v", version],
    ["type", "originaljson"],
    ["dataType", "json"],
    ["data", dataStr],
  ]
    .map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v))
    .join("&");

  return HOST + "/h5/" + api.toLowerCase() + "/" + version + "/?" + params;
}

function httpGetDirect(url, cookieHeader) {
  return new Promise((resolve) => {
    $httpClient.get(
      {
        url: url,
        timeout: 15000,
        node: "DIRECT",
        "auto-cookie": false,
        headers: {
          Cookie: cookieHeader,
          Referer: REFERER,
          Origin: ORIGIN,
          "User-Agent": UA,
          Accept: "application/json, text/plain, */*",
          "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        },
      },
      (error, response, data) => {
        resolve({ error: error, response: response, data: typeof data === "string" ? data : "" });
      }
    );
  });
}

function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callMtop(api, dataObj, jar, cfg, version = "1.0", maxRetries = 4) {
  let jarUpdated = false;
  let lastJson = null;
  let lastError = "";

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const url = buildMtopUrl(api, version, dataObj, jar);
    const { error, response, data } = await httpGetDirect(url, serializeCookieJar(jar));

    if (response && response.headers) {
      if (absorbSetCookiesFromHeaders(response.headers, jar)) {
        jarUpdated = true;
      }
    }

    if (error) {
      lastError = String(error);
      await sleepMs(400 * (attempt + 1));
      continue;
    }

    let json = null;
    try {
      json = JSON.parse(data);
    } catch (_) {
      if (data && data.indexOf("punish") !== -1) {
        return { ok: false, kind: "risk", message: "触发淘宝网关滑块验证（punish）" };
      }
      lastError = "响应非 JSON (HTTP " + ((response && response.status) || "?") + ")";
      await sleepMs(400 * (attempt + 1));
      continue;
    }

    lastJson = json;
    const ret0 = String((Array.isArray(json.ret) && json.ret[0]) || "");
    const upper = ret0.toUpperCase();

    if (upper.startsWith("SUCCESS")) {
      if (jarUpdated && !cfg.manualCookie) {
        writeCookieJar(jar, cfg);
      }
      return { ok: true, json: json, ret0: ret0 };
    }

    if (SESSION_EXPIRED_MARKERS.some((m) => upper.indexOf(m) !== -1)) {
      return { ok: false, kind: "session_expired", message: ret0 };
    }

    if (RISK_MARKERS.some((m) => upper.indexOf(m) !== -1) || data.slice(0, 300).indexOf("punish") !== -1) {
      return { ok: false, kind: "risk", message: ret0 || "触发接口风控限流" };
    }

    if (RETRY_MARKERS.some((m) => upper.indexOf(m) !== -1)) {
      await sleepMs(300 + attempt * 250);
      continue;
    }

    return { ok: false, kind: "business", message: ret0 || "未知网关返回" };
  }

  if (jarUpdated && !cfg.manualCookie) {
    writeCookieJar(jar, cfg);
  }
  const fallbackRet = lastJson && Array.isArray(lastJson.ret) ? lastJson.ret[0] : "";
  return {
    ok: false,
    kind: "network",
    message: fallbackRet || lastError || "请求重试耗尽",
  };
}

// ───────────────────────── 3. 包裹列表解析与分类 ─────────────────────────

function firstStr(obj, keys) {
  if (!obj || typeof obj !== "object") return "";
  for (let i = 0; i < keys.length; i++) {
    const v = obj[keys[i]];
    if (typeof v === "string") {
      const t = v.trim();
      if (t && t !== "null" && t !== "undefined" && t !== "0" && t !== "-1") {
        return t;
      }
    } else if (typeof v === "number" && v > 0) {
      return String(v);
    }
  }
  return "";
}

function extractPackagesArray(payload) {
  if (!payload || typeof payload !== "object") return [];
  const inner = (payload.data && payload.data.data) || payload.data || payload;
  const candidates = ["packages", "packageList", "packageInfoList", "packageDataList", "list", "items"];
  for (let i = 0; i < candidates.length; i++) {
    const arr = inner[candidates[i]];
    if (Array.isArray(arr)) return arr;
  }
  return [];
}

function extractTotalPages(payload) {
  const inner = (payload && payload.data && payload.data.data) || (payload && payload.data) || {};
  const n = Number(inner.totalPage || inner.totalPages || 1);
  return Number.isFinite(n) && n >= 1 ? Math.min(n, MAX_PAGES) : 1;
}

function parsePickupCode(pkg, stationObj) {
  const rawAuth = firstStr(stationObj, ["authCode", "auth_code"]);
  const isNeedSms = /^needsms|need_sms$/i.test(rawAuth);

  const candidates = [
    !isNeedSms ? rawAuth : "",
    firstStr(stationObj, ["showPickupCode", "show_pickup_code", "pickUpCode", "pickupCode", "pickup_code", "takeCode"]),
    firstStr(pkg.feature || {}, ["stationOrderPickUpCode", "station_order_pick_up_code"]),
    firstStr(pkg, ["pickupCode", "pickup_code", "takeCode", "pickCode"]),
  ];

  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i];
    if (!c) continue;
    if (/^(true|false|needsms|need_sms|null|none|-1|0)$/i.test(c)) continue;
    return { code: c, needsSms: false };
  }

  return { code: "", needsSms: isNeedSms };
}

function parseDwellDays(pkg, stationObj) {
  const rawTime =
    firstStr(stationObj, ["arrivalTime", "arriveTime", "inTime", "inStationTime", "stationArrivalTime"]) ||
    firstStr(pkg, ["arrivalTime", "arriveTime", "inStationTime", "stationArrivalTime"]) ||
    firstStr(pkg, ["lastLogisticDetail", "last_logistic_detail"]);
  if (!rawTime) return 0;

  if (/^\d{10,13}$/.test(rawTime)) {
    const ts = rawTime.length === 10 ? Number(rawTime) * 1000 : Number(rawTime);
    const diff = Date.now() - ts;
    return diff > 0 ? Math.floor(diff / 86400000) : 0;
  }

  const m = rawTime.match(/(20\d{2})[-/.](\d{1,2})[-/.](\d{1,2})/);
  if (!m) return 0;
  const arrivalDate = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  if (isNaN(arrivalDate.getTime())) return 0;
  const today = new Date();
  const todayStart = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const diffDays = Math.floor((todayStart.getTime() - arrivalDate.getTime()) / 86400000);
  return diffDays > 0 ? diffDays : 0;
}

function parsePackageTitle(pkg) {
  const feature = (pkg && pkg.feature) || {};
  const items = Array.isArray(pkg && pkg.packageItem) ? pkg.packageItem : [];
  const item0 = (items[0] && typeof items[0] === "object" ? items[0] : {}) || {};
  const title =
    firstStr(feature, ["recommendPackageTitle", "recommend_package_title"]) ||
    firstStr(pkg, ["userRemark", "title", "tradeOrderTitle", "goodsTitle", "itemTitle"]) ||
    firstStr(item0, ["itemTitle", "item_title", "title"]);
  if (!title) return "";
  return title.length > 14 ? title.slice(0, 14) + "…" : title;
}

function classifyPackages(rawPackages) {
  const pending = [];
  const transit = [];
  const seen = new Set();

  for (let i = 0; i < rawPackages.length; i++) {
    const o = rawPackages[i];
    if (!o || typeof o !== "object") continue;

    const st =
      [o.packageStation, o.package_station, o.station, o.pkgStation, o.pickupPoint].find(
        (x) => x && typeof x === "object" && !Array.isArray(x)
      ) || {};

    const mailNo = firstStr(o, ["mailNo", "mail_no", "waybillCode", "expressNo"]);
    const status = firstStr(o, ["logisticsStatus", "logistics_status", "status"]).toUpperCase();
    const statusDesc = firstStr(o, ["logisticsStatusDesc", "packageStatusDesc", "statusDesc", "stateDesc"]);
    const lastDetail = firstStr(o, ["lastLogisticDetail", "last_logistic_detail"]);
    const stationId = firstStr(st, ["stationId", "station_id"]);
    const stationName = firstStr(st, ["stationName", "station_name", "pointName", "point_name", "name"]);
    const cp = firstStr(o, ["partnerName", "partner_name", "cpName", "companyName"]) || "快递";
    const { code, needsSms } = parsePickupCode(o, st);

    const dedupKey = mailNo || (code ? stationName + "#" + code : "");
    if (dedupKey) {
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);
    }

    if (DONE_STATUS.has(status) || /已签收|已取出|本人签收|退回/.test(statusDesc)) {
      continue;
    }

    const isAtStation =
      Boolean(stationId) ||
      Boolean(code) ||
      needsSms ||
      /待取|驿站代收|已到站|代收点|自提柜|快递柜|请凭.*取/.test(statusDesc + " " + lastDetail);

    if (isAtStation) {
      pending.push({
        mailNo: mailNo,
        cp: cp,
        code: code,
        needsSms: needsSms,
        station: stationName || "驿站/代收点",
        title: parsePackageTitle(o),
        dwellDays: parseDwellDays(o, st),
      });
    } else {
      transit.push({
        mailNo: mailNo,
        cp: cp,
        title: parsePackageTitle(o),
        statusDesc: statusDesc,
      });
    }
  }

  return { pending: pending, transit: transit };
}

function formatPendingNotification(pending, transitCount, cfg) {
  const stations = [];
  const codes = [];
  const lines = [];

  for (let i = 0; i < pending.length; i++) {
    const p = pending[i];
    if (p.station && stations.indexOf(p.station) === -1) {
      stations.push(p.station);
    }
    if (p.code) {
      codes.push(p.code);
    }

    const codeTag = p.code ? "【" + p.code + "】" : p.needsSms ? "【需看App取件码】" : "【待取】";
    const tailParts = [p.cp];
    if (p.title) tailParts.push(p.title);
    if (p.dwellDays >= 1) tailParts.push("已到" + p.dwellDays + "天");
    const multiStationPrefix = stations.length > 1 || i > 0 ? "" : "";
    lines.push(i + 1 + ". " + codeTag + tailParts.join(" · ") + multiStationPrefix);
  }

  // 若存在多个不同驿站，在每行末尾补充驿站简称以免跑错点
  if (stations.length > 1) {
    for (let i = 0; i < pending.length; i++) {
      lines[i] += " @" + pending[i].station;
    }
  }

  const title = "📦 你有 " + pending.length + " 个快递待取";
  let subtitle = stations.length === 1 ? "📍 " + stations[0] : "📍 共 " + stations.length + " 个取件点";
  if (transitCount > 0) {
    subtitle += "（另有 " + transitCount + " 件在途）";
  }

  const attach = { openUrl: cfg.openTarget };
  if (codes.length > 0) {
    attach.clipboard = codes.join(" ");
  }

  return {
    title: title,
    subtitle: subtitle,
    content: lines.join("\n"),
    attach: attach,
  };
}

// ───────────────────────── 4. 定时 / 手动查询主流程 ─────────────────────────

async function runDailyCheck(cfg, done) {
  const manual = isManualTrigger();
  const jar = readCookieJar(cfg);

  if (!isAuthenticatedTaobaoJar(jar)) {
    sendNotification(
      "⚠️ 菜鸟提醒尚未配置登录态",
      "缺少有效的淘宝/菜鸟 Cookie",
      "请在 Loon 插件设置中开启「抓取Cookie临时开关」与插件 MitM，用 Safari 登录一次 h5.m.taobao.com。",
      { openUrl: "https://h5.m.taobao.com/mlapp/olist.html" }
    );
    done({ title: "未登录", content: "请先抓取或填写淘宝 Cookie" });
    return;
  }

  const allPackages = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await callMtop(
      API_PDS_LIST,
      {
        pageSize: 50,
        currentPage: page,
        needTemporality: false,
        needDynInfo: NEED_DYN_INFO,
      },
      jar,
      cfg
    );

    if (!res.ok) {
      if (res.kind === "session_expired") {
        sendNotification(
          "⚠️ 菜鸟/淘宝登录态已过期",
          "需要重新刷新一次 Cookie",
          "请打开 Loon 临时开启抓 Cookie 开关，用 Safari 访问 h5.m.taobao.com 重新登录一次即可恢复。",
          { openUrl: "https://h5.m.taobao.com/mlapp/olist.html" }
        );
      } else if (res.kind === "risk") {
        sendNotification(
          "⚠️ 菜鸟查询遇到风控验证",
          res.message,
          "请用 Safari 打开一次 h5.m.taobao.com 浏览订单完成正常访问后再试。",
          { openUrl: "https://h5.m.taobao.com/mlapp/olist.html" }
        );
      } else if (manual) {
        sendNotification("⚠️ 菜鸟查询失败", res.message, "请检查当前网络连接后重试。");
      } else {
        console.log("[菜鸟提醒] 查询异常: " + res.message);
      }
      done({ title: "查询异常", content: res.message });
      return;
    }

    const list = extractPackagesArray(res.json);
    for (let i = 0; i < list.length; i++) {
      allPackages.push(list[i]);
    }

    const totalPages = extractTotalPages(res.json);
    if (page >= totalPages || list.length === 0) {
      break;
    }
  }

  const { pending, transit } = classifyPackages(allPackages);
  console.log(
    "[菜鸟提醒] 检测完成：待取 " + pending.length + " 件，在途 " + transit.length + " 件"
  );

  if (pending.length > 0) {
    const msg = formatPendingNotification(pending, transit.length, cfg);
    sendNotification(msg.title, msg.subtitle, msg.content, msg.attach);
    done({ title: msg.title, content: msg.content });
    return;
  }

  if (manual || cfg.notifyEmpty) {
    const sub = transit.length > 0 ? "另有 " + transit.length + " 个包裹正在路上" : "名下暂无未签收包裹";
    sendNotification(
      "📭 今日暂无待取快递",
      sub,
      manual ? "连接与登录态正常！每天到设定时间若有待取件会自动通知你。" : "下班可以直接回家啦～",
      { openUrl: cfg.openTarget }
    );
  }

  done({
    title: "暂无待取快递",
    content: "待取 0 件，在途 " + transit.length + " 件",
  });
}

// ───────────────────────── 入口分发 ─────────────────────────

function main() {
  let finished = false;
  const safeDone = (val) => {
    if (finished) return;
    finished = true;
    if (typeof $done === "function") {
      $done(val);
    }
  };

  const cfg = parseConfig(typeof $argument !== "undefined" ? $argument : undefined);

  if (typeof $request !== "undefined" && $request && $request.url) {
    handleCaptureRequest(cfg, safeDone);
  } else {
    runDailyCheck(cfg, safeDone).catch((err) => {
      console.log("[菜鸟提醒] 未捕获异常: " + String(err));
      safeDone({ title: "执行异常", content: String(err) });
    });
  }
}

if (typeof $done === "function") {
  main();
} else if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    md5,
    encryptText,
    decryptText,
    parseCookieHeader,
    serializeCookieJar,
    splitSetCookieHeader,
    absorbSetCookiesFromHeaders,
    isAuthenticatedTaobaoJar,
    buildMtopUrl,
    classifyPackages,
    formatPendingNotification,
    parseConfig,
    runDailyCheck,
    handleCaptureRequest,
  };
}
