// ================== 影视·橘汁APP · TVBox QuickJS ==================
// 橘汁 (juziapp.hzhcbkj.cn) 
// 与小苹果同族: protobuf + AES-ECB/CBC + RSA-PKCS1 签名, 另有动态公钥拉取
// 二进制发送: body传Latin-1字符串 + Content-Type带charset=ISO-8859-1; 接收: buffer:2 返回base64
// 注意: TVBox req 的 timeout 单位是毫秒

// ==================== 基础编码 ====================
const B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64enc(bytes) {
    let out = "", i = 0;
    for (; i + 3 <= bytes.length; i += 3) {
        const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        out += B64C[(n >> 18) & 63] + B64C[(n >> 12) & 63] + B64C[(n >> 6) & 63] + B64C[n & 63];
    }
    if (i < bytes.length) {
        const n = (bytes[i] << 16) | (i + 1 < bytes.length ? bytes[i + 1] << 8 : 0);
        out += B64C[(n >> 18) & 63] + B64C[(n >> 12) & 63];
        out += i + 1 < bytes.length ? B64C[(n >> 6) & 63] : "=";
        out += "=";
    }
    return out;
}
function b64dec(s) {
    const rev = {};
    for (let i = 0; i < 64; i++) rev[B64C[i]] = i;
    s = String(s).replace(/[^A-Za-z0-9+/]/g, "");
    const out = [];
    let acc = 0, bits = 0;
    for (let i = 0; i < s.length; i++) {
        acc = (acc << 6) | rev[s[i]];
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); }
    }
    return out;
}
function utf8enc(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
        let c = str.charCodeAt(i);
        if (c < 0x80) out.push(c);
        else if (c < 0x800) { out.push(0xC0 | (c >> 6), 0x80 | (c & 63)); }
        else if (c >= 0xD800 && c < 0xDC00 && i + 1 < str.length) {
            c = 0x10000 + ((c & 0x3FF) << 10) + (str.charCodeAt(++i) & 0x3FF);
            out.push(0xF0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
        } else out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
}
function utf8dec(bytes) {
    let out = "", i = 0;
    while (i < bytes.length) {
        const c = bytes[i++];
        if (c < 0x80) out += String.fromCharCode(c);
        else if (c < 0xE0) out += String.fromCharCode(((c & 31) << 6) | (bytes[i++] & 63));
        else if (c < 0xF0) out += String.fromCharCode(((c & 15) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63));
        else { i += 3; out += " "; }
    }
    return out;
}
function hexenc(bytes) { let s = ""; for (const b of bytes) s += (b < 16 ? "0" : "") + b.toString(16); return s; }

// ==================== AES ====================
const SBOX = [99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];
const INV_SBOX = [82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125];
const RCON = [0,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154];
function xtime(x) { x <<= 1; return x & 256 ? (x ^ 0x11b) & 255 : x; }
function aesKeyExp(key) {
    const Nk = key.length / 4, Nr = Nk + 6, w = [];
    for (let i = 0; i < Nk; i++) w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    for (let i = Nk; i < 4 * (Nr + 1); i++) {
        let t = w[i - 1].slice();
        if (i % Nk === 0) { t = [SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]; t[0] ^= RCON[i / Nk]; }
        else if (Nk > 6 && i % Nk === 4) { t = [SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]]; }
        w.push([w[i - Nk][0] ^ t[0], w[i - Nk][1] ^ t[1], w[i - Nk][2] ^ t[2], w[i - Nk][3] ^ t[3]]);
    }
    return { w: w, Nr: Nr };
}
function aesAddRK(s, w, r) { for (let c = 0; c < 4; c++) for (let i = 0; i < 4; i++) s[i + 4 * c] ^= w[4 * r + c][i]; }
function aesSub(s) { for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]]; }
function aesInvSub(s) { for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]]; }
function aesShift(s) {
    for (let r = 1; r < 4; r++) {
        const t = [];
        for (let c = 0; c < 4; c++) t.push(s[r + 4 * ((c + r) % 4)]);
        for (let c = 0; c < 4; c++) s[r + 4 * c] = t[c];
    }
}
function aesInvShift(s) {
    for (let r = 1; r < 4; r++) {
        const t = [];
        for (let c = 0; c < 4; c++) t.push(s[r + 4 * ((c - r + 4) % 4)]);
        for (let c = 0; c < 4; c++) s[r + 4 * c] = t[c];
    }
}
function aesMix(s) {
    for (let c = 0; c < 4; c++) {
        const a = [s[4 * c], s[1 + 4 * c], s[2 + 4 * c], s[3 + 4 * c]];
        s[4 * c] = xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3];
        s[1 + 4 * c] = a[0] ^ xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3];
        s[2 + 4 * c] = a[0] ^ a[1] ^ xtime(a[2]) ^ (xtime(a[3]) ^ a[3]);
        s[3 + 4 * c] = (xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xtime(a[3]);
    }
}
function aesInvMix(s) {
    for (let c = 0; c < 4; c++) {
        const a = [s[4 * c], s[1 + 4 * c], s[2 + 4 * c], s[3 + 4 * c]];
        const m9 = (x) => xtime(xtime(xtime(x))) ^ x;
        const m11 = (x) => xtime(xtime(xtime(x))) ^ xtime(x) ^ x;
        const m13 = (x) => xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ x;
        const m14 = (x) => xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ xtime(x);
        s[4 * c] = m14(a[0]) ^ m11(a[1]) ^ m13(a[2]) ^ m9(a[3]);
        s[1 + 4 * c] = m9(a[0]) ^ m14(a[1]) ^ m11(a[2]) ^ m13(a[3]);
        s[2 + 4 * c] = m13(a[0]) ^ m9(a[1]) ^ m14(a[2]) ^ m11(a[3]);
        s[3 + 4 * c] = m11(a[0]) ^ m13(a[1]) ^ m9(a[2]) ^ m14(a[3]);
    }
}
function pkcs7pad(bytes) { const n = 16 - (bytes.length % 16), out = bytes.slice(); for (let i = 0; i < n; i++) out.push(n); return out; }
function pkcs7unpad(bytes) {
    if (!bytes.length) return bytes;
    const n = bytes[bytes.length - 1];
    if (n < 1 || n > 16 || n > bytes.length) return bytes;
    return bytes.slice(0, bytes.length - n);
}
function aesEncBlock(ek, block) {
    const s = block.slice();
    aesAddRK(s, ek.w, 0);
    for (let r = 1; r < ek.Nr; r++) { aesSub(s); aesShift(s); aesMix(s); aesAddRK(s, ek.w, r); }
    aesSub(s); aesShift(s); aesAddRK(s, ek.w, ek.Nr);
    return s;
}
function aesDecBlock(ek, block) {
    const s = block.slice();
    aesAddRK(s, ek.w, ek.Nr);
    for (let r = ek.Nr - 1; r >= 1; r--) { aesInvShift(s); aesInvSub(s); aesAddRK(s, ek.w, r); aesInvMix(s); }
    aesInvShift(s); aesInvSub(s); aesAddRK(s, ek.w, 0);
    return s;
}
function aesEcbEnc(key, bytes) {
    const ek = aesKeyExp(key), data = pkcs7pad(bytes), out = [];
    for (let i = 0; i < data.length; i += 16) { const b = aesEncBlock(ek, data.slice(i, i + 16)); for (const x of b) out.push(x); }
    return out;
}
function aesEcbDec(key, bytes) {
    const ek = aesKeyExp(key), out = [];
    for (let i = 0; i + 16 <= bytes.length; i += 16) { const b = aesDecBlock(ek, bytes.slice(i, i + 16)); for (const x of b) out.push(x); }
    return pkcs7unpad(out);
}
function aesCbcEnc(key, iv, bytes) {
    const ek = aesKeyExp(key), data = pkcs7pad(bytes), out = [];
    let prev = iv.slice();
    for (let i = 0; i < data.length; i += 16) {
        const block = data.slice(i, i + 16);
        for (let j = 0; j < 16; j++) block[j] ^= prev[j];
        prev = aesEncBlock(ek, block);
        for (const x of prev) out.push(x);
    }
    return out;
}

// ==================== RSA (BigInt modpow, 支持运行时换公钥) ====================
function derModulus(b64pub) {
    const der = b64dec(b64pub);
    for (let i = 0; i + 4 < der.length; i++) {
        if (der[i] === 2 && der[i + 1] === 0x81 && der[i + 2] === 0x81 && der[i + 3] === 0) return der.slice(i + 4, i + 132);
    }
    return der.slice(-131, -3);
}
// ==================== RSA (纯JS大数模幂, 兼容低版本QuickJS无BigInt) ====================
function bnCmp(a, b) {
    let i = a.length > b.length ? a.length : b.length;
    while (i-- > 0) {
        const x = a[i] || 0, y = b[i] || 0;
        if (x !== y) return x > y ? 1 : -1;
    }
    return 0;
}
function bnSub(a, b) {
    const out = [];
    let borrow = 0;
    for (let i = 0; i < a.length; i++) {
        let d = (a[i] || 0) - (b[i] || 0) - borrow;
        if (d < 0) { d += 65536; borrow = 1; } else borrow = 0;
        out.push(d);
    }
    while (out.length > 1 && out[out.length - 1] === 0) out.pop();
    return out.length ? out : [0];
}
function bnMul(a, b) {
    const out = new Array(a.length + b.length + 1);
    for (let i = 0; i < out.length; i++) out[i] = 0;
    for (let i = 0; i < a.length; i++) {
        let carry = 0;
        for (let j = 0; j < b.length; j++) {
            const t = a[i] * b[j] + out[i + j] + carry;
            out[i + j] = t & 0xFFFF;
            carry = Math.floor(t / 65536);
        }
        let k = i + b.length;
        while (carry > 0) {
            const t = out[k] + carry;
            out[k] = t & 0xFFFF;
            carry = Math.floor(t / 65536);
            k++;
        }
    }
    while (out.length > 1 && out[out.length - 1] === 0) out.pop();
    return out;
}
function bnBitLen(a) {
    let i = a.length - 1;
    while (i > 0 && a[i] === 0) i--;
    let w = a[i], bits = i * 16;
    while (w) { bits++; w = w >> 1; }
    return bits;
}
function bnMod(x, m) {
    let rem = [0];
    const bits = bnBitLen(x);
    for (let i = bits - 1; i >= 0; i--) {
        let carry = 0;
        for (let j = 0; j < rem.length; j++) {
            const v = (rem[j] << 1) | carry;
            rem[j] = v & 0xFFFF;
            carry = v >> 16;
        }
        if (carry) rem.push(carry);
        if (((x[i >> 4] || 0) >> (i & 15)) & 1) rem[0] = rem[0] | 1;
        if (bnCmp(rem, m) >= 0) rem = bnSub(rem, m);
    }
    return rem;
}
function bytesToBn(be) {
    const a = [];
    let cur = 0, bits = 0;
    for (let i = be.length - 1; i >= 0; i--) {
        cur = cur | (be[i] << bits);
        bits += 8;
        if (bits >= 16) { a.push(cur & 0xFFFF); cur = cur >> 16; bits -= 16; }
    }
    if (bits > 0) a.push(cur);
    return a.length ? a : [0];
}
function bnToBytes(a, len) {
    const out = [];
    let cur = 0, bits = 0, idx = 0;
    while (out.length < len) {
        while (bits < 8 && idx < a.length) { cur = cur | (a[idx++] << bits); bits += 16; }
        out.unshift(cur & 0xFF);
        cur = cur >> 8;
        bits -= 8;
    }
    return out;
}
function rsaEncrypt(msgBytes, modBytes) {
    const n = bytesToBn(modBytes);
    const k = modBytes.length;
    const ps = [];
    for (let i = 0; i < k - 3 - msgBytes.length; i++) ps.push(1 + Math.floor(Math.random() * 255));
    const em = [0, 2].concat(ps).concat([0]).concat(msgBytes);
    const m = bytesToBn(em);
    let r = m.slice();
    for (let i = 0; i < 16; i++) r = bnMod(bnMul(r, r), n);
    r = bnMod(bnMul(r, m), n);
    return bnToBytes(r, k);
}

// ==================== protobuf ====================
function varintEnc(n) {
    const out = [];
    n = Math.floor(n);
    while (n > 0x7f) { out.push((n % 128) | 0x80); n = Math.floor(n / 128); }
    out.push(n);
    return out;
}
function pbInt(field, value) { return varintEnc(field << 3).concat(varintEnc(value)); }
function pbBytes(field, value) { return varintEnc((field << 3) | 2).concat(varintEnc(value.length)).concat(value); }
function pbParse(buf) {
    const fields = {};
    let pos = 0;
    while (pos < buf.length) {
        let key = 0, shift = 1;
        while (pos < buf.length) { const b = buf[pos++]; key += (b & 0x7f) * shift; if (!(b & 0x80)) break; shift *= 128; }
        const field = Math.floor(key / 8), wire = key % 8;
        let value;
        if (wire === 0) {
            value = 0; shift = 1;
            while (pos < buf.length) { const b = buf[pos++]; value += (b & 0x7f) * shift; if (!(b & 0x80)) break; shift *= 128; }
        } else if (wire === 1) { value = buf.slice(pos, pos + 8); pos += 8; }
        else if (wire === 2) {
            let size = 0; shift = 1;
            while (pos < buf.length) { const b = buf[pos++]; size += (b & 0x7f) * shift; if (!(b & 0x80)) break; shift *= 128; }
            value = buf.slice(pos, pos + size); pos += size;
        } else if (wire === 5) { value = buf.slice(pos, pos + 4); pos += 4; }
        else break;
        if (!fields[field]) fields[field] = [];
        fields[field].push(value);
    }
    return fields;
}
function pbFirst(fields, n, def) { const v = fields[n]; return v && v.length ? v[0] : (def !== undefined ? def : []); }

// ==================== 橘汁业务 ====================
let CFG = {
    appName: "橘汁",
    publicKey: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCr8SzZhjYy+rsya1K09t8d2K50pWFoBkgUqMpKOiW+3IEVKd4eTdvg9RSOjQ82kypL6R9BnsmrS1V8s4PVDwjQbUtYhTPPC9Hz16qY7rpD6m0d2vr09/UpWQ5uOy9PR0QTrsioveZ+DIe9jc3C+zBCu/kZSY/R8stwJoiitki3gwIDAQAB",
    dataKey: "ZU1DSFFWNENKMDYXVUQRN0ZJDUC4PQ==",
    dataIv: "OC1A06E197EF10CF3F6058CA7A803B5E",
    pkg: "com.asjdhjhd.mgd.p3",
    host: "",
    site: "https://123-1349250429.cos.ap-shanghai.myqcloud.com/app.txt",
    version: "3.0.7.0",
    decrypt: "1"
};
const DEFAULT_HOST = "http://juziapp.hzhcbkj.cn";
const COMMON_KEY = "ed5fdsgucxumegqa";
const UA = "okhttp/3.12.1";
let dynamicKey = "";
let dynTried = false;
let staticMod = null, dynMod = null;
let hostCache = "", hostTried = false;

function init(ext) {
    let e = ext;
    if (typeof e === "string" && e.trim()) { try { e = JSON.parse(e); } catch (e2) { e = {}; } }
    if (e && typeof e === "object") { for (const k in e) CFG[k] = e[k]; }
    CFG.host = String(CFG.host || "").replace(/\/+$/, "");
    staticMod = derModulus(CFG.publicKey);
}

function uuidHex() {
    let s = "";
    for (let i = 0; i < 32; i++) s += "0123456789abcdef"[Math.floor(Math.random() * 16)];
    return s.toUpperCase();
}
function rndStr(n) {
    const c = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let s = "";
    for (let i = 0; i < Math.max(0, n - 1); i++) s += c[Math.floor(Math.random() * c.length)];
    return s + "=";
}
function isVideoFormat(url) {
    return /\.(mp4|m3u8|flv|mkv|avi|ts|mov|mpd|m4a|wmv)(\?.*)?$/i.test(String(url));
}

function ensureHost() {
    if (hostTried) return;
    hostTried = true;
    if (!CFG.host && CFG.site) {
        try {
            const r = req(CFG.site, { timeout: 12000 });
            const obj = JSON.parse((r && r.content) || "{}");
            const d = String(obj.domain || "").trim().replace(/\/+$/, "");
            if (d) CFG.host = d;
        } catch (e) {}
    }
    if (!CFG.host) CFG.host = DEFAULT_HOST;
    hostCache = CFG.host;
}

function currentMod() {
    if (dynamicKey) {
        if (!dynMod) { try { dynMod = derModulus(dynamicKey); } catch (e) { dynMod = null; } }
        if (dynMod) return dynMod;
    }
    return staticMod;
}

function makeHeaders(protobuf) {
    const ts = Date.now();
    const randomStr = rndStr(16);
    const version = String(CFG.version || "");
    const vapp = version.replace(/\./g, "") || "3019";
    const uid = uuidHex();
    const device = {
        country: "CN", vName: version, cpuId: "MT6893Z%2FCZA", young: 0,
        facturer: "Xiaomi", pkg: String(CFG.pkg || ""), uuid: uid,
        resolution: "1080x2272", mac: "02%3A00%3A00%3A00%3A00%3A00", abid: "397",
        model: "M2012K11AC", plat: "android", udid: uid, dpi: "440", net: "1",
        lang: "zh", brand: "Xiaomi", density: "2.75", appName: String(CFG.appName || "橘汁"),
        cpu: "arm64-v8a", chid: "10000", carrier: "%E8%81%94%E9%80%9A",
        _vOsCode: 30, vOs: "11", v: 1, tenantId: "",
        vApp: vapp, device: 0, androidID: uid.substring(0, 16).toLowerCase()
    };
    device.sig = b64enc(rsaEncrypt(utf8enc(String(ts) + randomStr + vapp), currentMod()));
    device.random_str = randomStr;
    device.timestamp = ts;
    const sig23 = b64enc(aesEcbEnc(utf8enc(CFG.dataIv), utf8enc(String(ts) + randomStr)));
    device.sig2 = sig23.substring(0, 8);
    device.sig3 = sig23.substring(8);
    const ck = utf8enc(COMMON_KEY);
    const params = hexenc(aesCbcEnc(ck, ck, utf8enc(JSON.stringify(device))));
    const ctype = protobuf ? "application/x-protobuf" : "application/json; charset=utf-8";
    const accept = protobuf ? "application/x-protobuf" : "application/json";
    return {
        "User-Agent": UA, "Accept": accept, "Content-Type": ctype,
        "publicParams": JSON.stringify({ paramsData: params })
    };
}

function secureBody(params) {
    const ts = Date.now();
    const random8 = rndStr(8);
    const fake20 = rndStr(20);
    const parts = [];
    for (const k in params) { const v = params[k]; if (v !== null && String(v) !== "") parts.push(k + "=" + v); }
    const query = parts.join("&");
    const encrypted = random8 + b64enc(aesEcbEnc(utf8enc(CFG.dataKey), utf8enc(query + ts)));
    return pbBytes(1, utf8enc(encrypted.substring(0, 20)))
        .concat(pbBytes(2, utf8enc(encrypted.substring(20))))
        .concat(pbBytes(3, utf8enc(fake20)))
        .concat(pbInt(4, ts))
        .concat(pbBytes(5, utf8enc(random8)));
}

// 二进制POST: Latin-1 body + charset=ISO-8859-1
function postRaw(path, bodyBytes, protobuf) {
    ensureHost();
    if (!CFG.host) return [];
    let bodyStr = "";
    for (const b of bodyBytes) bodyStr += String.fromCharCode(b);
    const headers = makeHeaders(protobuf !== false);
    if (protobuf !== false) headers["Content-Type"] = "application/x-protobuf; charset=ISO-8859-1";
    try {
        const r = req(CFG.host + path, {
            method: "POST", headers: headers, body: bodyStr,
            buffer: 2, timeout: 20000
        });
        const c = (r && r.content) || "";
        return c ? b64dec(c) : [];
    } catch (e) { return []; }
}

function postProto(path, params) {
    return postRaw(path, secureBody(params), true);
}

function getJson(path) {
    ensureHost();
    if (!CFG.host) return {};
    try {
        const r = req(CFG.host + path, { headers: makeHeaders(false), timeout: 20000 });
        return JSON.parse((r && r.content) || "{}");
    } catch (e) { return {}; }
}

function apiData(raw) { return pbFirst(pbParse(raw), 3, []); }

// 动态公钥: 首次请求前拉取
function ensureDynamicKey() {
    if (dynTried) return;
    dynTried = true;
    try {
        const ts = Date.now();
        const randomStr = rndStr(16);
        const sign = b64enc(rsaEncrypt(utf8enc(String(ts) + randomStr), staticMod));
        const body = pbInt(1, ts)
            .concat(pbBytes(2, utf8enc(sign)))
            .concat(pbBytes(3, utf8enc(rndStr(16))))
            .concat(pbBytes(4, utf8enc(randomStr)))
            .concat(pbBytes(5, utf8enc(rndStr(16))));
        const raw = postRaw("/api/v5/find/app/zone", body, true);
        const f = pbParse(apiData(raw));
        const parts = [];
        for (const n of [2, 3, 4, 5]) {
            const v = pbFirst(f, n, []);
            parts.push(v && v.length ? utf8dec(v) : String(v || ""));
        }
        const dk = parts.join("");
        if (dk.length > 50) { dynamicKey = dk; dynMod = null; }
    } catch (e) {}
}

function parseCover(raw) {
    if (!raw || !raw.length) return {};
    const f = pbParse(raw);
    const p = pbFirst(f, 1, []), t = pbFirst(f, 2, []);
    return { path: p.length ? utf8dec(p) : "", thumb: t.length ? utf8dec(t) : "" };
}

function parseDrama(raw) {
    const f = pbParse(raw);
    const coverRaw = pbFirst(f, 2, []);
    const cover = coverRaw && coverRaw.length ? parseCover(coverRaw) : {};
    const f13 = pbFirst(f, 13, []), f1 = pbFirst(f, 1, []);
    return {
        vod_id: String(pbFirst(f, 3, 0) || ""),
        vod_name: (() => { const v = pbFirst(f, 5, []); return v.length ? utf8dec(v) : ""; })(),
        vod_pic: cover.thumb || cover.path || "",
        vod_remarks: f13.length ? utf8dec(f13) : "",
        vod_year: String(pbFirst(f, 14, "") || ""),
        vod_area: f1.length ? utf8dec(f1) : ""
    };
}

function parseDramaPage(raw) {
    const page = pbParse(apiData(raw));
    const out = [];
    for (const v of (page[1] || [])) {
        const d = parseDrama(v);
        if (d.vod_id && d.vod_name) out.push(d);
    }
    return out;
}

function parseVideo(raw) {
    const f = pbParse(raw);
    const t2 = pbFirst(f, 2, []), t4 = pbFirst(f, 4, []), t9 = pbFirst(f, 9, []), t10 = pbFirst(f, 10, []);
    return {
        title: t2.length ? utf8dec(t2) : "",
        path: t4.length ? utf8dec(t4) : "",
        source: t9.length ? utf8dec(t9) : "",
        source_cn: t10.length ? utf8dec(t10) : ""
    };
}

function home(filter) {
    // 服务端旧分类接口 getCategory 已下线(400)，改为内置固定分类（实测 typeId 20-26）
    const classes = [
        { type_id: "20", type_name: "电影" },
        { type_id: "21", type_name: "剧集" },
        { type_id: "22", type_name: "综艺" },
        { type_id: "23", type_name: "动漫" },
        { type_id: "24", type_name: "短剧" },
        { type_id: "25", type_name: "电视" },
        { type_id: "26", type_name: "漫剧" }
    ];
    return JSON.stringify({ "class": classes, "filters": {} });
}

function appendVod(videos, vod) {
    if (!vod || typeof vod !== "object") return;
    let pic = "";
    const cover = vod.coverImage || vod.cover || {};
    if (cover && typeof cover === "object") pic = cover.path || cover.thumb || cover.url || "";
    videos.push({
        vod_id: String(vod.id || vod.vod_id || ""),
        vod_name: String(vod.name || vod.vod_name || ""),
        vod_pic: pic,
        vod_remarks: String(vod.remark || vod.vod_remarks || "")
    });
}

function homeVod() {
    const videos = [];
    try {
        ensureDynamicKey();
        const obj = getJson("/api/ex/v3/security/tag/list");
        const rawData = obj.data || "";
        let arr = null;
        if (Array.isArray(rawData)) arr = rawData;
        else if (rawData && typeof rawData === "object") arr = [rawData];
        else {
            const dataStr = String(rawData || "");
            if (dataStr) {
                try { arr = JSON.parse(dataStr); } catch (e) {}
                if (!arr && String(CFG.decrypt) !== "0") {
                    try { arr = JSON.parse(utf8dec(aesEcbDec(utf8enc(CFG.dataKey), b64dec(dataStr)))); } catch (e) {}
                }
                if (!arr && String(CFG.decrypt) !== "0") {
                    try {
                        const d1 = utf8dec(aesEcbDec(utf8enc(CFG.dataKey), b64dec(dataStr)));
                        arr = JSON.parse(utf8dec(aesEcbDec(utf8enc(CFG.dataIv), b64dec(d1))));
                    } catch (e) {}
                }
            }
        }
        for (const block of (arr || [])) {
            if (!block || typeof block !== "object") continue;
            if (block.vodList) { for (const vod of block.vodList) appendVod(videos, vod); continue; }
            for (const section of (block.sections || [])) {
                if (!section || typeof section !== "object") continue;
                for (const vod of (section.vodList || [])) appendVod(videos, vod);
            }
        }
        if (videos.length) return JSON.stringify({ list: videos });
    } catch (e) {}
    // 降级: 第一分类第1页
    try {
        const h = JSON.parse(home(false));
        const cls = h["class"] || [];
        if (cls.length) {
            const cat = JSON.parse(category(cls[0].type_id, "1", false, {}));
            if (cat.list && cat.list.length) return JSON.stringify({ list: cat.list });
        }
    } catch (e) {}
    return JSON.stringify({ list: [] });
}

function category(tid, pg, filter, extend) {
    const page = parseInt(pg, 10) || 1;
    const ex = extend || {};
    const params = {
        pagesize: "21", typeId1: String(tid), page: String(page),
        vodOrderBy: ex.extend_sort || "最新",
        vodArea: ex.area || "", vodLang: ex.lang || "",
        vodClass: ex["class"] || "", vodYear: ex.year || ""
    };
    try {
        ensureDynamicKey();
        const raw = postProto("/api/proto/v5/drama/list", params);
        const videos = parseDramaPage(raw);
        return JSON.stringify({ list: videos, page: page, pagecount: page + (videos.length >= 21 ? 1 : 0), limit: 21, total: 999999 });
    } catch (e) {
        return JSON.stringify({ list: [], page: page, pagecount: 1, limit: 21, total: 0 });
    }
}

function detail(ids) {
    try {
        ensureDynamicKey();
        const vid = String(Array.isArray(ids) ? ids[0] : ids);
        const raw = postProto("/api/proto/v5/drama/getDetail", { id: vid });
        const f = pbParse(apiData(raw));
        const coverRaw = pbFirst(f, 2, []);
        const cover = coverRaw && coverRaw.length ? parseCover(coverRaw) : {};
        const sources = {};
        const order = [];
        for (const item of (f[29] || [])) {
            const video = parseVideo(item);
            const source = video.source_cn || "橘汁";
            const path = video.path;
            let token;
            if (!isVideoFormat(path)) {
                token = b64enc(utf8enc(JSON.stringify({ vodPlayFrom: video.source, playUrl: path })));
            } else {
                token = path;
            }
            if (!sources[source]) { sources[source] = []; order.push(source); }
            sources[source].push((video.title || "播放") + "$" + token);
        }
        if (!order.length) return JSON.stringify({ list: [] });
        const txt = (n) => { const v = pbFirst(f, n, []); return v.length ? utf8dec(v) : ""; };
        const urlParts = [];
        for (const k of order) urlParts.push(sources[k].join("#"));
        return JSON.stringify({ list: [{
            vod_id: vid, vod_name: txt(9),
            vod_pic: cover.path || cover.thumb || "",
            vod_actor: txt(25), vod_director: txt(12),
            vod_area: txt(1), vod_year: String(pbFirst(f, 18, "") || ""),
            vod_remarks: txt(26), vod_content: "【琉🔹璃❤广告勿信👉剧情】📢" + txt(6),
            vod_play_from: order.join("$$$"), vod_play_url: urlParts.join("$$$")
        }] });
    } catch (e) {
        return JSON.stringify({ list: [] });
    }
}

function play(flag, id, vipFlags) {
    try {
        ensureDynamicKey();
        if (isVideoFormat(id)) {
            return JSON.stringify({ parse: 0, url: String(id), header: {} });
        }
        const params = JSON.parse(utf8dec(b64dec(String(id))));
        const raw = postProto("/api/proto/v5/videoUsableUrl", params);
        const f = pbParse(apiData(raw));
        const headers = {};
        for (const entry of (f[6] || [])) {
            const ef = pbParse(entry);
            const k1 = pbFirst(ef, 1, []), v2 = pbFirst(ef, 2, []);
            const k = k1.length ? utf8dec(k1) : "", v = v2.length ? utf8dec(v2) : "";
            if (k) headers[k] = v;
        }
        const u = pbFirst(f, 1, []);
        return JSON.stringify({ parse: 0, url: u.length ? utf8dec(u) : "", header: headers });
    } catch (e) {
        return JSON.stringify({ parse: 1, url: String(id), header: {} });
    }
}

function search(key, quick, pg) {
    try {
        ensureDynamicKey();
        const raw = postProto("/api/proto/v5/drama/search", { searchKeys: String(key), page: String(parseInt(pg, 10) || 1), pagesize: "21" });
        return JSON.stringify({ list: parseDramaPage(raw) });
    } catch (e) {
        return JSON.stringify({ list: [] });
    }
}

export default { init, home, homeVod, category, detail, play, search };