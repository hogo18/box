const host = 'https://souju.ai';
const UA = 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36';
const SECRET = 'f39d73aa7a6426203cdee1ef17b31d3b7ea8c23f4c59c62a3a8aa0f39ee5e79d';
const ACCOUNT_RAW = [
    [0x5b, 0x4d, 0x4f, 0x40], [0x5c, 0x5c, 0x40, 0x40],
    [0x5c, 0x5c, 0x4e, 0x4e], [0x53, 0x53, 0x40, 0x40],
    [0x43, 0x43, 0x40, 0x40], [0x46, 0x46, 0x40, 0x40],
    [0x50, 0x50, 0x40, 0x40], [0x4d, 0x4d, 0x40, 0x40],
    [0x5a, 0x5a, 0x40, 0x40], [0x55, 0x55, 0x40, 0x40]
];
const PASSWORD_RAW = [0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0f, 0x0e];
const ACCOUNTS = ACCOUNT_RAW.map(a => xorText(a));
const PASSWORD = xorText(PASSWORD_RAW);

let session = '';
let lastToken = '';
let poolIdx = 0;
let poolDay = '';
let poolDead = [];
let homeCache = null;
const ticketCache = Object.create(null);
const posterCache = Object.create(null);

function xorText(raw) {
    return raw.map(n => String.fromCharCode(n ^ 0x37)).join('');
}

function untag(text) {
    if (text === null || text === undefined) return '';
    return String(text).replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').trim();
}

function clean(text) {
    if (!text) return '';
    return String(text).replace(/\[\d{4,8}\]/g, '').replace(/[#$+]/g, '').trim();
}

function utf8enc(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
        let c = str.charCodeAt(i);
        if (c < 0x80) out.push(c);
        else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
        else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
            const d = str.charCodeAt(++i);
            const cp = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
            out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
        } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
}

const SHA_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function sha256(bytes) {
    const data = bytes.slice();
    const bitLen = data.length * 8;
    data.push(0x80);
    while (data.length % 64 !== 56) data.push(0);
    for (let i = 7; i >= 0; i--) data.push(Math.floor(bitLen / Math.pow(256, i)) & 255);
    let h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const rr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
    for (let off = 0; off < data.length; off += 64) {
        const w = [];
        for (let i = 0; i < 16; i++) {
            w.push(((data[off + 4 * i] << 24) | (data[off + 4 * i + 1] << 16) | (data[off + 4 * i + 2] << 8) | data[off + 4 * i + 3]) >>> 0);
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w.push((w[i - 16] + s0 + w[i - 7] + s1) >>> 0);
        }
        let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (let i = 0; i < 64; i++) {
            const s1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (hh + s1 + ch + SHA_K[i] + w[i]) >>> 0;
            const s0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
            const mj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (s0 + mj) >>> 0;
            hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        h = h.map((x, i) => (x + [a, b, c, d, e, f, g, hh][i]) >>> 0);
    }
    const out = [];
    for (const x of h) out.push((x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255);
    return out;
}

function hmacSha256(keyBytes, msgBytes) {
    let key = keyBytes.length > 64 ? sha256(keyBytes) : keyBytes.slice();
    while (key.length < 64) key.push(0);
    const ipad = key.map(b => b ^ 0x36);
    const opad = key.map(b => b ^ 0x5c);
    return sha256(opad.concat(sha256(ipad.concat(msgBytes))));
}

function sign(headers, path, method) {
    path = path.charAt(0) === '/' ? path : '/' + path;
    const qi = path.indexOf('?');
    const pathname = qi >= 0 ? path.substring(0, qi) : path;
    const query = qi >= 0 ? path.substring(qi + 1) : '';
    const timestamp = Date.now().toString();
    let nonce = '';
    for (let i = 0; i < 16; i++) nonce += Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
    const text = method.toUpperCase() + '\n' + pathname + (query ? '?' + query : '') + '\n' + timestamp + '\n' + nonce;
    const signature = hmacSha256(utf8enc(SECRET), utf8enc(text)).map(b => b.toString(16).padStart(2, '0')).join('');
    headers['x-ai-movie-timestamp'] = timestamp;
    headers['x-ai-movie-nonce'] = nonce;
    headers['x-ai-movie-signature'] = signature;
    return headers;
}

function rollPool() {
    const d = new Date();
    const day = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
    if (day !== poolDay) {
        poolDay = day;
        poolIdx = 0;
        poolDead = ACCOUNTS.map(() => false);
    }
}

function currentAccount() {
    rollPool();
    return ACCOUNTS[poolIdx];
}

function rotatePool() {
    rollPool();
    poolDead[poolIdx] = true;
    for (let i = 0; i < ACCOUNTS.length; i++) {
        const next = (poolIdx + 1 + i) % ACCOUNTS.length;
        if (!poolDead[next]) {
            poolIdx = next;
            return true;
        }
    }
    return false;
}

function findSession(headers) {
    if (!headers) return '';
    for (const key of Object.keys(headers)) {
        if (key.toLowerCase() !== 'set-cookie') continue;
        const values = typeof headers[key] === 'string' ? [headers[key]] : headers[key];
        for (const value of values || []) {
            const m = /ai_movie_session=([^;]+)/.exec(value);
            if (m) return m[1];
        }
    }
    return '';
}

function makeHeaders(path, method) {
    const headers = { 'User-Agent': UA, 'Accept': 'application/json' };
    if (session) headers.Cookie = 'ai_movie_session=' + session;
    return sign(headers, path, method || 'GET');
}

async function get(path) {
    try {
        const r = await req(host + path, { headers: makeHeaders(path, 'GET'), timeout: 20000 });
        return r && r.content ? r.content : '';
    } catch (e) {
        return '';
    }
}

async function doLogin() {
    const path = '/v1/users/password/login';
    session = '';
    try {
        rollPool();
        const headers = makeHeaders(path, 'POST');
        headers['Content-Type'] = 'application/json';
        headers.Origin = host;
        const r = await req(host + path, {
            method: 'POST',
            headers,
            data: { authProtocol: 'aimovie.native-auth.v3', account: currentAccount(), password: PASSWORD },
            postType: 'json',
            timeout: 20000
        });
        session = findSession(r && r.headers);
    } catch (e) {
        session = '';
    }
    return session;
}

async function getWithSession(path) {
    if (!session) await doLogin();
    try {
        const r = await req(host + path, { headers: makeHeaders(path, 'GET'), timeout: 20000 });
        return r && r.content ? r.content : '';
    } catch (e) {
        return '';
    }
}

async function postTicket(ticket) {
    const path = '/v1/playback/resolve-line';
    if (!session) await doLogin();
    try {
        const headers = makeHeaders(path, 'POST');
        headers['Content-Type'] = 'application/json';
        const r = await req(host + path, {
            method: 'POST',
            headers,
            data: { ticket },
            postType: 'json',
            timeout: 20000
        });
        return r && r.content ? r.content : '';
    } catch (e) {
        return '';
    }
}

async function resolveLines(token) {
    lastToken = token || '';
    if (!lastToken) return [];
    try {
        const text = await getWithSession('/v1/playback/resolve/' + encodeURIComponent(lastToken));
        if (!text) return [];
        const lines = JSON.parse(text).line_options;
        return Array.isArray(lines) ? lines : [];
    } catch (e) {
        return [];
    }
}

function hasUsableLine(text) {
    try {
        const line = JSON.parse(text).line;
        return !!(line && line.url);
    } catch (e) {
        return false;
    }
}

function parseResolvedLine(ticket, text) {
    try {
        const line = JSON.parse(text).line;
        if (!line || !line.url) return '';
        if (line.url_kind === 'mp4' || line.url_kind === 'm3u8' || line.resolve_mode === 'parse') {
            ticketCache[ticket] = line.url;
            return line.url;
        }
    } catch (e) {}
    return '';
}

async function remintTicket() {
    try {
        if (!lastToken) return '';
        const lines = await resolveLines(lastToken);
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (!line) continue;
            const url = line.url || '';
            if (url.indexOf('resolve://') === 0) return url.substring(10).trim();
            if (line.url_kind === 'm3u8' && line.resolved && url) {
                ticketCache[lastToken + '#' + i] = url;
                return '';
            }
        }
    } catch (e) {}
    return '';
}

async function resolveLine(ticket) {
    if (!ticket) return '';
    if (!session) await doLogin();
    if (ticketCache[ticket]) return ticketCache[ticket];
    let text = await postTicket(ticket);
    for (let attempt = 0; attempt < 3; attempt++) {
        if (!text) return '';
        if (text.indexOf('invalid_public_playback_id') >= 0) return '';
        if (text.indexOf('login_required') < 0 && hasUsableLine(text)) return parseResolvedLine(ticket, text);
        if (attempt === 0) {
            await doLogin();
            if (!session) rotatePool();
            text = await postTicket(ticket);
        } else if (attempt === 1) {
            if (!rotatePool()) break;
            await doLogin();
            text = await postTicket(await remintTicket());
        }
    }
    return 'LOGIN';
}

function cardsToVod(cards) {
    const list = [];
    const seen = Object.create(null);
    for (const card of cards || []) {
        if (!card || !card.id || card.id.indexOf('av_') !== 0 || seen[card.id]) continue;
        seen[card.id] = true;
        list.push({
            vod_id: card.id,
            vod_name: clean(untag(card.title)),
            vod_remarks: untag(card.remarks),
            vod_pic: card.poster_url || ''
        });
    }
    return list;
}

async function loadHome() {
    if (homeCache) return homeCache;
    const text = await get('/v1/feed/home?scope=public&mode=preview&sections=8&cards=16');
    if (!text) return { classes: [], list: [] };
    const data = JSON.parse(text);
    const classes = [];
    let list = [];
    const sections = Array.isArray(data.sections) ? data.sections : [];
    for (let i = 0; i < sections.length; i++) {
        const section = sections[i];
        if (!section || !section.id || !untag(section.title)) continue;
        classes.push({ type_id: section.id, type_name: untag(section.title) });
        if (i === 0) list = cardsToVod(section.cards);
    }
    homeCache = { classes, list };
    return homeCache;
}

async function init(cfg) {}

async function home(filter) {
    try {
        const data = await loadHome();
        return JSON.stringify({ class: data.classes });
    } catch (e) {
        return JSON.stringify({ class: [] });
    }
}

async function homeVod() {
    try {
        const data = await loadHome();
        return JSON.stringify({ list: data.list });
    } catch (e) {
        return JSON.stringify({ list: [] });
    }
}

async function category(tid, pg, filter, extend = {}) {
    const page = parseInt(pg) || 1;
    if (page > 1) return JSON.stringify({ page, pagecount: 1, list: [] });
    try {
        const text = await get('/v1/feed/home?scope=public&mode=preview&sections=12&cards=24');
        const sections = JSON.parse(text).sections || [];
        for (const section of sections) {
            if (section && section.id === tid) {
                return JSON.stringify({ page: 1, pagecount: 1, list: cardsToVod(section.cards) });
            }
        }
    } catch (e) {}
    return JSON.stringify({ page, pagecount: 1, list: [] });
}

async function detail(id) {
    try {
        if (!id) return JSON.stringify({ list: [] });
        const text = await get('/v1/catalog/' + id);
        if (!text) return JSON.stringify({ list: [] });
        const data = JSON.parse(text);
        const episodes = [];
        let offset = 0;
        while (true) {
            const epText = await get('/v1/catalog/' + id + '/episodes?limit=100&offset=' + offset);
            if (!epText) break;
            const epData = JSON.parse(epText);
            const items = epData.episodes;
            if (!Array.isArray(items) || !items.length) break;
            episodes.push(...items);
            if (!epData.episode_pagination || !epData.episode_pagination.has_more) break;
            offset += items.length;
        }
        if (!episodes.length) return JSON.stringify({ list: [] });
        const lines = await resolveLines(episodes[0].token || '');
        if (!lines.length) return JSON.stringify({ list: [] });
        const playFrom = [];
        const playUrl = [];
        for (let i = 0; i < lines.length; i++) {
            if (!lines[i]) continue;
            playFrom.push(lines[i].provider_name || '线路' + (i + 1));
            const items = [];
            for (const ep of episodes) {
                if (ep && ep.token) items.push(untag(ep.title) + '$' + ep.token);
            }
            playUrl.push(items.join('#'));
        }
        let content = untag(data.intro);
        const genres = Array.isArray(data.genres) ? data.genres : [];
        if (genres.length) {
            if (content) content += '\n类型：';
            content += genres.join(' / ');
        }
        return JSON.stringify({
            list: [{
                vod_id: id,
                vod_name: clean(untag(data.title)),
                vod_pic: data.poster_url || '',
                vod_remarks: data.remarks || '',
                vod_area: data.area || '',
                vod_year: String(Number(data.year) || 0),
                vod_content: '尤东风友情提醒🔺勿信广告，避免受骗🔺:' + content,
                vod_play_from: playFrom.join('$$$'),
                vod_play_url: playUrl.join('$$$')
            }]
        });
    } catch (e) {
        return JSON.stringify({ list: [] });
    }
}

async function search(wd, quick, pg = 1) {
    try {
        const text = await get('/v1/suggest?q=' + encodeURIComponent(wd) + '&limit=20&mode=thread');
        if (!text) return JSON.stringify({ page: pg, list: [] });
        const suggestions = JSON.parse(text).suggestions || [];
        const list = [];
        const seen = Object.create(null);
        for (const suggestion of suggestions) {
            const target = suggestion && suggestion.target;
            const id = target && target.variant_id;
            if (!id || id.indexOf('av_') !== 0 || seen[id]) continue;
            seen[id] = true;
            let name = clean(target.title || suggestion.label);
            if (!name) name = '未知';
            let pic = '';
            if (list.length < 12) {
                if (posterCache[id] !== undefined) pic = posterCache[id];
                else {
                    try {
                        pic = JSON.parse(await get('/v1/catalog/' + id)).poster_url || '';
                    } catch (e) {}
                    posterCache[id] = pic;
                }
            }
            list.push({ vod_id: id, vod_name: name, vod_remarks: untag(suggestion.subtitle), vod_pic: pic });
        }
        return JSON.stringify({ page: pg, list });
    } catch (e) {
        return JSON.stringify({ page: pg, list: [] });
    }
}

function playError(msg) {
    return JSON.stringify({ parse: 0, url: '', header: { 'User-Agent': UA }, msg });
}

async function play(flag, id, flags) {
    try {
        if (!id) return playError('播放参数异常');
        const lines = await resolveLines(id);
        if (!lines.length) return playError('无可用线路');
        let line = lines.find(item => item && item.provider_name === flag);
        if (!line) line = lines[0];
        if (!line) return playError('无可用线路');
        const url = line.url || '';
        if (line.url_kind === 'm3u8' && line.resolved) {
            return JSON.stringify({ parse: 0, url, header: { 'User-Agent': UA } });
        }
        if (url.indexOf('resolve://') === 0) {
            const resolved = await resolveLine(url.substring(10).trim());
            if (resolved === 'LOGIN') return playError('官方线路免费试看前3集，后续需登录，请切换采集线路');
            if (!resolved) return playError('该线路解析失败，请切换其他线路');
            return JSON.stringify({ parse: 0, url: resolved, header: { 'User-Agent': UA } });
        }
        return playError('暂不支持该线路类型');
    } catch (e) {
        return playError('播放异常：' + e.message);
    }
}

export default { init, home, homeVod, category, detail, search, play };
