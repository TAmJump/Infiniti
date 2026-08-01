/**
 * Next Innovation 受注プラットフォーム API
 * Cloudflare Worker + D1
 * 認証: Bearer トークン（HMAC-SHA256 署名）/ パスワード: PBKDF2-SHA256
 *
 * 必要バインディング:
 *   DB              : D1 Database
 * 必要 secret (vars):
 *   SESSION_SECRET  : トークン署名鍵
 *   RESEND_API_KEY  : メール送信（任意。未設定ならメールはスキップ）
 *   MAIL_FROM       : 送信元（任意。例 "Next Innovation <noreply@nextinnovation.tamjump.com>"）
 */

const TOKEN_TTL = 60 * 60 * 24 * 14; // 14日
const AGENT_TERMS_VERSION = "1.0";
const enc = new TextEncoder();

/* ---------- utils ---------- */
const json = (data, status = 200, origin = "*") =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Credentials": "false",
    },
  });

function b64url(buf) {
  const b = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return b.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlStr(str) { return b64url(enc.encode(str)); }
function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}
const nowISO = () => new Date().toISOString();
function joinAddr(b) {
  return [b.pref, b.city, b.addr1, b.addr2].map(x => String(x || "").trim()).filter(Boolean).join(" ");
}
function daysSince(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  return isNaN(t) ? null : Math.floor((Date.now() - t) / 86400000);
}

/* ---------- password (PBKDF2-SHA256) ---------- */
async function hashPw(pw, saltB64) {
  const salt = saltB64
    ? Uint8Array.from(fromB64url(saltB64), c => c.charCodeAt(0))
    : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return { hash: b64url(bits), salt: b64url(salt) };
}
async function verifyPw(pw, hash, salt) {
  const r = await hashPw(pw, salt);
  return timingEq(r.hash, hash);
}
function timingEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/* ---------- token (HMAC-SHA256) ---------- */
async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function signToken(payload, secret) {
  const body = b64urlStr(JSON.stringify(payload));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return body + "." + b64url(sig);
}
async function verifyToken(token, secret) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, sig] = token.split(".");
  const key = await hmacKey(secret);
  const ok = await crypto.subtle.verify("HMAC", key,
    Uint8Array.from(fromB64url(sig), c => c.charCodeAt(0)), enc.encode(body));
  if (!ok) return null;
  let p;
  try { p = JSON.parse(fromB64url(body)); } catch { return null; }
  if (p.exp && p.exp < Math.floor(Date.now() / 1000)) return null;
  return p;
}

/* ---------- auth helpers ---------- */
function bearer(req) {
  const h = req.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}
async function authSalon(req, env) {
  const p = await verifyToken(bearer(req), env.SESSION_SECRET);
  if (!p || p.role !== "salon") return null;
  const acc = await env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(p.sub).first();
  if (!acc || acc.status !== "active") return null;
  return acc;
}
async function authAgent(req, env) {
  const p = await verifyToken(bearer(req), env.SESSION_SECRET);
  if (!p || p.role !== "agent") return null;
  const a = await env.DB.prepare("SELECT * FROM agents WHERE id=?").bind(p.sub).first();
  if (!a || a.status !== "active") return null;
  return a;
}
async function authAdmin(req, env) {
  const p = await verifyToken(bearer(req), env.SESSION_SECRET);
  if (!p || p.role !== "admin") return null;
  const a = await env.DB.prepare("SELECT * FROM admins WHERE id=?").bind(p.sub).first();
  return a || null;
}

/* ---------- numbering ---------- */
function pad(n, w) { return String(n).padStart(w, "0"); }
function ymd() {
  const d = new Date();
  return d.getFullYear() + pad(d.getMonth() + 1, 2) + pad(d.getDate(), 2);
}

/* ---------- AWS S3 (SigV4) ---------- */
function s3cfg(env) {
  if (!env.DOC_AWS_ACCESS_KEY_ID || !env.DOC_AWS_SECRET_ACCESS_KEY) return null;
  return {
    key: env.DOC_AWS_ACCESS_KEY_ID,
    secret: env.DOC_AWS_SECRET_ACCESS_KEY,
    bucket: env.DOC_S3_BUCKET || "nextinnovation-docs",
    region: env.DOC_S3_REGION || "ap-northeast-1",
  };
}
function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function sha256hex(data) {
  return hex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
}
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey("raw", typeof key === "string" ? enc.encode(key) : key,
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, enc.encode(msg));
}
/* S3 に署名付きリクエストを送る。method は PUT / GET / DELETE */
async function s3fetch(env, method, key, body, contentType) {
  const c = s3cfg(env);
  if (!c) throw new Error("S3 未設定");
  const host = `${c.bucket}.s3.${c.region}.amazonaws.com`;
  const path = "/" + key.split("/").map(encodeURIComponent).join("/");
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const date = amzDate.slice(0, 8);
  const payloadHash = body ? await sha256hex(body) : await sha256hex("");

  const headers = {
    "host": host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };
  if (contentType) headers["content-type"] = contentType;
  if (method === "PUT") headers["x-amz-server-side-encryption"] = "AES256";

  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map(n => n + ":" + String(headers[n]).trim() + "\n").join("");
  const signedHeaders = names.join(";");
  const canonical = [method, path, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${date}/${c.region}/s3/aws4_request`;
  const sts = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256hex(canonical)].join("\n");

  let k = await hmac("AWS4" + c.secret, date);
  k = await hmac(k, c.region);
  k = await hmac(k, "s3");
  k = await hmac(k, "aws4_request");
  const sig = hex(await hmac(k, sts));

  headers["Authorization"] =
    `AWS4-HMAC-SHA256 Credential=${c.key}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}`;
  delete headers.host;

  return fetch(`https://${host}${path}`, { method, headers, body: body || undefined });
}

/* ---------- email (Resend, optional) ---------- */
async function sendMail(env, to, subject, text) {
  if (!env.RESEND_API_KEY || !to) return;
  try {
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: env.MAIL_FROM || "Next Innovation <onboarding@resend.dev>",
        to: [to], subject, text,
      }),
    });
  } catch (e) { /* メール失敗は本処理を止めない */ }
}

/* ====================================================== */
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "*";
    const path = url.pathname;
    const m = req.method;

    if (m === "OPTIONS") {
      return new Response(null, { status: 204, headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Max-Age": "86400",
      }});
    }
    const J = (d, s = 200) => json(d, s, origin);
    const body = async () => { try { return await req.json(); } catch { return {}; } };

    try {
      /* ---------- 取引申請 ---------- */
      if (path === "/api/register" && m === "POST") {
        const b = await body();
        const req_f = ["salon_name", "contact_name", "phone", "email", "address", "pw"];
        for (const f of req_f) if (!b[f]) return J({ error: "必須項目が不足しています" }, 400);
        if (String(b.pw).length < 8) return J({ error: "パスワードは8文字以上です" }, 400);
        const exists = await env.DB.prepare("SELECT id FROM accounts WHERE email=?").bind(b.email).first();
        if (exists) return J({ error: "このメールアドレスは既に登録されています" }, 409);
        const dupA = await env.DB.prepare("SELECT id FROM accounts WHERE lower(email)=?").bind(String(b.email).toLowerCase()).first();
        if (dupA) return J({ error: "このメールアドレスは既にご登録いただいています。ログインできない場合は info@tamjump.com までご連絡ください。" }, 409);
        let ref = String(b.ref || "").trim().toUpperCase();
        if (ref) {
          const ag = await env.DB.prepare("SELECT agent_code FROM agents WHERE agent_code=? AND status='active'").bind(ref).first();
          if (!ag) ref = "";
        }
        const { hash, salt } = await hashPw(b.pw);
        await env.DB.prepare(
          `INSERT INTO accounts (salon_name,contact_name,email,phone,postal,pref,city,addr1,addr2,address,note,pw_hash,pw_salt,status,created_at,referred_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending', ?,?)`
        ).bind(b.salon_name, b.contact_name, b.email, b.phone, b.postal || "",
               b.pref || "", b.city || "", b.addr1 || "", b.addr2 || "", b.address || joinAddr(b),
               b.note || "", hash, salt, nowISO(), ref).run();
        await sendMail(env, b.email, "取引申請を受け付けました｜Next Innovation",
          `${b.salon_name} ${b.contact_name} 様\n\n取引申請を受け付けました。内容を確認のうえ、承認後に取引先コードとログイン方法をご案内します。\n\n株式会社Next Innovation\ninfo@tamjump.com`);
        await sendMail(env, env.ADMIN_EMAIL || "info@tamjump.com", "【要確認】取引申請",
          `${b.salon_name}／${b.contact_name}\n${b.email}／${b.phone}\n〒${b.postal || ""} ${b.address || joinAddr(b)}\n紹介コード：${ref || "なし"}\n\nhttps://nextinnovation.tamjump.com/order/admin.html`);
        return J({ ok: true, ref });
      }

      /* ---------- 紹介コードの照会（公開） ---------- */
      if (path === "/api/ref/check" && m === "GET") {
        const code = String(url.searchParams.get("code") || "").trim().toUpperCase();
        if (!code) return J({ valid: false });
        const ag = await env.DB.prepare("SELECT agent_code,name FROM agents WHERE agent_code=? AND status='active'").bind(code).first();
        return J(ag ? { valid: true, agent_code: ag.agent_code, name: ag.name } : { valid: false });
      }

      /* ---------- 取引先ログイン ---------- */
      if (path === "/api/login" && m === "POST") {
        const b = await body();
        const acc = await env.DB.prepare("SELECT * FROM accounts WHERE email=?").bind(b.email || "").first();
        if (!acc || !(await verifyPw(b.pw || "", acc.pw_hash, acc.pw_salt)))
          return J({ error: "メールアドレスまたはパスワードが違います" }, 401);
        if (acc.status === "pending") return J({ error: "アカウントは承認待ちです" }, 403);
        if (acc.status === "rejected") return J({ error: "このアカウントはご利用いただけません" }, 403);
        if (acc.status === "suspended") return J({ error: "アカウントは現在停止中です" }, 403);
        const token = await signToken({ sub: acc.id, role: "salon", exp: Math.floor(Date.now() / 1000) + TOKEN_TTL }, env.SESSION_SECRET);
        return J({ token, salon_name: acc.salon_name });
      }

      /* ---------- 取引先: 自分の情報 ---------- */
      if (path === "/api/me" && m === "GET") {
        const acc = await authSalon(req, env);
        if (!acc) return J({ error: "unauthorized" }, 401);
        return J({ code: acc.code, salon_name: acc.salon_name, contact_name: acc.contact_name,
                   email: acc.email, phone: acc.phone, postal: acc.postal, address: acc.address });
      }

      /* ---------- 取引先: 商品一覧 ---------- */
      if (path === "/api/products" && m === "GET") {
        const acc = await authSalon(req, env);
        if (!acc) return J({ error: "unauthorized" }, 401);
        const { results } = await env.DB.prepare(
          "SELECT id,sku,name,variant,unit,wholesale_price,retail_price,moq,case_lot,description FROM products WHERE active=1 ORDER BY sort,id").all();
        return J({ products: results || [] });
      }

      /* ---------- 取引先: 発注 ---------- */
      if (path === "/api/orders" && m === "POST") {
        const acc = await authSalon(req, env);
        if (!acc) return J({ error: "unauthorized" }, 401);
        const b = await body();
        const items = Array.isArray(b.items) ? b.items.filter(i => i.qty > 0) : [];
        if (!items.length) return J({ error: "発注する商品がありません" }, 400);
        let subtotal = 0;
        const lines = [];
        for (const it of items) {
          const p = await env.DB.prepare("SELECT * FROM products WHERE id=? AND active=1").bind(it.product_id).first();
          if (!p) return J({ error: "無効な商品が含まれています" }, 400);
          if (!p.wholesale_price) return J({ error: `${p.name} は現在発注できません` }, 400);
          const qty = parseInt(it.qty);
          if (qty < (p.moq || 1)) return J({ error: `${p.name} は最低 ${p.moq} からの発注です` }, 400);
          const amount = qty * p.wholesale_price;
          subtotal += amount;
          lines.push({ product_id: p.id, product_name: p.name, unit_price: p.wholesale_price, qty, amount });
        }
        const order_no = "NX-ORD-" + ymd() + "-" + pad((await nextSeq(env, "order")), 4);
        const res = await env.DB.prepare(
          `INSERT INTO orders (order_no,account_id,status,subtotal,note,desired_date,created_at,updated_at)
           VALUES (?,?, 'received', ?,?,?,?,?)`
        ).bind(order_no, acc.id, subtotal, b.note || "", b.desired_date || "", nowISO(), nowISO()).run();
        const oid = res.meta.last_row_id;
        for (const l of lines) {
          await env.DB.prepare(
            "INSERT INTO order_items (order_id,product_id,product_name,unit_price,qty,amount) VALUES (?,?,?,?,?,?)"
          ).bind(oid, l.product_id, l.product_name, l.unit_price, l.qty, l.amount).run();
        }
        if (acc.referred_by) {
          const ag = await env.DB.prepare("SELECT * FROM agents WHERE agent_code=? AND status='active'").bind(acc.referred_by).first();
          if (ag) {
            await env.DB.prepare("UPDATE orders SET agent_code=?, agent_id=? WHERE id=?").bind(ag.agent_code, ag.id, oid).run();
            const units = lines.reduce((t, l) => t + l.qty, 0);
            const per = ag.reward_per_unit || 0;
            if (units > 0 && per > 0) {
              await env.DB.prepare(
                `INSERT INTO rewards (agent_id,agent_code,order_id,order_no,units,unit_reward,amount,kind,status,created_at)
                 VALUES (?,?,?,?,?,?,?, 'unit','pending', ?)`
              ).bind(ag.id, ag.agent_code, oid, order_no, units, per, units * per, nowISO()).run();
            }
          }
        }
        await sendMail(env, acc.email, "ご発注を受け付けました｜Next Innovation",
          `${acc.salon_name} 様\n\nご発注を受け付けました。\n注文番号：${order_no}\n合計（税抜）：¥${subtotal.toLocaleString("ja-JP")}\n\nマイページにて状況をご確認いただけます。\n\n株式会社Next Innovation`);
        return J({ ok: true, order_no });
      }

      /* ---------- 取引先: 注文一覧 ---------- */
      if (path === "/api/orders" && m === "GET") {
        const acc = await authSalon(req, env);
        if (!acc) return J({ error: "unauthorized" }, 401);
        const { results } = await env.DB.prepare(
          `SELECT o.order_no,o.status,o.subtotal,o.created_at,
                  (SELECT COUNT(*) FROM order_items WHERE order_id=o.id) item_count
           FROM orders o WHERE o.account_id=? ORDER BY o.id DESC`).bind(acc.id).all();
        return J({ orders: results || [] });
      }

      /* ---------- 取引先: 注文詳細 ---------- */
      let mDetail = path.match(/^\/api\/orders\/([^/]+)$/);
      if (mDetail && m === "GET") {
        const acc = await authSalon(req, env);
        if (!acc) return J({ error: "unauthorized" }, 401);
        const o = await env.DB.prepare("SELECT * FROM orders WHERE order_no=? AND account_id=?")
          .bind(decodeURIComponent(mDetail[1]), acc.id).first();
        if (!o) return J({ error: "not found" }, 404);
        const { results } = await env.DB.prepare("SELECT product_name,unit_price,qty,amount FROM order_items WHERE order_id=?").bind(o.id).all();
        o.items = results || [];
        return J({ order: o });
      }

      /* ---------- お問い合わせ（公開） ---------- */
      if (path === "/api/contact" && m === "POST") {
        const b = await body();
        for (const f of ["name", "email", "message"])
          if (!b[f]) return J({ error: "お名前・メールアドレス・お問い合わせ内容は必須です" }, 400);
        if (String(b.message).length > 4000) return J({ error: "お問い合わせ内容が長すぎます" }, 400);
        if (b.website) return J({ ok: true });   /* honeypot */
        await env.DB.prepare(
          `INSERT INTO contacts (name,company,email,phone,category,message,status,ip,created_at)
           VALUES (?,?,?,?,?,?, 'new', ?,?)`
        ).bind(b.name, b.company || "", b.email, b.phone || "", b.category || "その他",
               b.message, req.headers.get("CF-Connecting-IP") || "", nowISO()).run();
        await sendMail(env, env.ADMIN_EMAIL || "info@tamjump.com",
          `【お問い合わせ】${b.category || "その他"}｜${b.name} 様`,
          `お問い合わせを受け付けました。\n\nお名前：${b.name}\n会社名・サロン名：${b.company || "—"}\nメール：${b.email}\n電話：${b.phone || "—"}\n種別：${b.category || "その他"}\n\n${b.message}`);
        await sendMail(env, b.email, "お問い合わせを受け付けました｜Next Innovation",
          `${b.name} 様\n\nお問い合わせいただきありがとうございます。以下の内容で受け付けました。\n担当者より順次ご連絡いたします。\n\n──────────\n${b.message}\n──────────\n\n株式会社Next Innovation\n埼玉県上尾市仲町1-7-8\ninfo@tamjump.com`);
        return J({ ok: true });
      }

      /* ---------- 本人確認書類のアップロード（公開・登録前） ---------- */
      if (path === "/api/upload/id-doc" && m === "POST") {
        if (!s3cfg(env)) return J({ error: "現在アップロードをご利用いただけません。恐れ入りますが info@tamjump.com へ書類をお送りください。" }, 503);
        const ct = req.headers.get("Content-Type") || "";
        if (!/^image\/(jpeg|png|webp|heic)$|^application\/pdf$/.test(ct))
          return J({ error: "JPEG・PNG・WebP・PDF のいずれかでお願いします" }, 400);
        const buf = await req.arrayBuffer();
        if (buf.byteLength > MAX_DOC_BYTES) return J({ error: "ファイルサイズは6MBまでです" }, 400);
        if (buf.byteLength < 1024) return J({ error: "ファイルを読み取れませんでした" }, 400);
        const ext = ct === "application/pdf" ? "pdf" : ct.split("/")[1];
        const key = "id-docs/" + new Date().toISOString().slice(0, 10) + "/" +
                    crypto.randomUUID() + "." + ext;
        const up = await s3fetch(env, "PUT", key, buf, ct);
        if (!up.ok) return J({ error: "アップロードに失敗しました（" + up.status + "）" }, 502);
        return J({ ok: true, key });
      }

      /* ====================== 紹介パートナー ====================== */
      /* 登録（無料・商品購入不要） */
      if (path === "/api/agent/register" && m === "POST") {
        const b = await body();
        const isCorp = b.kind === "corp" || b.kind === "salon";
        for (const f of ["name", "email", "phone", "postal", "pref", "city", "addr1", "pw"])
          if (!b[f]) return J({ error: "必須項目が入力されていません" }, 400);
        if (!isCorp && !b.birthday) return J({ error: "生年月日をご入力ください" }, 400);
        if (String(b.pw).length < 8) return J({ error: "パスワードは8文字以上でご設定ください" }, 400);
        if (!b.agree) return J({ error: "紹介パートナー規約へのご同意が必要です" }, 400);
        if (!b.id_doc_type) return J({ error: "本人確認書類の種類をお選びください" }, 400);
        if (!b.id_doc_front) return J({ error: "本人確認書類の画像をアップロードしてください" }, 400);

        const email = String(b.email).trim().toLowerCase();
        const dup = await env.DB.prepare("SELECT id,status FROM agents WHERE lower(email)=?").bind(email).first();
        if (dup) {
          const msg = dup.status === "closed" || dup.status === "rejected"
            ? "このメールアドレスは過去に登録されています。再登録をご希望の場合は info@tamjump.com までご連絡ください。"
            : "このメールアドレスは既に登録されています。ログインできない場合は info@tamjump.com までご連絡ください。";
          return J({ error: msg }, 409);
        }
        /* 同一の携帯番号での重複登録も拒否する */
        const phone = String(b.phone).replace(/[^0-9]/g, "");
        if (phone) {
          const dupP = await env.DB.prepare(
            "SELECT id FROM agents WHERE replace(replace(phone,'-',''),' ','')=? AND status IN ('pending','active')"
          ).bind(phone).first();
          if (dupP) return J({ error: "この電話番号は既に登録されています。重複してのご登録はいただけません。" }, 409);
        }

        const address = joinAddr(b);
        const { hash, salt } = await hashPw(b.pw);
        await env.DB.prepare(
          `INSERT INTO agents (name,kind,contact_name,email,phone,postal,pref,city,addr1,addr2,address,
             birthday,corp_no,id_doc_type,id_doc_front,id_doc_back,id_doc_status,id_doc_at,
             bank_name,bank_branch,bank_type,bank_number,bank_holder,
             reward_per_unit,pw_hash,pw_salt,status,agreed_version,agreed_at,agreed_ip,agreed_ua,note,created_at,last_activity_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'submitted', ?,?,?,?,?,?,?,?,?, 'pending', ?,?,?,?,?,?,?)`
        ).bind(b.name, b.kind || "individual", b.contact_name || "", email, b.phone,
               b.postal, b.pref, b.city, b.addr1, b.addr2 || "", address,
               b.birthday || "", b.corp_no || "",
               b.id_doc_type, b.id_doc_front, b.id_doc_back || "", nowISO(),
               b.bank_name || "", b.bank_branch || "", b.bank_type || "", b.bank_number || "", b.bank_holder || "",
               1000, hash, salt,
               AGENT_TERMS_VERSION, nowISO(),
               req.headers.get("CF-Connecting-IP") || "", (req.headers.get("User-Agent") || "").slice(0, 300),
               b.note || "", nowISO(), nowISO()).run();

        await sendMail(env, email, "紹介パートナー登録を受け付けました｜Next Innovation",
          `${b.name} 様\n\n紹介パートナー登録のお申し込みを受け付けました。\n\nご登録内容とご提出いただいた本人確認書類を確認のうえ、審査結果をこのメールアドレスへご連絡します。通常3営業日ほどお時間をいただきます。\n\n承認後、あなた専用の紹介コードと紹介用リンクをお送りします。\n\n── ご登録内容 ──\nお名前・屋号：${b.name}\nご住所：〒${b.postal} ${address}\nお電話番号：${b.phone}\n\nお心当たりのない場合は、このメールへご返信ください。\n\n株式会社Next Innovation\ninfo@tamjump.com`);
        await sendMail(env, env.ADMIN_EMAIL || "info@tamjump.com", "【要確認】紹介パートナー登録の申込",
          `紹介パートナーの新規申込がありました。\n\nお名前：${b.name}\n区分：${b.kind}\nメール：${email}\n電話：${b.phone}\n住所：〒${b.postal} ${address}\n本人確認書類：${b.id_doc_type}\n\n管理コンソールで審査してください。\nhttps://nextinnovation.tamjump.com/order/admin.html`);
        return J({ ok: true });
      }

      /* ログイン */
      if (path === "/api/agent/login" && m === "POST") {
        const b = await body();
        const a = await env.DB.prepare("SELECT * FROM agents WHERE email=?").bind(b.email || "").first();
        if (!a || !(await verifyPw(b.pw || "", a.pw_hash, a.pw_salt)))
          return J({ error: "メールアドレスまたはパスワードが違います" }, 401);
        if (a.status === "pending") return J({ error: "ただいま審査中です。結果はメールでご連絡します" }, 403);
        if (a.status === "closed") return J({ error: "このアカウントは解約済みです。再開をご希望の場合は info@tamjump.com までご連絡ください" }, 403);
        if (a.status === "suspended") return J({ error: "このアカウントは現在ご利用いただけません。info@tamjump.com までご連絡ください" }, 403);
        if (a.status !== "active") return J({ error: "このアカウントはご利用いただけません" }, 403);
        await env.DB.prepare("UPDATE agents SET last_activity_at=? WHERE id=?").bind(nowISO(), a.id).run();
        const token = await signToken({ sub: a.id, role: "agent", exp: Math.floor(Date.now() / 1000) + TOKEN_TTL }, env.SESSION_SECRET);
        return J({ token, name: a.name, agent_code: a.agent_code });
      }

      /* 自分の情報 */
      if (path === "/api/agent/me" && m === "GET") {
        const a = await authAgent(req, env);
        if (!a) return J({ error: "unauthorized" }, 401);
        return J({ agent_code: a.agent_code, name: a.name, email: a.email, phone: a.phone,
                   postal: a.postal, address: a.address, reward_per_unit: a.reward_per_unit,
                   bank_name: a.bank_name, bank_branch: a.bank_branch, bank_type: a.bank_type,
                   bank_number: a.bank_number, bank_holder: a.bank_holder });
      }

      /* スコア集計 */
      if (path === "/api/agent/summary" && m === "GET") {
        const a = await authAgent(req, env);
        if (!a) return J({ error: "unauthorized" }, 401);
        const dormant = daysSince(a.last_activity_at);
        const tot = await env.DB.prepare(
          `SELECT COALESCE(SUM(units),0) units,
                  COALESCE(SUM(CASE WHEN status='pending'   THEN amount ELSE 0 END),0) pending,
                  COALESCE(SUM(CASE WHEN status='confirmed' THEN amount ELSE 0 END),0) confirmed,
                  COALESCE(SUM(CASE WHEN status='paid'      THEN amount ELSE 0 END),0) paid,
                  COALESCE(SUM(CASE WHEN status<>'void'     THEN amount ELSE 0 END),0) total
           FROM rewards WHERE agent_id=?`).bind(a.id).first();
        const intro = await env.DB.prepare(
          "SELECT COUNT(*) c FROM accounts WHERE referred_by=?").bind(a.agent_code || "").first();
        const { results: months } = await env.DB.prepare(
          `SELECT substr(created_at,1,7) ym, SUM(units) units, SUM(amount) amount
           FROM rewards WHERE agent_id=? AND status<>'void'
           GROUP BY ym ORDER BY ym DESC LIMIT 12`).bind(a.id).all();
        return J({ summary: tot, referred_accounts: intro ? intro.c : 0, months: months || [],
                   reward_per_unit: a.reward_per_unit,
                   dormant_days_left: dormant === null ? null : Math.max(0, DORMANT_DAYS - dormant) });
      }

      /* 報酬明細 */
      if (path === "/api/agent/rewards" && m === "GET") {
        const a = await authAgent(req, env);
        if (!a) return J({ error: "unauthorized" }, 401);
        const { results } = await env.DB.prepare(
          `SELECT r.id,r.order_no,r.units,r.unit_reward,r.amount,r.kind,r.status,r.memo,r.created_at,r.paid_at,
                  (SELECT salon_name FROM accounts WHERE id=(SELECT account_id FROM orders WHERE id=r.order_id)) salon_name
           FROM rewards r WHERE r.agent_id=? ORDER BY r.id DESC`).bind(a.id).all();
        return J({ rewards: results || [] });
      }

      /* ====================== ADMIN ====================== */
      if (path === "/api/admin/login" && m === "POST") {
        const b = await body();
        const a = await env.DB.prepare("SELECT * FROM admins WHERE username=?").bind(b.username || "").first();
        if (!a || !(await verifyPw(b.pw || "", a.pw_hash, a.pw_salt)))
          return J({ error: "ユーザー名またはパスワードが違います" }, 401);
        const token = await signToken({ sub: a.id, role: "admin", exp: Math.floor(Date.now() / 1000) + TOKEN_TTL }, env.SESSION_SECRET);
        return J({ token });
      }

      // 以降は管理者認証必須
      if (path.startsWith("/api/admin/")) {
        const admin = await authAdmin(req, env);
        if (!admin) return J({ error: "unauthorized" }, 401);

        /* アカウント一覧 */
        if (path === "/api/admin/accounts" && m === "GET") {
          const st = url.searchParams.get("status");
          const q = st
            ? env.DB.prepare("SELECT id,code,salon_name,contact_name,email,phone,postal,address,note,status,created_at FROM accounts WHERE status=? ORDER BY id DESC").bind(st)
            : env.DB.prepare("SELECT id,code,salon_name,contact_name,email,phone,postal,address,note,status,created_at FROM accounts ORDER BY id DESC");
          const { results } = await q.all();
          return J({ accounts: results || [] });
        }
        /* 承認 */
        let mAp = path.match(/^\/api\/admin\/accounts\/(\d+)\/approve$/);
        if (mAp && m === "POST") {
          const acc = await env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(mAp[1]).first();
          if (!acc) return J({ error: "not found" }, 404);
          const code = "NX-" + pad(await nextSeq(env, "account"), 4);
          await env.DB.prepare("UPDATE accounts SET status='active', code=?, approved_at=? WHERE id=?")
            .bind(code, nowISO(), acc.id).run();
          await sendMail(env, acc.email, "取引申請を承認しました｜Next Innovation",
            `${acc.salon_name} 様\n\n取引申請を承認しました。下記よりログインのうえご発注いただけます。\n取引先コード：${code}\nログインID：${acc.email}\n\n株式会社Next Innovation`);
          return J({ ok: true, code });
        }
        /* 却下 */
        let mRj = path.match(/^\/api\/admin\/accounts\/(\d+)\/reject$/);
        if (mRj && m === "POST") {
          await env.DB.prepare("UPDATE accounts SET status='rejected' WHERE id=?").bind(mRj[1]).run();
          return J({ ok: true });
        }
        /* 停止 / 再開 */
        let mSu = path.match(/^\/api\/admin\/accounts\/(\d+)\/(suspend|activate)$/);
        if (mSu && m === "POST") {
          await env.DB.prepare("UPDATE accounts SET status=? WHERE id=?")
            .bind(mSu[2] === "suspend" ? "suspended" : "active", mSu[1]).run();
          return J({ ok: true });
        }

        /* 受注一覧 */
        if (path === "/api/admin/orders" && m === "GET") {
          const st = url.searchParams.get("status");
          const sql = `SELECT o.order_no,o.status,o.subtotal,o.created_at,a.salon_name,a.code,
                       (SELECT COUNT(*) FROM order_items WHERE order_id=o.id) item_count
                       FROM orders o JOIN accounts a ON a.id=o.account_id
                       ${st ? "WHERE o.status=?" : ""} ORDER BY o.id DESC`;
          const q = st ? env.DB.prepare(sql).bind(st) : env.DB.prepare(sql);
          const { results } = await q.all();
          return J({ orders: results || [] });
        }
        /* 受注詳細 */
        let mOd = path.match(/^\/api\/admin\/orders\/([^/]+)$/);
        if (mOd && m === "GET") {
          const o = await env.DB.prepare(
            `SELECT o.*,a.salon_name,a.code,a.contact_name,a.email FROM orders o
             JOIN accounts a ON a.id=o.account_id WHERE o.order_no=?`).bind(decodeURIComponent(mOd[1])).first();
          if (!o) return J({ error: "not found" }, 404);
          const { results } = await env.DB.prepare("SELECT product_name,unit_price,qty,amount FROM order_items WHERE order_id=?").bind(o.id).all();
          o.items = results || [];
          return J({ order: o });
        }
        /* 受注ステータス更新 */
        let mOs = path.match(/^\/api\/admin\/orders\/([^/]+)\/status$/);
        if (mOs && m === "POST") {
          const b = await body();
          const allowed = ["received", "production", "shipped", "completed", "cancelled"];
          if (!allowed.includes(b.status)) return J({ error: "invalid status" }, 400);
          await env.DB.prepare("UPDATE orders SET status=?, updated_at=? WHERE order_no=?")
            .bind(b.status, nowISO(), decodeURIComponent(mOs[1])).run();
          return J({ ok: true });
        }

        /* 商品: 一覧（管理） */
        if (path === "/api/admin/products" && m === "GET") {
          const { results } = await env.DB.prepare("SELECT * FROM products ORDER BY sort,id").all();
          return J({ products: results || [] });
        }
        /* 商品: 追加 / 更新 */
        if (path === "/api/admin/products" && m === "POST") {
          const b = await body();
          if (!b.name) return J({ error: "商品名が必要です" }, 400);
          if (b.id) {
            await env.DB.prepare(
              `UPDATE products SET sku=?,name=?,variant=?,unit=?,wholesale_price=?,retail_price=?,moq=?,case_lot=?,description=?,active=? WHERE id=?`
            ).bind(b.sku || "", b.name, b.variant || "", b.unit || "本", b.wholesale_price || 0,
                   b.retail_price || 0, b.moq || 1, b.case_lot || 1, b.description || "", b.active ? 1 : 0, b.id).run();
          } else {
            await env.DB.prepare(
              `INSERT INTO products (sku,name,variant,unit,wholesale_price,retail_price,moq,case_lot,description,active,sort)
               VALUES (?,?,?,?,?,?,?,?,?,?, (SELECT COALESCE(MAX(sort),0)+1 FROM products))`
            ).bind(b.sku || "", b.name, b.variant || "", b.unit || "本", b.wholesale_price || 0,
                   b.retail_price || 0, b.moq || 1, b.case_lot || 1, b.description || "", b.active ? 1 : 0).run();
          }
          return J({ ok: true });
        }

        /* 製造発注: 作成 */
        if (path === "/api/admin/production-orders" && m === "POST") {
          const b = await body();
          if (!b.manufacturer) return J({ error: "製造会社名が必要です" }, 400);
          const po_no = "NX-PO-" + ymd() + "-" + pad(await nextSeq(env, "po"), 4);
          let order_id = null, orderRow = null;
          if (b.order_no) {
            orderRow = await env.DB.prepare("SELECT * FROM orders WHERE order_no=?").bind(b.order_no).first();
            if (orderRow) order_id = orderRow.id;
          }
          await env.DB.prepare(
            `INSERT INTO production_orders (po_no,order_id,order_no,manufacturer,manufacturer_email,status,note,created_at)
             VALUES (?,?,?,?,?, 'sent', ?,?)`
          ).bind(po_no, order_id, b.order_no || "", b.manufacturer, b.manufacturer_email || "", b.note || "", nowISO()).run();
          if (order_id) await env.DB.prepare("UPDATE orders SET status='production', updated_at=? WHERE id=?").bind(nowISO(), order_id).run();
          if (b.manufacturer_email && orderRow) {
            const { results } = await env.DB.prepare("SELECT product_name,qty FROM order_items WHERE order_id=?").bind(order_id).all();
            const lines = (results || []).map(i => `・${i.product_name} × ${i.qty}`).join("\n");
            await sendMail(env, b.manufacturer_email, `製造発注書 ${po_no}｜Next Innovation`,
              `${b.manufacturer} 御中\n\n下記の通り製造を発注いたします。\n発注番号：${po_no}\n\n${lines}\n\n${b.note ? "指示：" + b.note + "\n\n" : ""}株式会社Next Innovation`);
          }
          return J({ ok: true, po_no });
        }
        /* 紹介パートナー: 一覧 */
        if (path === "/api/admin/agents" && m === "GET") {
          const st = url.searchParams.get("status");
          const sql = `SELECT a.id,a.agent_code,a.name,a.kind,a.email,a.phone,a.postal,a.address,a.status,
                         a.reward_per_unit,a.agreed_version,a.agreed_at,a.created_at,a.birthday,a.corp_no,
                         a.id_doc_type,a.id_doc_front,a.id_doc_back,a.id_doc_status,a.id_doc_at,
                         a.last_activity_at,a.closed_at,a.close_reason,a.note,
                         a.bank_name,a.bank_branch,a.bank_type,a.bank_number,a.bank_holder,
                         (SELECT COALESCE(SUM(units),0) FROM rewards WHERE agent_id=a.id AND status<>'void') units,
                         (SELECT COALESCE(SUM(amount),0) FROM rewards WHERE agent_id=a.id AND status<>'void') amount,
                         (SELECT COALESCE(SUM(amount),0) FROM rewards WHERE agent_id=a.id AND status='paid') paid
                       FROM agents a ${st ? "WHERE a.status=?" : ""} ORDER BY a.id DESC`;
          const q = st ? env.DB.prepare(sql).bind(st) : env.DB.prepare(sql);
          const { results } = await q.all();
          return J({ agents: results || [] });
        }
        /* 紹介パートナー: 本人確認書類の閲覧（署名なしの直接配信） */
        let mDoc = path.match(/^\/api\/admin\/agents\/(\d+)\/doc\/(front|back)$/);
        if (mDoc && m === "GET") {
          if (!s3cfg(env)) return J({ error: "S3 が未設定です" }, 503);
          const a = await env.DB.prepare("SELECT id_doc_front,id_doc_back FROM agents WHERE id=?").bind(mDoc[1]).first();
          const key = a && (mDoc[2] === "front" ? a.id_doc_front : a.id_doc_back);
          if (!key) return J({ error: "書類がありません" }, 404);
          const obj = await s3fetch(env, "GET", key);
          if (!obj.ok) return J({ error: "書類を取得できませんでした（" + obj.status + "）" }, 404);
          return new Response(obj.body, { headers: {
            "Content-Type": obj.headers.get("Content-Type") || "application/octet-stream",
            "Cache-Control": "private, no-store",
            "Access-Control-Allow-Origin": origin,
          }});
        }
        /* 紹介パートナー: 本人確認の可否 */
        let mKyc = path.match(/^\/api\/admin\/agents\/(\d+)\/kyc$/);
        if (mKyc && m === "POST") {
          const b = await body();
          if (!["verified", "rejected", "submitted"].includes(b.id_doc_status))
            return J({ error: "invalid" }, 400);
          await env.DB.prepare("UPDATE agents SET id_doc_status=? WHERE id=?").bind(b.id_doc_status, mKyc[1]).run();
          return J({ ok: true });
        }
        /* 休眠パートナーの一括解約 */
        if (path === "/api/admin/agents/close-dormant" && m === "POST") {
          const r = await closeDormant(env);
          return J({ ok: true, closed: r });
        }
        /* お問い合わせ: 一覧 */
        if (path === "/api/admin/contacts" && m === "GET") {
          const { results } = await env.DB.prepare(
            "SELECT * FROM contacts ORDER BY id DESC LIMIT 300").all();
          return J({ contacts: results || [] });
        }
        let mCt = path.match(/^\/api\/admin\/contacts\/(\d+)\/status$/);
        if (mCt && m === "POST") {
          const b = await body();
          await env.DB.prepare("UPDATE contacts SET status=? WHERE id=?").bind(b.status || "done", mCt[1]).run();
          return J({ ok: true });
        }

        /* 紹介パートナー: 承認（コード発行） */
        let mAg = path.match(/^\/api\/admin\/agents\/(\d+)\/approve$/);
        if (mAg && m === "POST") {
          const a = await env.DB.prepare("SELECT * FROM agents WHERE id=?").bind(mAg[1]).first();
          if (!a) return J({ error: "not found" }, 404);
          if (a.id_doc_status !== "verified")
            return J({ error: "本人確認が未確認です。書類を確認して「本人確認OK」にしてから承認してください。" }, 400);
          const code = a.agent_code || ("AG-" + pad(await nextSeq(env, "agent"), 4));
          await env.DB.prepare("UPDATE agents SET status='active', agent_code=?, approved_at=?, last_activity_at=? WHERE id=?")
            .bind(code, nowISO(), nowISO(), a.id).run();
          const link = "https://nextinnovation.tamjump.com/order/register.html?ref=" + code;
          await sendMail(env, a.email, "紹介パートナー登録を承認しました｜Next Innovation",
            `${a.name} 様\n\n紹介パートナー登録を承認しました。\n\n紹介コード：${code}\n紹介用リンク：${link}\n\nご紹介先がこのリンクから取引申請し、ご発注されると報酬が計上されます。\nマイページで本数と報酬をご確認いただけます。\nhttps://nextinnovation.tamjump.com/order/agent.html\n\n株式会社Next Innovation`);
          return J({ ok: true, agent_code: code });
        }
        /* 紹介パートナー: 却下 / 停止 / 再開 */
        let mAs = path.match(/^\/api\/admin\/agents\/(\d+)\/(reject|suspend|activate|close)$/);
        if (mAs && m === "POST") {
          const b = await body().catch(() => ({}));
          const map = { reject: "rejected", suspend: "suspended", activate: "active", close: "closed" };
          const st = map[mAs[2]];
          const a = await env.DB.prepare("SELECT * FROM agents WHERE id=?").bind(mAs[1]).first();
          if (!a) return J({ error: "not found" }, 404);
          await env.DB.prepare("UPDATE agents SET status=?, close_reason=?, closed_at=?, last_activity_at=? WHERE id=?")
            .bind(st, b.reason || a.close_reason || "", (st === "closed" || st === "suspended") ? nowISO() : null,
                  st === "active" ? nowISO() : a.last_activity_at, a.id).run();
          if (st === "rejected")
            await sendMail(env, a.email, "紹介パートナー登録について｜Next Innovation",
              `${a.name} 様\n\nお申し込みいただいた紹介パートナー登録につきまして、今回は登録を見送らせていただくこととなりました。\n\n${b.reason ? "理由：" + b.reason + "\n\n" : ""}ご期待に沿えず申し訳ございません。ご不明な点は info@tamjump.com までご連絡ください。\n\n株式会社Next Innovation`);
          if (st === "suspended")
            await sendMail(env, a.email, "紹介パートナー資格の停止について｜Next Innovation",
              `${a.name} 様\n\n紹介パートナー規約に基づき、ご登録を一時停止いたしました。\n\n${b.reason ? "理由：" + b.reason + "\n\n" : ""}お心当たりのない場合、またはご説明をご希望の場合は info@tamjump.com までご連絡ください。\n\n株式会社Next Innovation`);
          if (st === "closed")
            await sendMail(env, a.email, "紹介パートナー登録の解約について｜Next Innovation",
              `${a.name} 様\n\nご登録を解約いたしました。\n\n${b.reason ? "理由：" + b.reason + "\n\n" : ""}確定済みで未払いの報酬がある場合は、規約に基づきお支払いいたします。\n再度のご登録をご希望の場合は info@tamjump.com までご連絡ください。\n\n株式会社Next Innovation`);
          return J({ ok: true });
        }
        /* 紹介パートナー: 単価変更 */
        let mAr = path.match(/^\/api\/admin\/agents\/(\d+)\/rate$/);
        if (mAr && m === "POST") {
          const b = await body();
          const v = parseInt(b.reward_per_unit);
          if (isNaN(v) || v < 0) return J({ error: "invalid" }, 400);
          await env.DB.prepare("UPDATE agents SET reward_per_unit=? WHERE id=?").bind(v, mAr[1]).run();
          return J({ ok: true });
        }

        /* 報酬: 一覧 */
        if (path === "/api/admin/rewards" && m === "GET") {
          const st = url.searchParams.get("status");
          const sql = `SELECT r.*, a.name agent_name,
                         (SELECT salon_name FROM accounts WHERE id=(SELECT account_id FROM orders WHERE id=r.order_id)) salon_name
                       FROM rewards r JOIN agents a ON a.id=r.agent_id
                       ${st ? "WHERE r.status=?" : ""} ORDER BY r.id DESC`;
          const q = st ? env.DB.prepare(sql).bind(st) : env.DB.prepare(sql);
          const { results } = await q.all();
          return J({ rewards: results || [] });
        }
        /* 報酬: ステータス更新 */
        let mRs = path.match(/^\/api\/admin\/rewards\/(\d+)\/status$/);
        if (mRs && m === "POST") {
          const b = await body();
          const allowed = ["pending", "confirmed", "paid", "void"];
          if (!allowed.includes(b.status)) return J({ error: "invalid status" }, 400);
          await env.DB.prepare("UPDATE rewards SET status=?, paid_at=? WHERE id=?")
            .bind(b.status, b.status === "paid" ? nowISO() : null, mRs[1]).run();
          return J({ ok: true });
        }
        /* 報酬: 手動追加（ボーナス・調整） */
        if (path === "/api/admin/rewards" && m === "POST") {
          const b = await body();
          const a = await env.DB.prepare("SELECT * FROM agents WHERE id=?").bind(b.agent_id).first();
          if (!a) return J({ error: "紹介パートナーが見つかりません" }, 404);
          const amt = parseInt(b.amount);
          if (isNaN(amt)) return J({ error: "金額が不正です" }, 400);
          await env.DB.prepare(
            `INSERT INTO rewards (agent_id,agent_code,units,unit_reward,amount,kind,status,memo,created_at)
             VALUES (?,?,0,0,?,?, 'confirmed', ?,?)`
          ).bind(a.id, a.agent_code, amt, b.kind === "adjust" ? "adjust" : "bonus", b.memo || "", nowISO()).run();
          return J({ ok: true });
        }

        /* 製造発注: 一覧 */
        if (path === "/api/admin/production-orders" && m === "GET") {
          const { results } = await env.DB.prepare("SELECT * FROM production_orders ORDER BY id DESC").all();
          return J({ production_orders: results || [] });
        }
      }

      return J({ error: "not found" }, 404);
    } catch (e) {
      return J({ error: "server error", detail: String(e && e.message || e) }, 500);
    }
  },

  /* Cron トリガー：休眠パートナーの自動解約（日次） */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(closeDormant(env));
  },
};

/* 90日間、報酬の計上も紹介もないパートナーを解約する */
async function closeDormant(env) {
  const limit = new Date(Date.now() - DORMANT_DAYS * 86400000).toISOString();
  const { results } = await env.DB.prepare(
    `SELECT a.* FROM agents a
     WHERE a.status='active'
       AND COALESCE(a.last_activity_at, a.approved_at, a.created_at) < ?
       AND NOT EXISTS (SELECT 1 FROM rewards r WHERE r.agent_id=a.id AND r.created_at >= ?)
       AND NOT EXISTS (SELECT 1 FROM accounts c WHERE c.referred_by=a.agent_code AND c.created_at >= ?)`
  ).bind(limit, limit, limit).all();
  const list = results || [];
  for (const a of list) {
    await env.DB.prepare(
      "UPDATE agents SET status='closed', closed_at=?, close_reason=? WHERE id=?"
    ).bind(nowISO(), DORMANT_DAYS + "日間ご利用実績がないため自動解約", a.id).run();
    await sendMail(env, a.email, "紹介パートナー登録の自動解約について｜Next Innovation",
      `${a.name} 様\n\n紹介パートナー規約に基づき、${DORMANT_DAYS}日間ご紹介の実績がなかったため、ご登録を自動的に解約いたしました。\n紹介コード ${a.agent_code || ""} は無効となります。\n\n確定済みで未払いの報酬がある場合は、規約に基づきお支払いいたします。\n再度ご利用をご希望の場合は、あらためてご登録いただけます。\n\n株式会社Next Innovation\ninfo@tamjump.com`);
  }
  return list.length;
}

/* 連番（counters テーブル, アトミック更新） */
async function nextSeq(env, name) {
  await env.DB.prepare("INSERT INTO counters (name,val) VALUES (?,1) ON CONFLICT(name) DO UPDATE SET val=val+1")
    .bind(name).run();
  const r = await env.DB.prepare("SELECT val FROM counters WHERE name=?").bind(name).first();
  return r.val;
}
