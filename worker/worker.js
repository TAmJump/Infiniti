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
        const { hash, salt } = await hashPw(b.pw);
        await env.DB.prepare(
          `INSERT INTO accounts (salon_name,contact_name,email,phone,postal,address,note,pw_hash,pw_salt,status,created_at)
           VALUES (?,?,?,?,?,?,?,?,?, 'pending', ?)`
        ).bind(b.salon_name, b.contact_name, b.email, b.phone, b.postal || "", b.address,
               b.note || "", hash, salt, nowISO()).run();
        return J({ ok: true });
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
          "SELECT id,sku,name,variant,unit,wholesale_price,moq,case_lot,description FROM products WHERE active=1 ORDER BY sort,id").all();
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
              `UPDATE products SET sku=?,name=?,variant=?,unit=?,wholesale_price=?,moq=?,case_lot=?,description=?,active=? WHERE id=?`
            ).bind(b.sku || "", b.name, b.variant || "", b.unit || "本", b.wholesale_price || 0,
                   b.moq || 1, b.case_lot || 1, b.description || "", b.active ? 1 : 0, b.id).run();
          } else {
            await env.DB.prepare(
              `INSERT INTO products (sku,name,variant,unit,wholesale_price,moq,case_lot,description,active,sort)
               VALUES (?,?,?,?,?,?,?,?,?, (SELECT COALESCE(MAX(sort),0)+1 FROM products))`
            ).bind(b.sku || "", b.name, b.variant || "", b.unit || "本", b.wholesale_price || 0,
                   b.moq || 1, b.case_lot || 1, b.description || "", b.active ? 1 : 0).run();
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
};

/* 連番（counters テーブル, アトミック更新） */
async function nextSeq(env, name) {
  await env.DB.prepare("INSERT INTO counters (name,val) VALUES (?,1) ON CONFLICT(name) DO UPDATE SET val=val+1")
    .bind(name).run();
  const r = await env.DB.prepare("SELECT val FROM counters WHERE name=?").bind(name).first();
  return r.val;
}
