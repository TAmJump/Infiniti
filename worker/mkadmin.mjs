// 管理者アカウント作成用 INSERT を生成する
// 使い方: node mkadmin.mjs <username> <password>
import crypto from "node:crypto";

const [, , username, password] = process.argv;
if (!username || !password) {
  console.error("usage: node mkadmin.mjs <username> <password>");
  process.exit(1);
}
const b64url = b => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const salt = crypto.randomBytes(16);
const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
const now = new Date().toISOString();
console.log(
  `INSERT INTO admins (username,pw_hash,pw_salt,created_at) VALUES ('${username}','${b64url(hash)}','${b64url(salt)}','${now}');`
);
