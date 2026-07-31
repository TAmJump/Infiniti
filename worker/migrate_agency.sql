-- 紹介・代理店チャネル 追加マイグレーション（既存DB用）
-- 実行: Cloudflare D1 コンソールで上から順に、または
--       wrangler d1 execute next-orders --remote --file=./worker/migrate_agency.sql

CREATE TABLE IF NOT EXISTS agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_code TEXT UNIQUE,
  name TEXT NOT NULL,
  kind TEXT DEFAULT 'individual',
  contact_name TEXT,
  email TEXT UNIQUE NOT NULL,
  phone TEXT,
  postal TEXT,
  address TEXT,
  bank_name TEXT,
  bank_branch TEXT,
  bank_type TEXT,
  bank_number TEXT,
  bank_holder TEXT,
  reward_per_unit INTEGER DEFAULT 1000,
  pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  agreed_version TEXT,
  agreed_at TEXT,
  agreed_ip TEXT,
  agreed_ua TEXT,
  note TEXT,
  created_at TEXT,
  approved_at TEXT
);

CREATE TABLE IF NOT EXISTS rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id INTEGER NOT NULL,
  agent_code TEXT,
  order_id INTEGER,
  order_no TEXT,
  units INTEGER DEFAULT 0,
  unit_reward INTEGER DEFAULT 0,
  amount INTEGER DEFAULT 0,
  kind TEXT DEFAULT 'unit',
  status TEXT DEFAULT 'pending',
  memo TEXT,
  created_at TEXT,
  paid_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_rewards_agent ON rewards(agent_id);
CREATE INDEX IF NOT EXISTS idx_rewards_status ON rewards(status);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);

ALTER TABLE accounts ADD COLUMN referred_by TEXT;
ALTER TABLE orders ADD COLUMN agent_code TEXT;
ALTER TABLE orders ADD COLUMN agent_id INTEGER;
