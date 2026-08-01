-- Next Innovation 受注プラットフォーム D1 スキーマ

CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE,
  salon_name TEXT NOT NULL,
  contact_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  phone TEXT,
  postal TEXT,
  address TEXT,
  note TEXT,
  pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT,
  approved_at TEXT,
  referred_by TEXT,
  pref TEXT, city TEXT, addr1 TEXT, addr2 TEXT
);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sku TEXT UNIQUE,
  name TEXT NOT NULL,
  variant TEXT,
  unit TEXT DEFAULT '本',
  wholesale_price INTEGER NOT NULL DEFAULT 0,
  retail_price INTEGER DEFAULT 0,
  moq INTEGER DEFAULT 1,
  case_lot INTEGER DEFAULT 1,
  description TEXT,
  active INTEGER DEFAULT 1,
  sort INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_no TEXT UNIQUE NOT NULL,
  account_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'received',
  subtotal INTEGER DEFAULT 0,
  note TEXT,
  desired_date TEXT,
  agent_code TEXT,
  agent_id INTEGER,
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  product_name TEXT,
  unit_price INTEGER,
  qty INTEGER,
  amount INTEGER
);

CREATE TABLE IF NOT EXISTS production_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  po_no TEXT UNIQUE NOT NULL,
  order_id INTEGER,
  order_no TEXT,
  manufacturer TEXT NOT NULL,
  manufacturer_email TEXT,
  status TEXT DEFAULT 'sent',
  note TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS counters (
  name TEXT PRIMARY KEY,
  val INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_orders_account ON orders(account_id);
CREATE INDEX IF NOT EXISTS idx_items_order ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
-- 紹介・代理店チャネル

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
  approved_at TEXT,
  pref TEXT, city TEXT, addr1 TEXT, addr2 TEXT,
  birthday TEXT, corp_no TEXT,
  id_doc_type TEXT, id_doc_front TEXT, id_doc_back TEXT,
  id_doc_status TEXT DEFAULT 'none', id_doc_at TEXT,
  last_activity_at TEXT, closed_at TEXT, close_reason TEXT
);

CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  company TEXT,
  email TEXT NOT NULL,
  phone TEXT,
  category TEXT,
  message TEXT NOT NULL,
  status TEXT DEFAULT 'new',
  ip TEXT,
  created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status);

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

