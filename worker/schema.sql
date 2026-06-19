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
  approved_at TEXT
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
