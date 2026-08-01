-- 紹介パートナー：本人確認・住所分割・稼働管理 追加マイグレーション
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

ALTER TABLE agents ADD COLUMN pref TEXT;
ALTER TABLE agents ADD COLUMN city TEXT;
ALTER TABLE agents ADD COLUMN addr1 TEXT;
ALTER TABLE agents ADD COLUMN addr2 TEXT;
ALTER TABLE agents ADD COLUMN birthday TEXT;
ALTER TABLE agents ADD COLUMN corp_no TEXT;
ALTER TABLE agents ADD COLUMN id_doc_type TEXT;
ALTER TABLE agents ADD COLUMN id_doc_front TEXT;
ALTER TABLE agents ADD COLUMN id_doc_back TEXT;
ALTER TABLE agents ADD COLUMN id_doc_status TEXT DEFAULT 'none';
ALTER TABLE agents ADD COLUMN id_doc_at TEXT;
ALTER TABLE agents ADD COLUMN last_activity_at TEXT;
ALTER TABLE agents ADD COLUMN closed_at TEXT;
ALTER TABLE agents ADD COLUMN close_reason TEXT;

ALTER TABLE accounts ADD COLUMN pref TEXT;
ALTER TABLE accounts ADD COLUMN city TEXT;
ALTER TABLE accounts ADD COLUMN addr1 TEXT;
ALTER TABLE accounts ADD COLUMN addr2 TEXT;
