-- 初期データ：商品
-- 卸価格は 0（未設定）で登録。管理コンソールの「商品」から正式な卸価格を設定すると発注可能になる。

INSERT INTO products (sku,name,variant,unit,wholesale_price,moq,case_lot,description,active,sort) VALUES
('IRS-100','Infinite Repair Serum','洗い流さない ヘアダメージ保護セラム','本',0,1,1,'ケラチン × シルク × CMC 処方。ダメージ保護・手触り改善・つや感。',1,1);

-- 卸価格を設定する例（管理画面からでも可）:
-- UPDATE products SET wholesale_price=3800 WHERE sku='IRS-100';
