-- 初期データ：商品（INFINI WORLD）
-- 卸価格はサロン直販価格 13,000円（税抜）で登録。
-- 価格や内容の変更は管理コンソールの「商品」から、または wrangler d1 execute で行う。

INSERT INTO products (sku,name,variant,unit,wholesale_price,moq,case_lot,description,active,sort) VALUES
('IW-1000','INFINI WORLD','ヘアトリートメント（販売名：アンフィニ ワールド）／1000mL','本',13000,1,1,'本来サロン専売のプロ仕様ヘアトリートメント。ハリ・コシとまとまり、ツヤ・指通りへ。シャンプー後タオルドライした髪に塗布し、手ぐし／ブラシで整えて乾かす（乾いた髪にも可）。1000mL／日本製。',1,1);

-- 卸価格を変更する例:
-- UPDATE products SET wholesale_price=13000 WHERE sku='IW-1000';
