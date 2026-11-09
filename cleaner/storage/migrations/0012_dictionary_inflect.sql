-- Отметка записи словаря «искать во всех падежах»: падежные формы строит ядро (detect.dictionary.inflected).
ALTER TABLE dictionary ADD COLUMN inflect INTEGER NOT NULL DEFAULT 0;
