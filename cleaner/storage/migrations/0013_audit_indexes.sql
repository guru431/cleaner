-- Отбор журнала по событию и времени (блок «Служба», карточки настроек, страница «Журнал») — без просмотра всей таблицы.
CREATE INDEX audit_by_event ON audit(event, ts);
CREATE INDEX audit_by_ts ON audit(ts);
