"""Русские организации по организационно-правовой форме и названию в кавычках.

Дополнение к слою 4: у русской модели слоя 4 нет метки организации, а GLiNER обучен на английском.
Правило детерминированное, поэтому работает как слой 1 и не отключается.
"""
from __future__ import annotations

import re

from cleaner.core.detect.base import DetectContext
from cleaner.core.types import EntityType, Span

name = "rules"

_FORMS = (
    r"(?:ООО|ОАО|ЗАО|ПАО|НАО|АО|ИП|ФГУП|ФГБУ|ФГБОУ|ГУП|МУП|ГБУ|МБУ|АНО|НКО|ТОО|ТСЖ|СНТ"
    r"|Общество с ограниченной ответственностью"
    r"|(?:Публичное |Непубличное |Закрытое |Открытое )?акционерное общество)"
)
_QUOTED = r"(?:«[^»\n]{1,80}»|\"[^\"\n]{1,80}\"|„[^“”\n]{1,80}[“”]|“[^”\n]{1,80}”)"
_ORG = re.compile(rf"(?<!\w){_FORMS}\s*{_QUOTED}", re.IGNORECASE)


def detect(text: str, ctx: DetectContext) -> list[Span]:
    return [Span(m.start(), m.end(), EntityType.ORG, name) for m in _ORG.finditer(text)]
