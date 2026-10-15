"""Слой 2: пароли, ключи и токены — по виду значения и по контексту."""
from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable
from functools import lru_cache

from cleaner.core.detect.base import DetectContext
from cleaner.core.entities.names import part_of_speech
from cleaner.core.types import EntityType, Span

name = "secrets"

# Блок приватного ключа. Заголовок «BEGIN … PRIVATE KEY» между рядами дефисов или тире (от двух с каждой стороны:
# при пересылке «-----» становится «—–» или теряет дефисы) — блок до END или до конца текста, как настоящий PEM.
# Заголовок без рядов или с рядом с одной стороны — блок, только если со следующей строки идёт тело base64, и до
# строки END или пустой строки: «Файл начинается со строки BEGIN RSA PRIVATE KEY» в прозе — не секрет. Ряд перед
# заголовком досчитывается назад кодом (_private_keys): выражение, начатое с ряда, перебирало бы «-----…» от каждого
# дефиса. Слов перед PRIVATE не больше трёх (SSH2 ENCRYPTED): «BEGIN BEGIN …» иначе перебирался бы до конца от каждого.
# Тело может идти после строк «Имя: значение» (_PEM_ARMOUR: броня PGP — Version:, Comment:; шифрованный PEM — Proc-Type:,
# DEK-Info:; SSH2 — Comment:) и одной пустой строки. Ряды, отделённые от заголовка пробелом («---- BEGIN SSH2 ENCRYPTED
# PRIVATE KEY ----»), — тоже заголовок с телом, а не блок до конца текста: «-- BEGIN RSA PRIVATE KEY --» бывает и тире.
_DASHES = "-—–"
_PEM_BEGIN = re.compile(r"(?<!\w)BEGIN (?:[A-Z0-9]++ ){0,3}PRIVATE KEY(?: BLOCK)?(?P<dashes>[-—–]{2,}+)?")
_PEM_END = re.compile(r"(?<!\w)END (?:[A-Z0-9]++ ){0,3}PRIVATE KEY(?: BLOCK)?[-—–]*+")
_PEM_ARMOUR = re.compile(r"[ \t]*+(?:[-—–]++[ \t]*+)?(?:\r?\n[ \t]*+[A-Za-z][\w-]*+:[ \t][^\r\n]*+)*+")
_PEM_BODY = re.compile(
    r"(?:\r?\n[ \t]*+(?=\r?\n))?(?=\r?\n[ \t]*[A-Za-z0-9+/]{16})(?:\r?\n(?![ \t]*+(?:[-—–]++[ \t]?)?END )[ \t]*\S[^\r\n]*)++"
    r"(?:\r?\n[ \t]*+(?:[-—–]++[ \t]?)?END (?:[A-Z0-9]++ ){0,3}PRIVATE KEY(?: BLOCK)?(?:[ \t]?[-—–]++)?)?"
)
# Ключ PuTTY (версии 2 и 3): строка «PuTTY-User-Key-File-3: ssh-ed25519», поля «Имя: значение» и строки base64 — до поля
# Private-MAC включительно или до строки другого вида (пустой, прозы). Секрет — только блок со строкой тела (_KEY_LINE):
# заголовок в прозе («файл начинается с PuTTY-User-Key-File-3: ssh-ed25519») ключом не считается.
_PUTTY = re.compile(
    r"(?<![\w-])PuTTY-User-Key-File-\d++:[^\r\n]*+"
    r"(?:\r?\n[ \t]*+(?!Private-MAC:)(?:[A-Z][\w-]*+:[^\r\n]*+|[A-Za-z0-9+/]++=*+[ \t]*+(?![^\r\n])))*+"
    r"(?:\r?\n[ \t]*+Private-MAC:[^\r\n]*+)?"
)
_KEY_LINE = re.compile(r"\n[ \t]*+[A-Za-z0-9+/]{16}")
# Подпись может быть пустой («alg: none»): такой токен раньше находило правило JWT из detect-secrets.
_JWT = re.compile(r"(?<![\w-])eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*")
# Токены GitLab всех видов — от 20 знаков после префикса (Devise.friendly_token): у правила detect-secrets значение — группа
# префикса («gldt», короче 8 знаков, отбрасывается), а правила glimt-, glptt-, gloas- ждут токен ровно своей длины.
_TOKEN = re.compile(
    r"""(?<![\w-])(?:
        AKIA[0-9A-Z]{16}
      | gh[pousr]_[A-Za-z0-9]{36,}
      | github_pat_[A-Za-z0-9_]{40,}
      | gl(?:pat|dt|ft|soat|rtr?|cbt|ffct|imt|ptt|agent|oas)-[\w-]{20,}
      | xox[baprs]-[A-Za-z0-9-]{10,}
      | sk_live_[A-Za-z0-9]{16,}
      | AIza[\w-]{35}
      | sk-[A-Za-z0-9_-]{20,}
      | npm_[A-Za-z0-9]{36}
      | \d{8,10}:AA[\w-]{33}
    )(?![\w-])""",
    re.VERBOSE,
)

# Значение без кавычек тянется до пробела. «;», «&» и «,» внутри пароля законны; концом значения
# они служат, только если за ними пробел, конец текста или следующее поле вида «имя=»
# (строка подключения, параметры адреса). Имя поля пробелов не содержит: в «pwd=Qw,er7y retries=3»
# запятая — часть пароля. Исключение — «;» перед словами с заглавной буквы через пробел и «=»:
# это поля ADO.NET («;Persist Security Info=», «;User ID=»; _ADO_FIELD, его же видит _NEXT_FIELD).
_ADO_FIELD = r"[A-Z][\w.-]*(?: [A-Z][\w.-]*)+="
_BARE = rf"(?P<bare>(?:[^\s;&,\"'<>]|[;&,](?![\s;&,]|[\w.-]+=|(?<=;){_ADO_FIELD}|$))+)"
_VALUE = rf"""(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)'|{_BARE})"""
# Имя ключа содержит слово целиком или склеенным: db_password, dbpass, userpwd, accessToken.
# Имя берётся целиком одним проходом без возвратов («++»), а слово секрета ищется в нём кодом:
# предел длины имени пропускал длинные ключи (spring….client-secret), а без предела выражение
# со словом внутри перебирало «tokentoken…» квадратичное время. Значение разбирается отдельно и
# только у ключа со словом секрета: пара без него не съедает соседнюю («id:token=…»).
_KEY_NAME = re.compile(r"""(?<![\w.-])(?P<key>[\w.-]++)["']?\s*[:=]\s*""")
_KEY_WORD = re.compile(
    r"password|passwd|passphrase|pass|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|credential|пароль",
    re.IGNORECASE,
)
_VALUE_AT = re.compile(_VALUE)
# Имена ключей, которые содержат те же слова, но хранят не секрет: счётчики токенов,
# политики паролей, атрибуты Active Directory, обычные слова с «pass» (passes — число проходов: Argon2-Passes ключа PuTTY).
_NOT_SECRET_KEY = re.compile(
    r"""(?:[\w.-]*[_.-])?(?:max|min|num|total|prompt|completion|input|output|context)[_.-]?tokens?
      | tokens
      | (?:[\w.-]*[_.-])?tokens?[_.-]?(?:type|count|limit|usage|budget|endpoint|url|uri|ttl|lifetime|expir\w*)
      | [\w.-]*tokeniz\w*
      | [\w.-]*(?:bypass|compass|passive|passed|passes|passage|passenger|pass[_.-]?through)[\w.-]*
      | (?:bad|max|min)?pwd(?:lastset|properties|historylength|count|age|length)
      | badpasswordtime
      | [\w.-]*password[_.-]?(?:policy|length|min\w*|max\w*|expir\w*|age|complexity|history
                              |last[_.-]?set|neverexpires|required|changed|reset\w*)""",
    re.IGNORECASE | re.VERBOSE,
)
# Ключ, который кончается словом секрета, хранит секрет, какие бы слова ни стояли перед ним:
# bypass_token, passwordResetToken, VERCEL_AUTOMATION_BYPASS_SECRET. Список выше его не отменяет.
_SECRET_END = re.compile(
    r"(?:^|[_.-])(?i:password|passwd|passphrase|pass|pwd|secret|token|key|credentials?|пароль)$"
    r"|(?<=[a-z])(?:Password|Passwd|Passphrase|Pass|Pwd|Secret|Token|Key|Credentials?)$"
)
_XML = re.compile(
    r"<(?P<tag>[\w.-]{0,64}(?:password|passwd|secret|token|api[_-]?key)[\w.-]{0,64})>"
    r"(?P<bare>[^<\r\n]+)</(?P=tag)>",
    re.IGNORECASE,
)
# Длина схемы ограничена: без предела цепочка «a.b.a.b…» без «://» даёт квадратичный перебор.
# Логина может не быть: «redis://:пароль@хост» — стандартная запись Redis.
_URL = re.compile(r"\b[a-z][a-z0-9+.-]{0,31}://[^\s:/@]*:(?P<bare>[^\s@/]+)@", re.IGNORECASE)
# Слово после пробела, начатое с «-», — следующий параметр («--password --verbose»), а «/p:имя=значение» —
# свойство MSBuild («/p:Configuration=Release»; пароль в нём находит правило ключа). Пароль из base64
# с «=» на конце («/p:dGVzdDE=») свойством не считается: после «=» у свойства есть значение.
_CLI = re.compile(
    r"(?<![\w-])(?:--?(?:password|passwd|pwd|pass|secret|token|api-key)(?:\s+(?!-)|=)"
    r"|/p(?:assword)?:(?![A-Za-z_][\w-]*=[^\s=]))" + _VALUE,
    re.IGNORECASE,
)
# Пароль без слова-ключа на своём месте в известной команде. «net use \\хост\ресурс пароль /user:…» —
# первое слово после пути, кроме параметров и «*» (запрос пароля). «mysql -pпароль» — только слитно:
# «-p имя» — запрос пароля и имя базы, «-P» — порт; не дальше двадцати слов и не за «|», «;», «&».
# «sshpass -p пароль»; ключ приложения в web.config — <add key="…Password" value="…"/>.
_COMMANDS = (
    re.compile(
        r"(?<![\w-])net[ \t]+use[ \t]+(?:(?:[a-z]:|\*)[ \t]+)?\\\\[^\s\\]+\\\S+(?:[ \t]+/\S+)*[ \t]+(?![/*])"
        + _VALUE,
        re.IGNORECASE,
    ),
    re.compile(r"(?<![\w-])(?:mysql|mariadb)[\w.-]*(?:[ \t]+(?!-p)[^\s|;&]++){0,20}?[ \t]+-p" + _VALUE),
    re.compile(r"(?<![\w-])sshpass[ \t]+-p[ \t]*" + _VALUE),
)
_ADD_KEY = re.compile(
    r"""<add\s+key\s*=\s*(?P<q>["'])(?P<key>[^"'<>\r\n]+)(?P=q)\s+value\s*=\s*"""
    r"""(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)')""",
    re.IGNORECASE,
)
_SECURE = re.compile(
    r"""ConvertTo-SecureString\s+(?:-String\s+)?(?:"(?P<dq>[^"\r\n]+)"|'(?P<sq>[^'\r\n]+)')""",
    re.IGNORECASE,
)
# После тире или дефиса в прозе часто идёт не пароль («Пароль — это строка…»). Такое значение
# отбрасывается, только если это слово прозы (_prose_word) и на пароль оно не похоже; продолжение фразы
# за ним не в счёт: «Пароль от Wi-Fi — sunflower для гостей» — пароль. После «:» и «=» берётся любое, кроме связки.
# Перед тире — до шести слов («Пароль для входа в систему — …»), перед «:» и «=» — до трёх: значение там на прозу не
# проверяется. От четырёх до шести слов перед «:» с пробелом после него (colon; «at 10:30» — время) значение проверяется,
# как после тире: заголовок «Password policy for domain users: minimum…» не скрывает minimum во всём чате.
# Слово перед тире начинается не с дефиса: иначе «Пароль - Qwerty - временный» брал значение после второго.
_PHRASE = re.compile(
    r"(?<!\w)(?:пароль|password)(?:(?:[ \t]+[\w-]+){0,3}(?P<sep>[ \t]*[:=][ \t]*)"
    r"|(?:[ \t]+\w[\w-]*){0,6}(?P<dash>[ \t]*[—–][ \t]*|[ \t]+--?[ \t]+)"
    r"|(?:[ \t]++\w[\w-]*+){4,6}(?P<colon>[ \t]*+:[ \t]++))" + _VALUE,
    re.IGNORECASE,
)
# После связки значение — следующее слово: «Пароль — это Qwerty123», «пароль — это: Zx81kLmN», «Пароль: это Zx81kLmN»;
# связка без слова за ней («Пароль: это») — не значение.
_COPULAS = frozenset({"это", "is", "was"})
_NEXT_VALUE = re.compile(r"[ \t]+" + _VALUE)
# Знаки в конце — не часть слова прозы: «Password - here!», «Пароль — какой?», «это:».
_TRAILING = "?!:;,.…"
_PROSE = re.compile(r"(?<!\w)(?:пароль|password)(?:\s+is)?\s+(?P<bare>(?!-)[^\s,;:=]+)", re.IGNORECASE)
# Токен или код в тексте без ключа присваивания: «пришёл код восстановления 3f8e…», «Подтвердите действие токеном 8c7b…»,
# «API-ключ для доступа к эндпоинту api_3f…», «смс с кодом 847593». После слова «токен», «код», «ключ», «пароль» (token,
# code, key, password) в любом падеже — до четырёх слов без знаков препинания, «:» или пробел и ближайшее значение вида
# токена. Проверка прозы, как после «пароль —», здесь в самом виде: шестнадцатеричное от 16 знаков или строка от 20 знаков
# с цифрой и буквой похожи на пароль и ищутся во всём чате; код из 6–8 цифр — только после «код» и code и скрывается
# только на своём месте. Четыре-пять цифр — код события или ошибки («код события 4625», «код ошибки 18456»).
# Значение и проверки вида — знаки ASCII, слова перед ним — любые; слова берутся по одному, от ближайшего.
_TOKEN_PHRASE = re.compile(
    r"(?<!\w)(?:токе?н(?:а|у|ом|е|ы|ов|ам|ами|ах)?|tokens?|(?P<code>код(?:а|у|ом|е|ы|ов|ам|ами|ах)?|codes?)"
    r"|ключ(?:а|у|ом|е|и|ей|ам|ами|ах)?|keys?|парол(?:ь|я|ю|ем|е|и|ей)|passwords?)"
    r"(?:[ \t]++[\w-]++){0,4}?(?:[ \t]*+:[ \t]*+|[ \t]++)"
    r"(?P<bare>(?=[A-Za-z0-9_+/-]*?\d)(?=[A-Za-z0-9_+/-]*?[A-Za-z])(?:[0-9a-fA-F]{16,}+|[A-Za-z0-9][A-Za-z0-9_+/-]{19,}+=*+)"
    r"|(?(code)\d{6,8}+|(?!)))(?![\w+/=-])(?!\.\w)",
    re.IGNORECASE,
)
# Русское слово через дефис («по-прежнему», «кто-то») похоже на пароль только дефисом, а то же слово
# без дефиса паролем в тексте и так не считается.
_HYPHENATED_WORD = re.compile(r"[а-яё]+(?:-[а-яё]+)+", re.IGNORECASE)
_LINKING_WORDS = frozenset({"это", "is", "was", "not", "see", "не", "см"})
# Слова, которые в тексте стоят после «Пароль —» вместо пароля. Русские служебные слова, местоимения,
# прилагательные, наречия, числительные и глаголы распознаёт словарь (_prose_word), здесь — только то, что он
# читает существительным; английские — списком.
_PROSE_WORDS = _LINKING_WORDS | frozenset({
    "минимум", "рабочий", "строка", "набор", "комбинация", "сочетание", "слово", "фраза", "дата", "номер", "имя",
    "фамилия",
    "the", "a", "an", "this", "that", "it", "same", "your", "my", "our", "his", "her", "their", "any", "one",
    "at", "of", "for", "from", "in", "on", "to", "by", "with", "without", "as", "like", "and", "or", "but",
    "also", "only", "just", "still", "are", "be", "has", "have", "will", "should", "must", "can", "never",
    "minimum", "min", "maximum", "more", "less", "old", "new", "empty", "blank", "temporary", "current",
    "previous", "initial", "usual", "standard", "unchanged", "changed", "expired", "reset", "sent", "stored",
    "here", "there", "below", "above", "attached", "needs", "needed", "please", "incorrect", "wrong", "invalid",
    "error", "unknown", "expires", "missing", "updated", "n/a", "tbd", "todo",
    # Отрезанные апострофом: значение без кавычек кончается перед «'» («doesn't work» -> doesn).
    "isn", "doesn", "don", "didn", "wasn",
})
_RUSSIAN_WORD = re.compile(r"[а-яё]+(?:-[а-яё]+)*", re.IGNORECASE)
_AUTH = re.compile(
    r"\bauthorization\s*[:=]\s*[\"']?(?:bearer|basic|token|negotiate|ntlm|apikey)\s+(?P<bare>[^\s\"'<>,;]+)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?<!\w)bearer\s+(?P<bare>[A-Za-z0-9._~+/=-]{16,})", re.IGNORECASE)
# После «bearer» в тексте бывают слова («bearer authentication», «Bearer authentication-scheme»):
# в настоящем токене есть цифры или заглавные внутри слова.
_WORDS = re.compile(r"[A-Za-z][a-z]*(?:[-./][A-Za-z][a-z]*)*")
# Под ключом со словом секрета в коде часто стоит не значение, а вызов команды PowerShell
# («$pwd = Read-Host», «$token = Invoke-RestMethod»).
_CMDLET = re.compile(r"(?:Get|Read|ConvertTo|ConvertFrom|Import|Invoke|New)-[A-Z][A-Za-z]*")

_NOT_SECRET = frozenset({
    "true", "false", "yes", "no", "none", "null", "nil", "on", "off", "required", "optional",
    "enabled", "disabled", "bearer", "basic", "string", "text", "prompt", "да", "нет", "ok",
})
# Подстановки и выражения — не значения: ${VAR}, $(...), $env:VAR, %VAR%, {{...}}, <...>, [[...]],
# $VAR и $var без цифр (переменная), «(…» без закрывающей скобки и слово или число в скобках — пояснение
# («(optional)», «(см. выше)», «(1)»). «$ecret123» с цифрами и «(Qw1)» — значения.
_TEMPLATE = re.compile(
    r"^(?:[*xX•·.]+|\$\{.*\}|\$\(.*|\$env:\w+|%\w+%|\{\{.*\}\}|<[^>]*>|\[\[[^\]]*\]\]|\$[A-Za-z_]+"
    r"|\([^)]*|\((?:[^\W\d_]+(?:[./-][^\W\d_]+)*\.?|\d+)\))$"
)
# Закрывающая скобка в конце значения без кавычек — его часть, если её пара внутри значения («Ab[1]», «(Qw1)»);
# иначе это скобка вокруг («f(password=abc)»).
_OPENING = {")": "(", "]": "[", "}": "{"}
# Вызов или индекс в коде после ключа — тоже не значение: «password = input()», «token = os.environ["TOKEN"]»,
# «api_key=config.get("key")» давали секреты «input(», «os.environ[», и обрывок кода скрывался во всём чате.
# Имя через точку перед скобкой — код всегда («getpass.getpass()», «$cred.GetNetworkCredential().Password»).
# Имя без точки — когда скобки пусты («input()»), за скобкой сразу кавычка (аргумент или индекс строкой) или
# в скобках только имена из букв, а имя функции — со строчной буквы, «_» или «$» («get_secret(name)», «tokens[i]»;
# аргументы после «, » в значение не входят). «password=Ab(1», «Ab(1)», «Pass(word)», «Summer2024(» — пароли.
# Атрибут без скобок — код, если имена из букв и «_», первое — объект кода (_CODE_OBJECTS, переменная PowerShell, имя
# с «_» или заглавной внутри), а в последнем слово секрета целиком (_SECRET_NAME): «self.password»,
# «settings.SECRET_KEY», «$cred.Password», «db_config.password». «Summer.2024», «Ab.Cd», «summer.night», «My.Password»,
# «admin.secret», «my.pass», «self.compass» — пароли. Значение в кавычках не проверяется: «"self.password"» — строка.
# Всё это — только после ключа присваивания в коде (_in_code): в адресе, команде, XML, прозе и строке подключения
# вызов и атрибут — пароль («redis://:my.pass@», «sshpass -p top.secret», «Пароль: qwerty(abc)»).
_CALL = re.compile(r"(?P<name>\$?[A-Za-z_]\w*)(?P<dotted>(?:\.[A-Za-z_]\w*)+)?[(\[]")
_CLOSING = {"(": ")", "[": "]"}
_VARIABLE = re.compile(r"\$|[a-z_]")
_NAMES = re.compile(r"[A-Za-z_][A-Za-z_.]*(?:,[A-Za-z_][A-Za-z_.]*)*")
_ATTRIBUTE = re.compile(r"(?P<first>(?:\$[A-Za-z_]|[a-z_])[A-Za-z_]*)(?:\.[A-Za-z_]+)*\.(?P<last>[A-Za-z_]+)")
# Первое имя, которое в пароле не встречается: объекты и настройки из кода. Любое другое имя из строчных букв
# («admin», «my», «north», «user») — часть пароля: лишняя замена атрибута дешевле открытого пароля.
_CODE_OBJECTS = frozenset({
    "self", "this", "cls", "settings", "config", "cfg", "os", "env", "process", "options", "opts", "args", "params",
})
_CAMEL = re.compile(r"[a-z][A-Z]")
# Слово секрета целиком — между краями имени, «_» и границами camelCase («SECRET_KEY», «client_secret», «accessToken»),
# а не внутри слова («compass»). Без «pass»: в Python это ключевое слово, атрибута с таким именем нет, и «$ecret.Pass» —
# скорее пароль, чем код.
_SECRET_NAME = re.compile(
    r"(?:^|(?<=_)|(?<=[a-z])(?=[A-Z]))"
    r"(?i:password|passwd|passphrase|pwd|secret|token|credentials?|(?:api|access|private)_?key)"
    r"(?:$|(?=_)|(?<=[a-z])(?=[A-Z]))"
)
# Поле строки подключения: «;» прямо перед ключом или после значения перед следующим полем, как их видит _BARE
# («Server=db;Password=…», «Password=…;User ID=app»). Значение поля — строка как есть, а не код.
_NEXT_FIELD = re.compile(rf";(?:[\w.-]+=|{_ADO_FIELD})")

# Правила по энтропии и по ключевым словам шумят на обычном тексте; контекст у нас свой.
# Правила npm, JWT и OpenAI без начала слова перебирают строку от каждого «//», «eyJ», «sk-» —
# квадратичное время под общей блокировкой интерпретатора, то есть остановка службы для всех.
# Их токены находят свои правила: _TOKEN (npm_, sk-), _JWT и ключ «_authToken=» в .npmrc.
# IP-адреса — работа слоя 3: там они получают подмену и восстанавливаются (спецификация 6.2).
# Правило приватных ключей находит только фразу заголовка («BEGIN RSA PRIVATE KEY») — и в прозе тоже, а сам ключ
# не скрывает; блок PEM целиком, и с испорченным заголовком, находит _private_keys.
_SKIPPED_PLUGINS = frozenset({
    "Base64HighEntropyString", "HexHighEntropyString", "KeywordDetector",
    "NpmDetector", "JwtTokenDetector", "OpenAIDetector", "IPPublicDetector", "PrivateKeyDetector",
})
# Выражение без групп отдаёт совпадение целиком, а правило Artifactory берёт в него и края: пробел (любой, и неразрывный:
# «\s» в выражении), «=», «:» или кавычку перед значением, пробел или кавычку после. Края в значение не входят («=» в
# конце — часть ключа Azure в base64).
_LEADING_EDGE = "=:\""
_TRAILING_EDGE = "\""
# Правила IBM, Cloudant и Softlayer разбирают пробелы вокруг «=» тремя повторами подряд (« *», « +»,
# « *»): на длинном ряде пробелов это кубическое время. Ряд сжимается до одного пробела — повторы
# принимают любое их число, а двух пробелов подряд нет ни в одном значении этих правил.
_SPACES = re.compile(" {2,}")
# Сколько разных значений строки ищется по всей строке. Только такой поиск находит повтор значения без контекста
# его правила («aws_key="…"», а дальше по строке то же значение без ключа), но стоит длину строки на каждое
# значение: строка выгрузки с тысячами разных токенов шла квадратичное время (8000 SID на строке в 472 КБ — 3,4 с).
# Остальные значения берутся там, где их нашли правила; повтор без контекста находит следующий проход очистки
# по известным значениям чата (слой 3), а пропущенный — проверка утечек.
_REPEATS = 50


@lru_cache(maxsize=1)
def _library_rules() -> tuple[re.Pattern[str], ...]:
    """Выражения правил detect-secrets (denylist) по порядку правил. Не scan_line: тот читает общие для процесса
    настройки, которые меняет любой параллельный вызов, и слушается пометки «pragma: allowlist secret» во вставленном
    тексте. И не analyze_string: все включённые правила берут его общим, а он отдаёт значения без позиций."""
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    return tuple(
        regex
        for cls in get_mapping_from_secret_type_to_class().values()
        if cls.__name__ not in _SKIPPED_PLUGINS
        for regex in cls().denylist
    )


def _library_hits(squeezed: str) -> dict[str, list[int]]:
    """Значения правил в строке -> их начала, в порядке analyze_string. Значение — как у него: findall отдаёт
    непустые группы совпадения, а у выражения без групп — всё совпадение (здесь — без краёв, см. _LEADING_EDGE)."""
    hits: dict[str, list[int]] = {}
    for regex in _library_rules():
        groups = range(1, regex.groups + 1) if regex.groups else (0,)
        for m in regex.finditer(squeezed):
            for group in groups:
                value, start = m.group(group) or "", m.start(group)
                if not group:                           # края совпадения целиком (_LEADING_EDGE)
                    stripped = value.lstrip().lstrip(_LEADING_EDGE)
                    value, start = stripped.rstrip().rstrip(_TRAILING_EDGE), start + len(value) - len(stripped)
                if len(value) >= 8:
                    hits.setdefault(value, []).append(start)
    return hits


def _unsqueezed(line: str) -> Callable[[int], int]:
    """Позиция в строке со сжатыми рядами пробелов -> позиция в настоящей строке."""
    after: list[int] = []      # первая позиция сжатой строки после ряда
    removed: list[int] = []    # сколько пробелов выброшено до неё
    total = 0
    for m in _SPACES.finditer(line):
        total += m.end() - m.start() - 1
        after.append(m.end() - total)
        removed.append(total)

    def original(position: int) -> int:
        index = bisect_right(after, position)
        return position + (removed[index - 1] if index else 0)

    return original


def _library_spans(text: str, own: list[Span]) -> list[Span]:
    """Токены известных сервисов по правилам detect-secrets — там, где свои правила ничего не нашли."""
    spans: list[Span] = []
    # Занятые знаки — картой, а не перебором найденного: токен, повторённый на строке выгрузки сотни
    # раз, давал кубическое время (каждое повторение сверялось с каждым найденным, и столько же раз).
    taken = bytearray(len(text))
    for span in own:
        taken[span.start:span.end] = b"\x01" * (span.end - span.start)
    offset = 0
    for line in text.splitlines(keepends=True):
        hits = _library_hits(_SPACES.sub(" ", line))
        original = _unsqueezed(line) if len(hits) > _REPEATS else None
        for index, (value, starts) in enumerate(hits.items()):
            if original is None or index < _REPEATS:
                places = []                    # все вхождения, и там, где правило значения не видит
                position = line.find(value)    # значение ищется в настоящей строке, не в сжатой
                while position >= 0:
                    places.append(position)
                    position = line.find(value, position + 1)
            else:                              # значение с рядом пробелов внутри в настоящей строке другое
                places = [p for p in map(original, starts) if line.startswith(value, p)]
            for position in places:
                start, end = offset + position, offset + position + len(value)
                if taken.find(1, start, end) < 0:
                    spans.append(Span(start, end, EntityType.SECRET, name, validated=True))
                    taken[start:end] = b"\x01" * len(value)
        offset += len(line)
    return spans


def _value(m: re.Match[str], minimum: int = 3, code: bool = False) -> tuple[int, int] | None:
    """Границы значения в совпадении или None, если это не секрет. После имени ключа или параметра
    берётся и короткое значение (minimum=2): «password=Q7» — тоже пароль. code — значение стоит после ключа
    присваивания в коде (_in_code), и вызов или атрибут (_code) там не значение."""
    for group in ("dq", "sq", "bare"):
        if group not in m.re.groupindex or m.group(group) is None:
            continue
        start, end = m.span(group)
        if _TEMPLATE.match(m.group(group)):    # до обрезки: закрывающая скобка — часть подстановки
            return None
        if group == "bare":
            end = _trimmed_end(m.string, start, end)
            if code and _code(m.string, start, end):
                return None
        value = m.string[start:end]
        if len(value) < minimum or value.lower() in _NOT_SECRET or _TEMPLATE.match(value):
            return None
        return start, end
    return None


def _trimmed_end(string: str, start: int, end: int) -> int:
    """Конец значения string[start:end] без точек, запятых и скобок в конце, кроме скобки с парой внутри (_OPENING).
    Скобки считаются один раз: пересчёт на каждом знаке шёл квадратичное время на ряде «)))…»."""
    balance = {c: string.count(o, start, end) - string.count(c, start, end) for c, o in _OPENING.items()}
    while end > start and string[end - 1] in ".,)]}":
        closing = string[end - 1]
        if closing in balance:
            if balance[closing] >= 0:          # открывающих не меньше, чем закрывающих: пара последней внутри
                break
            balance[closing] += 1
        end -= 1
    return end


def _code(string: str, start: int, end: int) -> bool:
    """Значение без кавычек string[start:end] — вызов, индекс или атрибут в коде (см. _CALL), и в скобках тоже:
    «(input())». Скобки снимаются только парой по краям; «(Qw1)», «(Ab(1))» внутри — не код, «(a)(b)» — тоже. Снятое
    берётся копией: знак за ним (_CALL, «f(password=abc)») — своя скобка, а не текст после значения."""
    inner = start
    while end - inner > 2 and string[inner] == "(" and string[end - 1] == ")":
        inner, end = inner + 1, end - 1
    if inner > start:
        string, start, end = string[inner:end], 0, end - inner
    call = _CALL.match(string, start, end)
    if call is None:
        attribute = _ATTRIBUTE.fullmatch(string, start, end)
        return (
            attribute is not None and _code_object(attribute.group("first"))
            and _SECRET_NAME.search(attribute.group("last")) is not None
        )
    if call.group("dotted") is not None or (call.end() == end < len(string) and string[end] in ")]\"'"):
        return True
    closed = string[end - 1] == _CLOSING[string[call.end() - 1]]
    if not closed and not string.startswith(",", end):     # за значением — следующий аргумент («f(name, x)»)
        return False
    arguments = string[call.end():end - closed]
    return (closed and not arguments) or (
        _VARIABLE.match(call.group("name")) is not None and _NAMES.fullmatch(arguments) is not None
    )


def _code_object(name: str) -> bool:
    return name.startswith("$") or "_" in name or _CAMEL.search(name) is not None or name in _CODE_OBJECTS


def _in_code(text: str, key: str, key_start: int, value_end: int) -> bool:
    """Ключ text[key_start:…] из знаков ASCII и значение до value_end — присваивание в коде, а не поле строки
    подключения (_NEXT_FIELD) и не русское «Пароль:» (там пишут пароль, а не код)."""
    return (
        key.isascii() and not (key_start > 0 and text[key_start - 1] == ";")
        and _NEXT_FIELD.match(text, value_end) is None
    )


def _private_keys(text: str) -> list[Span]:
    """Блоки приватных ключей (_PEM_BEGIN, _PUTTY). Поиск идёт после конца предыдущего блока: заголовок внутри блока до
    конца текста иначе снова искал бы END до конца — квадратичное время на тексте из одних заголовков. По той же причине
    заголовок внутри строк «Имя: значение» заголовка без тела (failed_until) тело не ищет: его строки кончаются там же."""
    spans: list[Span] = []
    position = failed_until = 0
    while (m := _PEM_BEGIN.search(text, position)) is not None:
        start = m.start()
        while start > position and text[start - 1] in _DASHES:
            start -= 1
        if m.start() - start >= 2 and m.group("dashes"):
            end = _PEM_END.search(text, m.end())
            position = end.end() if end else len(text)
        elif m.end() <= failed_until:
            position = m.end()
            continue
        elif body := _PEM_BODY.match(text, armour := _PEM_ARMOUR.match(text, m.end()).end()):
            if start == m.start() and start > position and text[start - 1] in " \t":    # ряд через пробел — SSH2
                run = start - 1
                while run > position and text[run - 1] in _DASHES:
                    run -= 1
                start = run if start - 1 - run >= 2 else start
            position = body.end()
        else:
            failed_until, position = armour, m.end()
            continue
        spans.append(Span(start, position, EntityType.SECRET, name, validated=True))
    spans += [
        Span(m.start(), m.end(), EntityType.SECRET, name, validated=True)
        for m in _PUTTY.finditer(text) if _KEY_LINE.search(text, m.start(), m.end())
    ]
    return spans


def _looks_like_password(value: str) -> bool:
    kinds = (
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    )
    return len(value) >= 6 and sum(kinds) >= 2 and (kinds[2] or kinds[3])


def _prose_word(value: str) -> bool:
    """Слово фразы после «Пароль —», а не пароль: из _PROSE_WORDS или русское слово словаря, кроме существительного.
    Существительное и слово не из словаря — значение: «подсолнух», «йцукен» бывают паролями. Цена — русское
    прилагательное или глагол в роли пароля («Пароль — зелёный») остаётся открытым."""
    word = value.lower().replace("ё", "е")
    return word in _PROSE_WORDS or (
        _RUSSIAN_WORD.fullmatch(word) is not None and part_of_speech(word) not in (None, "NOUN")
    )


def _copula(m: re.Match[str]) -> bool:
    return (m.group("bare") or "").rstrip(_TRAILING).lower() in _COPULAS


def _after_dash(m: re.Match[str]) -> Span | None:
    """Значение после «Пароль —» (а также после связки за «:» и после четырёх слов и «:», см. _PHRASE) или None — там
    проза. Знаки в конце в проверку не входят, но скрываются со значением.
    Обычное слово, не похожее на пароль, скрывается только на этом месте и искомым написанием чата (5.4) не становится:
    «Пароль — Windows не принимает» иначе скрыло бы Windows во всех текстах чата, без восстановления в ответах.
    Значение в кавычках написано как есть, а не словом фразы, — оно искомое."""
    if _copula(m):
        m = _NEXT_VALUE.match(m.string, m.end())
    bounds = _value(m) if m else None
    if not bounds:
        return None
    if m.group("bare") is None:
        return Span(*bounds, EntityType.SECRET, name)
    word = m.string[bounds[0]:bounds[1]].rstrip(_TRAILING)
    # Русское слово через дефис похоже на пароль только дефисом («по-прежнему», см. _HYPHENATED_WORD) — его решает словарь.
    if _looks_like_password(word) and not _HYPHENATED_WORD.fullmatch(word):
        return Span(*bounds, EntityType.SECRET, name)
    return None if not word or _prose_word(word) else Span(*bounds, EntityType.SECRET, name, searchable=False)


def _secret_key(key: str) -> bool:
    return bool(_KEY_WORD.search(key)) and not (_NOT_SECRET_KEY.fullmatch(key) and not _SECRET_END.search(key))


def _not_a_value(key: str, value: str) -> bool:
    """Значение под ключом со словом секрета, которое секретом не является: имя той же переменной
    («cancellationToken: cancellationToken», «accessToken: AccessToken;»; но «password: password» —
    слабый пароль), вызов команды и число под ключом токена — счётчик («max_new_tokens: 1024»).
    Токенов из одних цифр не бывает, а пароль из цифр обычен, поэтому числа — только у «token».
    PWD и OLDPWD с путём — рабочий каталог оболочки, а не поле Pwd строки подключения."""
    return (
        (value.lower() == key.lower() and not _KEY_WORD.fullmatch(key))
        or _CMDLET.fullmatch(value) is not None
        or (value.isdigit() and all(word.lower() == "token" for word in _KEY_WORD.findall(key)))
        or (key.upper() in ("PWD", "OLDPWD") and value.startswith(("/", "~")))
    )


def detect(text: str, ctx: DetectContext) -> list[Span]:
    spans = _private_keys(text) + [
        Span(m.start(), m.end(), EntityType.SECRET, name, validated=True)
        for pattern in (_JWT, _TOKEN)
        for m in pattern.finditer(text)
    ]
    parsed_until = 0
    for m in _KEY_NAME.finditer(text):
        key = m.group("key")
        # Пара внутри уже разобранного значения пропускается: её значение кончается там же, а без этого
        # «token=token=…» или «PWD=/PWD=/…» разбирали значение до конца строки от каждого ключа.
        # Цена — пара внутри отвергнутого значения («PWD=/x?token=…») не ищется.
        if m.start() < parsed_until or not _secret_key(key):
            continue
        value = _VALUE_AT.match(text, m.end())
        if not value:
            continue
        parsed_until = value.end()
        if _copula(value):                     # «Пароль: это строка» — значение после связки, как после тире
            if span := _after_dash(value):
                spans.append(span)
            continue
        bounds = _value(value, minimum=2, code=_in_code(text, key, m.start(), value.end()))
        if bounds and not _not_a_value(key, text[bounds[0]:bounds[1]]):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _ADD_KEY.finditer(text):
        bounds = _value(m, minimum=2) if _secret_key(m.group("key")) else None
        if bounds and not _not_a_value(m.group("key"), text[bounds[0]:bounds[1]]):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for pattern in (_XML, _URL, _CLI, _SECURE, _AUTH, _BEARER, *_COMMANDS):
        for m in pattern.finditer(text):
            bounds = _value(m, minimum=2 if pattern is _CLI or pattern in _COMMANDS else 3)
            if bounds and not (pattern in (_AUTH, _BEARER) and _WORDS.fullmatch(text, *bounds)):
                spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _PHRASE.finditer(text):
        if m.group("sep") is None or _copula(m):
            span = _after_dash(m)
        else:
            # «password = …» без слов перед «=» — тот же ключ присваивания, что видит _KEY_NAME.
            keyword = text[m.start():m.start("sep")]
            bounds = _value(m, code=keyword.lower() == "password" and _in_code(text, keyword, m.start(), m.end()))
            span = Span(*bounds, EntityType.SECRET, name) if bounds else None
        if span:
            spans.append(span)
    for m in _PROSE.finditer(text):
        bounds = _value(m)
        if bounds and _looks_like_password(text[bounds[0]:bounds[1]]) and not _HYPHENATED_WORD.fullmatch(text, *bounds):
            spans.append(Span(*bounds, EntityType.SECRET, name))
    for m in _TOKEN_PHRASE.finditer(text):
        spans.append(Span(*m.span("bare"), EntityType.SECRET, name, searchable=_looks_like_password(m.group("bare"))))
    return spans + _library_spans(text, spans)
