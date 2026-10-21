// Копирование, парная подсветка замен (FR-6.1) и выделение фрагмента оригинала (FR-6.3).
"use strict";

// Объявления для экранных читалок: подпись кнопки меняется молча, а область role=status читается. Область — с загрузки:
// созданную в момент объявления читалка пропускает.
const live = document.createElement("span");
live.className = "sr-only";
live.setAttribute("role", "status");
document.body.append(live);

// Итог копирования — на кнопке словом (и цветом, data-state), через несколько секунд подпись прежняя.
const copyTimers = new WeakMap();
function copyState(button, text, state, ms) {
  const label = button.querySelector("span") || button;     // подпись — в <span>, если он есть: иконка остаётся
  button.dataset.label ??= label.textContent;
  label.textContent = text;
  button.dataset.state = state;
  live.textContent = text;
  clearTimeout(copyTimers.get(button));
  copyTimers.set(button, setTimeout(() => { label.textContent = button.dataset.label; delete button.dataset.state; }, ms));
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (button) {
    const source = document.getElementById(button.dataset.copy);
    // Буфер запрещён браузером или недоступен (адрес не https и не петля — navigator.clipboard нет): текст выделяется,
    // и его копируют сами.
    const failed = () => {
      const range = document.createRange();
      range.selectNodeContents(source);
      const selection = document.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      copyState(button, "Не удалось скопировать — текст выделен, нажмите Ctrl+C", "failed", 8000);
    };
    if (!navigator.clipboard) { failed(); return; }
    navigator.clipboard.writeText(source.textContent).then(() => copyState(button, "Скопировано", "done", 2000), failed);
    return;
  }
  // Кнопки рабочего места проверки и карточка «Почему скрыто» выбор не снимают (select — ниже).
  if (event.target.closest("[data-review-tools], #why")) return;
  select(event.target.closest("mark"));
});

document.addEventListener("selectionchange", () => {
  const panel = document.getElementById("original");
  const field = document.getElementById("mask-value");
  const selection = document.getSelection();
  if (!panel || !field || !selection || selection.isCollapsed) return;
  if (!panel.contains(selection.anchorNode) || !panel.contains(selection.focusNode)) return;
  // Значение, а не позиции: браузер отдаёт переводы строк как LF, сервер ищет значение в оригинале сам.
  field.value = selection.toString().trim();
});

// Перезагрузка по опросу или по концу потока. Ленту прокручивает она сама, а страницу проверки — main, а не окно,
// и их место браузер не восстанавливает. Оно кладётся в состояние этой записи истории (history.state — не хранилище:
// живёт в этой вкладке, на этой записи) и возвращается при загрузке: у ленты, если читали не конец, — верхний
// видимый элемент и сдвиг от его верха (элемент, а не scrollTop: выросший выше элемент — повтор старого текста —
// иначе сдвинул бы место чтения); у main — scrollTop (на проверке перезагружает итог проверки риска, а всё выше
// вкладок остаётся прежним; без этого вкладка с итогом уходила под край окна).
function refresh() {
  const place = { ...history.state };
  const feed = document.querySelector("[data-scroll-end]");
  if (feed && feed.scrollHeight - feed.scrollTop - feed.clientHeight > 2) {
    const top = feed.getBoundingClientRect().top;
    const item = [...feed.children].find((element) => element.getBoundingClientRect().bottom > top);
    if (item) place.feed = { item: item.id, offset: top - item.getBoundingClientRect().top };
  }
  const main = document.querySelector("main");
  if (main && main.scrollTop > 0) place.main = main.scrollTop;
  // Панели «Оригинал» и «Очищенный» на проверке прокручиваются сами (pre.text с id) — их места тоже.
  const panes = [...document.querySelectorAll("pre.text[id]")].filter((pane) => pane.scrollTop > 0);
  if (panes.length) place.panes = Object.fromEntries(panes.map((pane) => [pane.id, pane.scrollTop]));
  history.replaceState(place, "");
  window.location.reload();
}

// Начатый, но не отправленный ввод: перезагрузка его сбросила бы (поля браузер восстанавливает не всегда, выбор файла —
// никогда). Скрытые поля пишет сервер — не в счёт; список без selected в разметке исходно стоит на первом варианте.
function editing() {
  return [...document.querySelectorAll("input, textarea, select")].some((field) => {
    if (field.type === "hidden" || field.disabled) return false;
    if (field.type === "file") return field.files.length > 0;
    if (field.type === "checkbox" || field.type === "radio") return field.checked !== field.defaultChecked;
    if (field.tagName === "SELECT") {
      const options = [...field.options];
      if (field.multiple) return options.some((option) => option.selected !== option.defaultSelected);
      return options.length > 0 && field.selectedIndex !== Math.max(0, options.findIndex((option) => option.defaultSelected));
    }
    return field.value !== field.defaultValue;
  });
}

// По концу задания, проверки риска или потока страница перезагружается, если ввод не начат. Иначе — строка над
// страницей: что готово и кнопка «Обновить результат», которую нажимают, когда закончат; опрос больше не нужен.
const finished = [];
let note = null;
function reload(what) {
  if (!editing()) { refresh(); return; }
  if (!finished.includes(what)) finished.push(what);
  if (!note) {
    note = document.createElement("div");
    note.className = "reload-note";
    note.setAttribute("role", "status");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Обновить результат";
    button.title = "Перезагрузить страницу: не отправленный ввод в формах пропадёт";
    button.addEventListener("click", refresh);
    note.append(document.createElement("span"), button);
    document.querySelector("main").before(note);
  }
  note.firstChild.textContent = `Готово: ${finished.join(", ")}. Страница не обновлена, чтобы не сбросить ваш ввод.`;
}

// Что готово — для строки выше: заголовок элемента ленты, иначе (проверка) — что именно шло.
function finishedName(element) {
  const title = element.closest(".item") && element.closest(".item").querySelector(".title");
  if (title) return title.textContent.trim();
  return element.dataset.pollField === "risk" ? "проверка остаточного риска" : "обработка текста";
}

// Ответ облачной модели по мере получения (раздел 14): события сервера несут весь восстановленный к этому
// моменту текст; по «done» страница перезагружается и показывает полное восстановление с выделением.
document.querySelectorAll("[data-stream]").forEach((element) => {
  const source = new EventSource(element.dataset.stream);
  source.onmessage = (event) => {
    element.classList.remove("muted");
    element.textContent = JSON.parse(event.data).text;
  };
  source.addEventListener("done", () => { source.close(); reload(finishedName(element)); });
});

// Опрос фоновой обработки (раздел 14): пока задание в очереди или в работе — раз в секунду, потом перезагрузка.
document.querySelectorAll("[data-poll]").forEach((element) => {
  const field = element.dataset.pollField || "status";
  const check = () => {
    fetch(element.dataset.poll, { credentials: "same-origin", cache: "no-store" })
      .then((response) => (response.ok ? response.json() : null))
      .then((state) => {
        if (!state) { setTimeout(check, 5000); return; }
        const progress = element.querySelector("[data-progress]");
        if (progress) progress.textContent = state.progress || "";
        if (state[field] === "queued" || state[field] === "running") setTimeout(check, 1000);
        else reload(finishedName(element));
      })
      .catch(() => setTimeout(check, 5000));
  };
  setTimeout(check, 1000);
});

// Тема (раздел 14): кнопка в шапке и на входе — по кругу «как в системе → светлая → тёмная». «Как в системе» — без
// data-theme и без записи в localStorage, тогда действует prefers-color-scheme. Режим на кнопке показывает CSS по data-theme.
const root = document.documentElement;
const THEMES = ["", "light", "dark"];
document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const next = THEMES[(THEMES.indexOf(root.dataset.theme || "") + 1) % THEMES.length];
    if (next) root.dataset.theme = next;
    else delete root.dataset.theme;
    try {
      if (next) localStorage.setItem("cleaner-theme", next);
      else localStorage.removeItem("cleaner-theme");
    } catch (error) { /* выбор — до перезагрузки */ }
  });
});

// Вкладки: кнопки [data-tab], панели [data-tab-panel]; без JS видны все панели. data-tabs-remember — выбор
// этой страницы в sessionStorage.
document.querySelectorAll("[data-tabs]").forEach((container) => {
  const key = `tab:${window.location.pathname}`;
  const remember = "tabsRemember" in container.dataset;
  const tabs = [...container.querySelectorAll("[data-tab]")];
  const show = (name) => {
    tabs.forEach((tab) => tab.setAttribute("aria-selected", String(tab.dataset.tab === name)));
    container.querySelectorAll("[data-tab-panel]").forEach((panel) => panel.classList.toggle("on", panel.dataset.tabPanel === name));
  };
  tabs.forEach((tab) => tab.addEventListener("click", () => {
    show(tab.dataset.tab);
    if (remember) {
      try { sessionStorage.setItem(key, tab.dataset.tab); } catch (error) { /* не запомнится */ }
    }
  }));
  if (remember) {
    let saved = null;
    try { saved = sessionStorage.getItem(key); } catch (error) { /* как по умолчанию */ }
    if (tabs.some((tab) => tab.dataset.tab === saved)) show(saved);
  }
});

// Лента открывается там, где её читали перед перезагрузкой (reload выше; место возвращается один раз), иначе — на
// элементе из адреса (#item-… после ответа, отправки, вопроса локальной модели: браузер переходит к якорю при
// открытии, но не при перезагрузке), иначе — на последнем элементе.
document.querySelectorAll("[data-scroll-end]").forEach((feed) => {
  const { feed: saved, ...rest } = history.state || {};
  const item = document.getElementById(saved ? saved.item : window.location.hash.slice(1));
  if (item && feed.contains(item)) feed.scrollTop += item.getBoundingClientRect().top - feed.getBoundingClientRect().top + (saved ? saved.offset : 0);
  else feed.scrollTop = feed.scrollHeight;
  if (saved) history.replaceState(rest, "");
});

// main — туда же, где страницу читали перед перезагрузкой (reload выше), один раз. После вкладок: выбранная вкладка
// задаёт высоту страницы.
document.querySelectorAll("main").forEach((main) => {
  const { main: saved, ...rest } = history.state || {};
  if (saved === undefined) return;
  main.scrollTop = saved;
  history.replaceState(rest, "");
});

// Панели текста — туда же, один раз.
(() => {
  const { panes, ...rest } = history.state || {};
  if (!panes) return;
  Object.entries(panes).forEach(([id, top]) => {
    const pane = document.getElementById(id);
    if (pane) pane.scrollTop = top;
  });
  history.replaceState(rest, "");
})();

// Рабочее место проверки (review.html): выбор замены (щелчок, кнопки, N / P, Enter — пара в соседней панели, Esc —
// снять выбор), легенда-фильтр, поиск по обеим панелям, синхронная прокрутка, карточка «Почему скрыто», фильтры
// таблицы фрагментов. Всё — на странице, без запросов; в карточку копируется готовая запись из <template id="why-data">.
const reviewPanes = ["original", "sanitized"].map((id) => document.getElementById(id)).filter(Boolean);
const whyBody = document.querySelector("#why [data-why-body]");
const whyEmpty = whyBody ? [...whyBody.childNodes].map((node) => node.cloneNode(true)) : [];
let picked = null;                      // выбранная замена: от неё считают N / P и Enter
let lastPane = reviewPanes[0];

const paneOf = (node) => reviewPanes.find((pane) => pane.contains(node));

// Видимая часть панели: прокручивается сама панель, а не страница.
function reveal(pane, rect) {
  const box = pane.getBoundingClientRect();
  if (rect.top < box.top || rect.bottom > box.bottom) pane.scrollTop += rect.top - box.top - pane.clientHeight / 3;
}

// Замены панели, по которым ходят N / P: при включённой легенде — только отобранные ею.
function marksOf(pane) {
  const marks = [...pane.querySelectorAll("mark")];
  return pane.classList.contains("only") ? marks.filter((mark) => mark.classList.contains("pick")) : marks;
}

function showWhy(mark) {
  if (!whyBody) return;
  const place = document.querySelector("#why [data-why-place]");
  const key = mark && (mark.dataset.entity || ["leak", "opened"].find((name) => mark.classList.contains(name)));
  const entry = key && document.getElementById("why-data").content.querySelector(`[data-why="${CSS.escape(key)}"]`);
  const pane = mark && paneOf(mark);
  if (!entry || !pane) {
    whyBody.replaceChildren(...whyEmpty.map((node) => node.cloneNode(true)));
    place.textContent = "";
    return;
  }
  whyBody.replaceChildren(entry.cloneNode(true));
  const marks = [...pane.querySelectorAll("mark")];
  place.textContent = `${pane.getAttribute("aria-label")}: ${marks.indexOf(mark) + 1} из ${marks.length}`;
}

// Выбор замены: у сущности подсвечивается пара во всех панелях (FR-6.1); в панелях проверки выбираются и метки без
// сущности (утечка, открытое значение). focus — для клавиатуры и кнопок: фокус на метке, панель докручивается до неё.
function select(mark, focus = false) {
  document.querySelectorAll("mark.active").forEach((active) => active.classList.remove("active"));
  picked = mark && (mark.dataset.entity || paneOf(mark)) ? mark : null;
  if (picked && picked.dataset.entity) {
    document.querySelectorAll(`mark[data-entity="${CSS.escape(picked.dataset.entity)}"]`).forEach((pair) => pair.classList.add("active"));
  } else if (picked) picked.classList.add("active");
  showWhy(picked);
  if (picked && focus) {
    picked.tabIndex = -1;
    picked.focus({ preventScroll: true });
    reveal(paneOf(picked), picked.getBoundingClientRect());
  }
}

function step(direction) {
  const pane = (picked && paneOf(picked)) || lastPane;
  const marks = pane ? marksOf(pane) : [];
  if (!marks.length) return;
  const at = marks.indexOf(picked);
  let next;
  if (at >= 0) next = (at + direction + marks.length) % marks.length;
  else {
    // Выбранная скрыта легендой (или выбора нет) — ближайшая отобранная по направлению.
    const after = picked ? marks.findIndex((mark) => picked.compareDocumentPosition(mark) & Node.DOCUMENT_POSITION_FOLLOWING) : -1;
    next = direction > 0 ? Math.max(after, 0) : (after > 0 ? after : marks.length) - 1;
  }
  select(marks[next], true);
}

// Пара выбранной замены в соседней панели: то же по счёту вхождение той же сущности (порядок замен в панелях общий).
function pair() {
  const pane = picked && picked.dataset.entity && paneOf(picked);
  const other = pane && reviewPanes.find((candidate) => candidate !== pane);
  if (!other) return;
  const selector = `mark[data-entity="${CSS.escape(picked.dataset.entity)}"]`;
  const twins = [...other.querySelectorAll(selector)];
  if (twins.length) select(twins[Math.min([...pane.querySelectorAll(selector)].indexOf(picked), twins.length - 1)], true);
}

reviewPanes.forEach((pane) => {
  pane.addEventListener("focusin", () => { lastPane = pane; });
  pane.addEventListener("keydown", (event) => {
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    // По коду клавиши: N / P работают и в русской раскладке.
    if (event.code === "KeyN" || event.code === "KeyP") {
      event.preventDefault();
      step(event.code === "KeyN" ? 1 : -1);
    } else if (event.key === "Enter" && picked && pane.contains(picked)) {
      event.preventDefault();
      pair();
    } else if (event.key === "Escape" && picked) {
      select(null);
      pane.focus();
    }
  });
});

document.querySelectorAll("[data-step]").forEach((button) => button.addEventListener("click", () => step(Number(button.dataset.step))));

// Легенда: нажатые кнопки оставляют выделенными только свои метки (тип, блокировка, утечка, открытое); N / P ходят по ним.
const legendChips = [...document.querySelectorAll("[data-legend]")];
legendChips.forEach((chip) => chip.addEventListener("click", () => {
  chip.setAttribute("aria-pressed", String(chip.getAttribute("aria-pressed") !== "true"));
  const on = legendChips.filter((item) => item.getAttribute("aria-pressed") === "true").map((item) => item.dataset.legend);
  reviewPanes.forEach((pane) => {
    pane.classList.toggle("only", on.length > 0);
    pane.querySelectorAll("mark").forEach((mark) => mark.classList.toggle("pick", on.some((name) => mark.classList.contains(name))));
  });
}));

// Синхронная прокрутка — по доле высоты (тексты разной длины). echo — панель, которую прокрутил этот обработчик: её
// событие обратно не отражается. Включённая — запоминается в этом браузере.
document.querySelectorAll("[data-sync-scroll]").forEach((button) => {
  let on = false;
  let echo = null;
  try { on = localStorage.getItem("cleaner-sync-scroll") === "1"; } catch (error) { /* выключена */ }
  button.setAttribute("aria-pressed", String(on));
  button.addEventListener("click", () => {
    on = !on;
    button.setAttribute("aria-pressed", String(on));
    try { localStorage.setItem("cleaner-sync-scroll", on ? "1" : "0"); } catch (error) { /* до перезагрузки */ }
  });
  reviewPanes.forEach((pane) => pane.addEventListener("scroll", () => {
    if (echo === pane) { echo = null; return; }
    const other = reviewPanes.find((candidate) => candidate !== pane);
    if (!on || !other) return;
    const range = pane.scrollHeight - pane.clientHeight;
    const target = range > 0 ? (pane.scrollTop / range) * (other.scrollHeight - other.clientHeight) : 0;
    if (Math.abs(other.scrollTop - target) < 1) return;
    echo = other;
    other.scrollTop = target;
  }, { passive: true }));
});

// Поиск по обеим панелям: совпадения — CSS Custom Highlight API (разметку текста не трогает), без него — счётчик и
// переходы. Без учёта регистра, если строчные буквы той же длины. Не больше FIND_LIMIT совпадений — DOM и подсветка
// ограничены и на длинном тексте.
const FIND_LIMIT = 1000;
document.querySelectorAll("#review-find").forEach((field) => {
  const found = document.getElementById("review-found");
  const highlights = window.CSS && CSS.highlights;
  // Текст панели неизменен — текстовые узлы и их начала считаются один раз.
  const indexes = new Map(reviewPanes.map((pane) => {
    const walker = document.createTreeWalker(pane, NodeFilter.SHOW_TEXT);
    const nodes = [];
    const starts = [];
    let length = 0;
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      nodes.push(node);
      starts.push(length);
      length += node.data.length;
    }
    return [pane, { nodes, starts, text: nodes.map((node) => node.data).join("") }];
  }));
  const point = ({ nodes, starts }, offset, end) => {
    let low = 0;
    let high = starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if (end ? starts[mid] < offset : starts[mid] <= offset) low = mid;
      else high = mid - 1;
    }
    return [nodes[low], offset - starts[low]];
  };
  let hits = [];
  let current = -1;
  const paint = () => {
    if (highlights) {
      highlights.set("review-find", new Highlight(...hits.map((hit) => hit.range)));
      highlights.set("review-find-current", new Highlight(...(current >= 0 ? [hits[current].range] : [])));
    }
    const counts = reviewPanes.map((pane) => `${pane.getAttribute("aria-label").toLowerCase()} ${hits.filter((hit) => hit.pane === pane).length}`);
    const more = hits.length >= FIND_LIMIT ? " (показаны первые — уточните запрос)" : "";
    found.textContent = !field.value ? "" : hits.length ? `${current + 1} из ${hits.length}${more} · ${counts.join(", ")}` : "Не найдено";
    if (current >= 0) reveal(hits[current].pane, hits[current].range.getBoundingClientRect());
  };
  let timer = null;
  let searched = "";                    // запрос, по которому собраны hits
  const search = () => {
    clearTimeout(timer);
    searched = field.value;
    hits = [];
    for (const pane of reviewPanes) {
      const index = indexes.get(pane);
      if (!field.value || !index.nodes.length) continue;
      const lower = index.text.toLowerCase();
      const fold = lower.length === index.text.length;
      const text = fold ? lower : index.text;
      const needle = fold ? field.value.toLowerCase() : field.value;
      for (let at = text.indexOf(needle); at >= 0 && hits.length < FIND_LIMIT; at = text.indexOf(needle, at + needle.length)) {
        const range = document.createRange();
        range.setStart(...point(index, at, false));
        range.setEnd(...point(index, at + needle.length, true));
        hits.push({ pane, range });
      }
    }
    current = hits.length ? 0 : -1;
    paint();
  };
  // Запрос ещё не искали (Enter или кнопка до конца паузы ввода) — искать и встать на первое, иначе — соседнее.
  const go = (direction) => {
    if (field.value !== searched) { search(); return; }
    if (!hits.length) return;
    current = (current + direction + hits.length) % hits.length;
    paint();
  };
  field.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 150); });
  field.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    go(event.shiftKey ? -1 : 1);
  });
  document.querySelectorAll("[data-find]").forEach((button) => button.addEventListener("click", () => go(Number(button.dataset.find))));
});

// Фильтры таблицы по кодам в data-атрибутах строк (тип, кто нашёл); строки только скрываются.
document.querySelectorAll("[data-filter-table]").forEach((bar) => {
  const rows = [...document.getElementById(bar.dataset.filterTable).querySelectorAll("tbody tr[data-type]")];
  const count = bar.querySelector("[data-filter-count]");
  const apply = () => {
    const chosen = Object.fromEntries([...bar.querySelectorAll("[data-filter]")].map((control) => [control.dataset.filter, control.value]));
    let shown = 0;
    rows.forEach((row) => {
      row.hidden = Boolean((chosen.type && row.dataset.type !== chosen.type) || (chosen.source && !row.dataset.sources.split(" ").includes(chosen.source)));
      if (!row.hidden) shown += 1;
    });
    count.textContent = chosen.type || chosen.source ? `Показаны ${shown} из ${rows.length}` : "";
  };
  bar.addEventListener("change", apply);
  apply();
});
