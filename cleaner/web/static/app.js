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
  document.querySelectorAll("mark.active").forEach((mark) => mark.classList.remove("active"));
  const mark = event.target.closest("mark[data-entity]");
  if (mark) {
    const selector = `mark[data-entity="${CSS.escape(mark.dataset.entity)}"]`;
    document.querySelectorAll(selector).forEach((pair) => pair.classList.add("active"));
  }
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
