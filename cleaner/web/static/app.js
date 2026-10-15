// Копирование, парная подсветка замен (FR-6.1) и выделение фрагмента оригинала (FR-6.3).
"use strict";

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (button) {
    const source = document.getElementById(button.dataset.copy);
    // Подпись — в <span>, если он есть: иконка кнопки остаётся.
    navigator.clipboard.writeText(source.textContent).then(() => { (button.querySelector("span") || button).textContent = "Скопировано"; });
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
function reload() {
  const place = { ...history.state };
  const feed = document.querySelector("[data-scroll-end]");
  if (feed && feed.scrollHeight - feed.scrollTop - feed.clientHeight > 2) {
    const top = feed.getBoundingClientRect().top;
    const item = [...feed.children].find((element) => element.getBoundingClientRect().bottom > top);
    if (item) place.feed = { item: item.id, offset: top - item.getBoundingClientRect().top };
  }
  const main = document.querySelector("main");
  if (main && main.scrollTop > 0) place.main = main.scrollTop;
  history.replaceState(place, "");
  window.location.reload();
}

// Ответ облачной модели по мере получения (раздел 14): события сервера несут весь восстановленный к этому
// моменту текст; по «done» страница перезагружается и показывает полное восстановление с выделением.
document.querySelectorAll("[data-stream]").forEach((element) => {
  const source = new EventSource(element.dataset.stream);
  source.onmessage = (event) => {
    element.classList.remove("muted");
    element.textContent = JSON.parse(event.data).text;
  };
  source.addEventListener("done", () => { source.close(); reload(); });
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
        else reload();
      })
      .catch(() => setTimeout(check, 5000));
  };
  setTimeout(check, 1000);
});

// Тема (раздел 14): кнопка в шапке ставит противоположную действующей и запоминает выбор в этом браузере.
const root = document.documentElement;
document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("cleaner-theme", root.dataset.theme); } catch (error) { /* выбор — до перезагрузки */ }
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
