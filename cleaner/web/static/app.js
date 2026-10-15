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

// Ответ облачной модели по мере получения (раздел 14): события сервера несут весь восстановленный к этому
// моменту текст; по «done» страница перезагружается и показывает полное восстановление с выделением.
document.querySelectorAll("[data-stream]").forEach((element) => {
  const source = new EventSource(element.dataset.stream);
  source.onmessage = (event) => {
    element.classList.remove("muted");
    element.textContent = JSON.parse(event.data).text;
  };
  source.addEventListener("done", () => { source.close(); window.location.reload(); });
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
        else window.location.reload();
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

// Лента открывается на последнем элементе.
document.querySelectorAll("[data-scroll-end]").forEach((element) => { element.scrollTop = element.scrollHeight; });
