// Копирование, парная подсветка замен (FR-6.1) и выделение фрагмента оригинала (FR-6.3).
"use strict";

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (button) {
    const source = document.getElementById(button.dataset.copy);
    navigator.clipboard.writeText(source.textContent).then(() => { button.textContent = "Скопировано"; });
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
