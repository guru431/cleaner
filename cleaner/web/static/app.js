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
