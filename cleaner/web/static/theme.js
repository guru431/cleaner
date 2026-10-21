// Тема до отрисовки (раздел 14): класс js для вкладок и выбор пользователя из localStorage.
"use strict";
document.documentElement.classList.add("js");
try {
  const theme = localStorage.getItem("cleaner-theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch (error) {
  // хранилище недоступно — тема как в системе
}
// Вид рабочего места (меню «Вид»): отметки — именами через пробел; ставятся только известные, иначе — исходный вид.
try {
  const marks = ["text-large", "rows-loose", "side-folded", "composer-folded", "reading"];
  (localStorage.getItem("cleaner-view") || "").split(" ").filter((name) => marks.includes(name))
    .forEach((name) => document.documentElement.classList.add(`view-${name}`));
} catch (error) {
  // хранилище недоступно — исходный вид
}
