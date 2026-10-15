// Тема до отрисовки (раздел 14): класс js для вкладок и выбор пользователя из localStorage.
"use strict";
document.documentElement.classList.add("js");
try {
  const theme = localStorage.getItem("cleaner-theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch (error) {
  // хранилище недоступно — тема как в системе
}
