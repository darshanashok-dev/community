/**
 * Progressive-enhancement navigation toggle for responsive layouts.
 */
(function () {
  "use strict";

  const toggleButton = document.getElementById("nav-toggle");
  const navMenu = document.getElementById("primary-navigation");

  if (!toggleButton || !navMenu) {
    return;
  }

  function setMenuOpen(isOpen) {
    toggleButton.setAttribute("aria-expanded", String(isOpen));
    navMenu.classList.toggle("is-open", isOpen);
  }

  toggleButton.addEventListener("click", function () {
    const currentlyOpen = toggleButton.getAttribute("aria-expanded") === "true";
    setMenuOpen(!currentlyOpen);
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && navMenu.classList.contains("is-open")) {
      setMenuOpen(false);
      toggleButton.focus();
    }
  });
})();
