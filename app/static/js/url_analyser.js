/**
 * Progressive-enhancement helpers for the URL Analyser page.
 * Sets score meter width safely without inline styles and populates fictional demo URLs.
 */
(function () {
  "use strict";

  const urlInput = document.getElementById("url-input");
  const clearBtn = document.getElementById("clear-url-btn");
  const sampleButtons = document.querySelectorAll(".url-sample-btn");
  const meterFill = document.querySelector(".score-meter__fill[data-score]");

  if (meterFill) {
    const score = Number(meterFill.getAttribute("data-score")) || 0;
    const clamped = Math.max(0, Math.min(100, score));
    meterFill.style.width = clamped + "%";
  }

  if (!urlInput) {
    return;
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", function () {
      urlInput.value = "";
      urlInput.focus();
    });
  }

  const form = document.getElementById("url-analyser-form");
  const submitBtn = form ? form.querySelector('button[type="submit"]') : null;

  if (form && submitBtn) {
    form.addEventListener("submit", function () {
      form.setAttribute("aria-busy", "true");
      submitBtn.textContent = "Inspecting URL...";
    });
  }

  sampleButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      const sampleUrl = btn.getAttribute("data-url");
      if (sampleUrl) {
        urlInput.value = sampleUrl;
        urlInput.focus();
      }
    });
  });
})();
