/**
 * Client-side session progress tracker for the After-Scam Recovery steps.
 * Purely in-memory in the current browser tab; nothing is stored or transmitted.
 */
(function () {
  "use strict";

  const checkboxes = document.querySelectorAll(".recovery-step-check");
  const statusEl = document.getElementById("recovery-progress-text");
  const resetBtn = document.getElementById("reset-recovery-checks");

  if (!checkboxes.length || !statusEl) {
    return;
  }

  function updateProgress() {
    let completed = 0;
    checkboxes.forEach(function (box) {
      if (box.checked) {
        completed += 1;
      }
    });
    statusEl.textContent =
      completed + " of " + checkboxes.length + " recovery steps marked complete (for your reference only).";
  }

  checkboxes.forEach(function (box) {
    box.addEventListener("change", updateProgress);
  });

  if (resetBtn) {
    resetBtn.addEventListener("click", function () {
      checkboxes.forEach(function (box) {
        box.checked = false;
      });
      updateProgress();
    });
  }

  updateProgress();
})();
