/**
 * Progressive-enhancement helper for the Learning & Quiz page.
 * Sets the quiz score bar width cleanly without inline styles.
 */
(function () {
  "use strict";

  const meterFill = document.querySelector(".score-meter__fill[data-score]");
  if (meterFill) {
    const score = Number(meterFill.getAttribute("data-score")) || 0;
    const clamped = Math.max(0, Math.min(100, score));
    meterFill.style.width = clamped + "%";
  }
})();
