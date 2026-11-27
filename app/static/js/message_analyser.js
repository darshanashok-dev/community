/**
 * Progressive-enhancement helpers for the Message Analyser page.
 * Handles character counter, clearing the form, and populating fictional demo examples.
 * Does not persist, log, or transmit user input externally.
 */
(function () {
  "use strict";

  const textarea = document.getElementById("message-text");
  const channelSelect = document.getElementById("message-channel");
  const counter = document.getElementById("message-char-count");
  const clearBtn = document.getElementById("clear-message-btn");
  const sampleButtons = document.querySelectorAll(".sample-btn");
  const meterFill = document.querySelector(".score-meter__fill[data-score]");

  if (meterFill) {
    const score = Number(meterFill.getAttribute("data-score")) || 0;
    const clamped = Math.max(0, Math.min(100, score));
    meterFill.style.width = clamped + "%";
  }

  if (!textarea) {
    return;
  }

  const maxLen = Number(textarea.getAttribute("maxlength")) || 5000;

  function updateCount() {
    if (counter) {
      counter.textContent = textarea.value.length + " / " + maxLen;
    }
  }

  textarea.addEventListener("input", updateCount);
  updateCount();

  if (clearBtn) {
    clearBtn.addEventListener("click", function () {
      textarea.value = "";
      updateCount();
      textarea.focus();
    });
  }

  const FICTIONAL_SAMPLES = {
    digital_arrest:
      "This is CBI Cyber Crime Officer calling. Your Aadhaar is linked to a money laundering parcel with illegal drugs. A non-bailable arrest warrant is issued and you are under digital arrest. Stay on WhatsApp video call, do not tell family or anyone, and transfer Rs. 50,000 to the RBI safe account for verification.",
    phishing_kyc:
      "URGENT: Your bank KYC is suspended today and your account will be blocked within 2 hours. Click http://example-verify-kyc.invalid/login and enter your OTP and PAN card details immediately.",
    benign_bank:
      "Rs. 1,250.00 debited from A/c XX4321 via UPI Ref 633100001122. Avl Bal Rs. 14,820.50. Your OTP for login is 482910. Valid for 5 mins. Do not share this OTP with anyone.",
    benign_delivery:
      "Your package AWB No 90887766 is out for delivery today. Our delivery partner will reach you soon. Track on official app."
  };

  const form = document.getElementById("message-analyser-form");
  const submitBtn = form ? form.querySelector('button[type="submit"]') : null;

  if (form && submitBtn) {
    form.addEventListener("submit", function () {
      form.setAttribute("aria-busy", "true");
      submitBtn.textContent = "Analysing Message...";
    });
  }

  sampleButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      const key = btn.getAttribute("data-sample");
      const channel = btn.getAttribute("data-channel");
      if (key && FICTIONAL_SAMPLES[key]) {
        textarea.value = FICTIONAL_SAMPLES[key];
        if (channelSelect && channel) {
          channelSelect.value = channel;
        }
        updateCount();
        textarea.focus();
      }
    });
  });
})();
