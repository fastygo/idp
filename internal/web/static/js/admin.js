/**
 * admin.js — Admin console interactions.
 * Handles user creation form validation and feedback.
 */
(function () {
  "use strict";

  const form = document.querySelector('form[action="/console/users"]');
  if (!form) return;

  form.addEventListener("submit", function () {
    const btn = form.querySelector('button[type="submit"]');
    if (btn) {
      btn.disabled = true;
      btn.classList.add("opacity-50");
    }
  });
})();
