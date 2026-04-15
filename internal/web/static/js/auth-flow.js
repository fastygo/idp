/**
 * auth-flow.js — Custom login state machine using hanko-frontend-sdk.
 * Drives the login form rendered by login.templ with UI8Kit CSS classes.
 *
 * State flow is driven imperatively: createState() and action.run() return
 * the next interactive state after the SDK's internal auto-steps (e.g.
 * "preflight" is skipped automatically). We do NOT use onAfterStateChange
 * because it fires for intermediate auto-stepped states and conflicts with
 * the SDK's own stepping logic.
 */
(function () {
  "use strict";

  var configEl = document.getElementById("auth-config");
  if (!configEl) return;

  var config = JSON.parse(configEl.textContent);
  var hankoApiUrl = config.hankoApiUrl;
  var allowPublicRegistration = config.allowPublicRegistration;

  var HankoClass =
    (window.hankoFrontendSdk && window.hankoFrontendSdk.Hanko) ||
    window.Hanko;

  if (!hankoApiUrl || !HankoClass) return;

  var loadingEl = document.getElementById("auth-loading");
  var formEl = document.getElementById("auth-login-form");
  var emailInput = document.getElementById("auth-email");
  var passwordWrap = document.getElementById("auth-password-wrap");
  var passwordInput = document.getElementById("auth-password");
  var errorEl = document.getElementById("auth-error");
  var submitBtn = document.getElementById("auth-submit");

  if (!formEl || !emailInput) return;

  var hanko = new HankoClass(hankoApiUrl);
  var currentState = null;

  function showError(msg) {
    if (errorEl) {
      errorEl.textContent = msg;
      errorEl.classList.remove("hidden");
    }
  }

  function clearError() {
    if (errorEl) {
      errorEl.textContent = "";
      errorEl.classList.add("hidden");
    }
  }

  function showForm() {
    if (loadingEl) loadingEl.classList.add("hidden");
    formEl.classList.remove("hidden");
  }

  function showPasswordField() {
    if (passwordWrap) {
      passwordWrap.classList.remove("hidden");
      if (passwordInput) passwordInput.focus();
    }
  }

  function hidePasswordField() {
    if (passwordWrap) {
      passwordWrap.classList.add("hidden");
    }
  }

  function setLoading(on) {
    if (submitBtn) {
      submitBtn.disabled = on;
      submitBtn.classList.toggle("opacity-50", on);
    }
  }

  function renderState(state) {
    currentState = state;
    clearError();

    switch (state.name) {
      case "login_init":
      case "login_identifier":
        showForm();
        hidePasswordField();
        emailInput.focus();
        break;

      case "login_password":
        showForm();
        showPasswordField();
        break;

      case "onboarding_email":
        showForm();
        if (!allowPublicRegistration) {
          showError(
            "Registration is not available. Contact your administrator."
          );
        }
        break;

      case "success":
        window.location.href = "/sso/complete";
        return;

      case "error":
        showForm();
        showError(
          state.error_message ||
            (state.payload && state.payload.error) ||
            "Authentication error"
        );
        break;

      default:
        showForm();
        console.log("[auth-flow] unhandled state:", state.name, state);
        break;
    }
  }

  hanko.onSessionCreated(function () {
    window.location.href = "/sso/complete";
  });

  formEl.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!currentState) return;

    clearError();
    setLoading(true);

    processSubmit(currentState)
      .then(function (next) {
        if (next) renderState(next);
      })
      .catch(function (err) {
        showError(err.message || "An error occurred");
      })
      .finally(function () {
        setLoading(false);
      });
  });

  function processSubmit(state) {
    var a = state.actions;

    if (a.continue_with_login_identifier && a.continue_with_login_identifier.enabled) {
      return a.continue_with_login_identifier.run({
        identifier: emailInput.value,
      });
    }

    if (a.password_login && a.password_login.enabled) {
      return a.password_login.run({ password: passwordInput.value });
    }

    if (a.continue_to_password_login && a.continue_to_password_login.enabled) {
      return a.continue_to_password_login.run();
    }

    return Promise.reject(new Error("Unexpected state: " + state.name));
  }

  (function init() {
    hanko
      .createState("login")
      .then(function (state) {
        renderState(state);
      })
      .catch(function (err) {
        showForm();
        showError("Failed to initialize: " + err.message);
      });
  })();
})();
