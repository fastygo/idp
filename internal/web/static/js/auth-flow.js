/**
 * auth-flow.js — Custom login state machine using hanko-frontend-sdk.
 * Reads config from <script id="auth-config"> and drives the login form
 * rendered by login.templ with UI8Kit CSS classes.
 */
(function () {
  "use strict";

  const configEl = document.getElementById("auth-config");
  if (!configEl) return;

  const config = JSON.parse(configEl.textContent);
  const { hankoApiUrl, allowPublicRegistration } = config;

  if (!hankoApiUrl || !window.Hanko) return;

  const loadingEl = document.getElementById("auth-loading");
  const formEl = document.getElementById("auth-login-form");
  const emailInput = document.getElementById("auth-email");
  const passwordWrap = document.getElementById("auth-password-wrap");
  const passwordInput = document.getElementById("auth-password");
  const errorEl = document.getElementById("auth-error");
  const submitBtn = document.getElementById("auth-submit");

  if (!formEl || !emailInput) return;

  const hanko = new window.Hanko({ apiUrl: hankoApiUrl });

  let currentState = null;

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

  function setLoading(loading) {
    if (submitBtn) {
      submitBtn.disabled = loading;
      submitBtn.classList.toggle("opacity-50", loading);
    }
  }

  async function handleState(state) {
    currentState = state;
    clearError();

    switch (state.name) {
      case "preflight":
        if (state.actions.continue_to_login_init) {
          const next = await state.actions.continue_to_login_init.run();
          handleState(next);
        } else if (state.actions.continue_with_login_identifier) {
          showForm();
          hidePasswordField();
        } else {
          showForm();
        }
        break;

      case "login_init":
        showForm();
        hidePasswordField();
        emailInput.focus();
        break;

      case "login_identifier":
        showForm();
        hidePasswordField();
        emailInput.focus();
        break;

      case "login_method_chooser":
        if (state.actions.continue_to_password_login) {
          const next = await state.actions.continue_to_password_login.run();
          handleState(next);
        } else {
          showForm();
          showPasswordField();
        }
        break;

      case "login_password":
        showForm();
        showPasswordField();
        break;

      case "onboarding_email":
        if (!allowPublicRegistration) {
          showError("Registration is not available. Contact your administrator.");
          showForm();
          return;
        }
        showForm();
        break;

      case "passcode_confirmation":
        showForm();
        break;

      case "success":
        window.location.href = "/sso/complete";
        return;

      case "error":
        showForm();
        showError(state.error_message || state.payload?.error || "Authentication error");
        break;

      default:
        showForm();
        break;
    }
  }

  hanko.onSessionCreated(function () {
    window.location.href = "/sso/complete";
  });

  hanko.onAfterStateChange(function (detail) {
    if (detail && detail.state) {
      handleState(detail.state);
    }
  });

  formEl.addEventListener("submit", async function (e) {
    e.preventDefault();
    clearError();
    setLoading(true);

    try {
      if (!currentState) {
        const state = await hanko.createState("login");
        await processSubmit(state);
        return;
      }

      await processSubmit(currentState);
    } catch (err) {
      showError(err.message || "An error occurred");
    } finally {
      setLoading(false);
    }
  });

  async function processSubmit(state) {
    if (state.actions.continue_with_login_identifier) {
      const next = await state.actions.continue_with_login_identifier.run({
        username: emailInput.value,
      });
      handleState(next);
    } else if (state.actions.password_login) {
      const next = await state.actions.password_login.run({
        password: passwordInput.value,
      });
      handleState(next);
    } else if (state.actions.continue_to_password_login) {
      const next = await state.actions.continue_to_password_login.run();
      handleState(next);
    } else {
      showError("Unexpected state: " + state.name);
    }
  }

  // Initialize
  (async function init() {
    try {
      const state = await hanko.createState("login");
      handleState(state);
    } catch (err) {
      showForm();
      showError("Failed to initialize: " + err.message);
    }
  })();
})();
