(() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __moduleCache = /* @__PURE__ */ new WeakMap;
  var __toCommonJS = (from) => {
    var entry = __moduleCache.get(from), desc;
    if (entry)
      return entry;
    entry = __defProp({}, "__esModule", { value: true });
    if (from && typeof from === "object" || typeof from === "function")
      __getOwnPropNames(from).map((key) => !__hasOwnProp.call(entry, key) && __defProp(entry, key, {
        get: () => from[key],
        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
      }));
    __moduleCache.set(from, entry);
    return entry;
  };
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, {
        get: all[name],
        enumerable: true,
        configurable: true,
        set: (newValue) => all[name] = () => newValue
      });
  };

  // src/umd.ts
  var exports_umd = {};
  __export(exports_umd, {
    HankoProvider: () => HankoProvider,
    AuthFlow: () => AuthFlow,
    AuthDOMController: () => AuthDOMController
  });

  // src/core/dom.ts
  var defaultOptions = {
    loadingId: "auth-loading",
    formId: "auth-login-form",
    emailId: "auth-email",
    passwordWrapId: "auth-password-wrap",
    passwordId: "auth-password",
    errorId: "auth-error",
    submitId: "auth-submit"
  };

  class AuthDOMController {
    flow;
    config;
    options;
    boundSubmit = null;
    constructor(flow, options = {}) {
      this.flow = flow;
      this.config = flow.getConfig();
      this.options = { ...defaultOptions, ...options };
    }
    async mount() {
      const form = this.getForm();
      const emailInput = this.getEmailInput();
      if (!form || !emailInput) {
        return;
      }
      this.boundSubmit = (event) => {
        event.preventDefault();
        this.handleSubmit();
      };
      form.addEventListener("submit", this.boundSubmit);
      this.flow.onSessionCreated(() => {
        window.location.href = this.config.successRedirect ?? "/sso/complete";
      });
      try {
        const state = await this.flow.start("login");
        this.renderState(state);
      } catch (error) {
        this.showForm();
        this.showError(this.getErrorMessage(error, "Failed to initialize"));
      }
    }
    destroy() {
      const form = this.getForm();
      if (form && this.boundSubmit) {
        form.removeEventListener("submit", this.boundSubmit);
      }
      this.boundSubmit = null;
    }
    renderState(state) {
      this.clearError();
      switch (state.name) {
        case "login_init":
        case "login_identifier":
          this.renderIdentifierState(state);
          break;
        case "login_method_chooser":
          this.showForm();
          this.hidePasswordField();
          this.renderInlineError(state);
          break;
        case "login_password":
          this.showForm();
          this.showPasswordField();
          this.renderInlineError(state);
          break;
        case "onboarding_email":
          this.showForm();
          if (!this.config.features?.allowPublicRegistration) {
            this.showError("Registration is not available. Contact your administrator.");
          } else {
            this.renderInlineError(state);
          }
          break;
        case "success":
          window.location.href = this.config.successRedirect ?? "/sso/complete";
          break;
        case "error":
          this.showForm();
          this.showError(state.error_message ?? (typeof state.payload?.error === "string" ? state.payload.error : "Authentication error"));
          break;
        default:
          this.showForm();
          break;
      }
    }
    static readConfig(scriptId = "auth-config") {
      const configEl = document.getElementById(scriptId);
      if (!configEl?.textContent) {
        return null;
      }
      return JSON.parse(configEl.textContent);
    }
    async handleSubmit() {
      const emailInput = this.getEmailInput();
      const passwordInput = this.getPasswordInput();
      const state = this.flow.getState();
      if (!state || !emailInput) {
        return;
      }
      this.clearError();
      this.setLoading(true);
      try {
        let next;
        if (state.actions.password_login?.enabled) {
          next = await this.flow.submitPassword(passwordInput?.value ?? "");
        } else if (state.actions.continue_with_login_identifier?.enabled) {
          next = await this.flow.submitIdentifier(emailInput.value);
        } else {
          next = await this.flow.submitCurrent();
        }
        this.renderState(next);
      } catch (error) {
        this.showError(this.getErrorMessage(error, "An error occurred"));
      } finally {
        this.setLoading(false);
      }
    }
    renderIdentifierState(state) {
      const emailInput = this.getEmailInput();
      const action = state.actions.continue_with_login_identifier;
      const input = action?.inputs?.email ?? action?.inputs?.username ?? action?.inputs?.identifier ?? null;
      this.showForm();
      this.hidePasswordField();
      if (emailInput && input) {
        emailInput.name = input.name || "identifier";
        emailInput.type = input.type === "string" ? "text" : input.type;
        emailInput.setAttribute("autocomplete", input.name === "username" ? "username webauthn" : "email username webauthn");
        emailInput.focus();
      }
      this.renderInlineError(state);
    }
    getForm() {
      return document.getElementById(this.options.formId);
    }
    getEmailInput() {
      return document.getElementById(this.options.emailId);
    }
    getPasswordWrap() {
      return document.getElementById(this.options.passwordWrapId);
    }
    getPasswordInput() {
      return document.getElementById(this.options.passwordId);
    }
    getErrorElement() {
      return document.getElementById(this.options.errorId);
    }
    getLoadingElement() {
      return document.getElementById(this.options.loadingId);
    }
    getSubmitButton() {
      return document.getElementById(this.options.submitId);
    }
    showForm() {
      this.getLoadingElement()?.classList.add("hidden");
      this.getForm()?.classList.remove("hidden");
    }
    showPasswordField() {
      this.getPasswordWrap()?.classList.remove("hidden");
      this.getPasswordInput()?.focus();
    }
    hidePasswordField() {
      this.getPasswordWrap()?.classList.add("hidden");
    }
    showError(message) {
      const errorEl = this.getErrorElement();
      if (!errorEl) {
        return;
      }
      errorEl.textContent = message;
      errorEl.classList.remove("hidden");
    }
    renderInlineError(state) {
      const message = state.error_message ?? state.error?.message ?? (typeof state.payload?.error === "string" ? state.payload.error : "");
      if (message) {
        this.showError(message);
      }
    }
    clearError() {
      const errorEl = this.getErrorElement();
      if (!errorEl) {
        return;
      }
      errorEl.textContent = "";
      errorEl.classList.add("hidden");
    }
    setLoading(enabled) {
      const button = this.getSubmitButton();
      if (!button) {
        return;
      }
      button.disabled = enabled;
      button.classList.toggle("opacity-50", enabled);
    }
    getErrorMessage(error, fallback) {
      if (error instanceof Error && error.message) {
        return `${fallback}: ${error.message}`;
      }
      return fallback;
    }
  }

  // src/core/flow.ts
  function getLoginIdentifierAction(state) {
    if (!state) {
      return null;
    }
    return state.actions.continue_with_login_identifier ?? null;
  }
  function getLoginIdentifierInput(action) {
    if (!action?.inputs) {
      return null;
    }
    return action.inputs.email ?? action.inputs.username ?? action.inputs.identifier ?? null;
  }

  class AuthFlow {
    provider;
    config;
    currentState = null;
    constructor(provider, config) {
      this.provider = provider;
      this.config = config;
    }
    async start(flow = "login") {
      const state = await this.provider.init(flow);
      return this.setState(await this.advanceState(state));
    }
    getConfig() {
      return this.config;
    }
    onSessionCreated(cb) {
      this.provider.onSessionCreated(cb);
    }
    getState() {
      return this.currentState;
    }
    async submitIdentifier(value) {
      const action = getLoginIdentifierAction(this.currentState);
      const input = getLoginIdentifierInput(action);
      if (!action?.enabled || !input) {
        throw new Error(`Identifier submission is unavailable in state: ${this.currentState?.name ?? "none"}`);
      }
      const next = await action.run({ [input.name]: value });
      return this.setState(await this.advanceState(next));
    }
    async submitPassword(value) {
      const state = this.requireState();
      const action = state.actions.password_login;
      if (!action?.enabled) {
        throw new Error(`Password submission is unavailable in state: ${state.name}`);
      }
      const next = await action.run({ password: value });
      return this.setState(next);
    }
    async continuePasswordLogin() {
      const state = this.requireState();
      const action = state.actions.continue_to_password_login;
      if (!action?.enabled) {
        throw new Error(`Password continuation is unavailable in state: ${state.name}`);
      }
      const next = await action.run();
      return this.setState(next);
    }
    async submitCurrent(data) {
      const state = this.requireState();
      const action = this.resolveSubmitAction(state);
      if (!action) {
        throw new Error(`Unexpected state: ${state.name}`);
      }
      const next = await action.run(data);
      return this.setState(await this.advanceState(next));
    }
    async advanceState(state) {
      if (state.name === "login_method_chooser" && state.actions.continue_to_password_login?.enabled) {
        return state.actions.continue_to_password_login.run();
      }
      return state;
    }
    resolveSubmitAction(state) {
      const identifierAction = getLoginIdentifierAction(state);
      const identifierInput = getLoginIdentifierInput(identifierAction);
      if (identifierAction?.enabled && identifierInput) {
        return identifierAction;
      }
      if (state.actions.password_login?.enabled) {
        return state.actions.password_login;
      }
      if (state.actions.continue_to_password_login?.enabled) {
        return state.actions.continue_to_password_login;
      }
      return null;
    }
    requireState() {
      if (!this.currentState) {
        throw new Error("Auth flow has not started");
      }
      return this.currentState;
    }
    setState(state) {
      this.currentState = this.normalizeState(state);
      return this.currentState;
    }
    normalizeState(state) {
      const message = this.resolveStateErrorMessage(state);
      if (!message || state.error_message === message) {
        return state;
      }
      return {
        ...state,
        error_message: message
      };
    }
    resolveStateErrorMessage(state) {
      if (state.error?.message) {
        return state.error.message;
      }
      const inputError = this.findInputError(state);
      if (inputError?.message) {
        return inputError.message;
      }
      if (typeof state.payload?.error === "string") {
        return state.payload.error;
      }
      return state.error_message;
    }
    findInputError(state) {
      for (const action of Object.values(state.actions)) {
        if (!action?.inputs) {
          continue;
        }
        for (const input of Object.values(action.inputs)) {
          if (input?.error) {
            return input.error;
          }
        }
      }
      return;
    }
  }

  // node_modules/@teamhanko/hanko-frontend-sdk/dist/sdk.modern.js
  function e() {
    return e = Object.assign ? Object.assign.bind() : function(e2) {
      for (var t = 1;t < arguments.length; t++) {
        var s = arguments[t];
        for (var i in s)
          ({}).hasOwnProperty.call(s, i) && (e2[i] = s[i]);
      }
      return e2;
    }, e.apply(null, arguments);
  }

  class t {
    static throttle(e2, t2, s = {}) {
      const { leading: i = true, trailing: n = true } = s;
      let o, a, r, c = 0;
      const h = () => {
        c = i === false ? 0 : Date.now(), r = null, e2.apply(o, a);
      };
      return function(...s2) {
        const l = Date.now();
        c || i !== false || (c = l);
        const d = t2 - (l - c);
        o = this, a = s2, d <= 0 || d > t2 ? (r && (window.clearTimeout(r), r = null), c = l, e2.apply(o, a)) : r || n === false || (r = window.setTimeout(h, d));
      };
    }
  }
  var s = "hanko-session-created";
  var i = "hanko-session-expired";
  var n = "hanko-user-logged-out";
  var o = "hanko-user-deleted";
  var a = "hanko-after-state-change";
  var r = "hanko-before-state-change";

  class c extends CustomEvent {
    constructor(e2, t2) {
      super(e2, { detail: t2 });
    }
  }

  class h {
    constructor() {
      this.throttleLimit = 1000, this._addEventListener = document.addEventListener.bind(document), this._removeEventListener = document.removeEventListener.bind(document), this._throttle = t.throttle;
    }
    wrapCallback(e2, t2) {
      const s2 = (t3) => {
        e2(t3.detail);
      };
      return t2 ? this._throttle(s2, this.throttleLimit, { leading: true, trailing: false }) : s2;
    }
    addEventListenerWithType({ type: e2, callback: t2, once: s2 = false, throttle: i2 = false }) {
      const n2 = this.wrapCallback(t2, i2);
      return this._addEventListener(e2, n2, { once: s2 }), () => this._removeEventListener(e2, n2);
    }
    static mapAddEventListenerParams(e2, { once: t2, callback: s2 }, i2) {
      return { type: e2, callback: s2, once: t2, throttle: i2 };
    }
    addEventListener(e2, t2, s2) {
      return this.addEventListenerWithType(h.mapAddEventListenerParams(e2, t2, s2));
    }
    onSessionCreated(e2, t2) {
      return this.addEventListener(s, { callback: e2, once: t2 }, true);
    }
    onSessionExpired(e2, t2) {
      return this.addEventListener(i, { callback: e2, once: t2 }, true);
    }
    onUserLoggedOut(e2, t2) {
      return this.addEventListener(n, { callback: e2, once: t2 });
    }
    onUserDeleted(e2, t2) {
      return this.addEventListener(o, { callback: e2, once: t2 });
    }
    onAfterStateChange(e2, t2) {
      return this.addEventListener(a, { callback: e2, once: t2 }, false);
    }
    onBeforeStateChange(e2, t2) {
      return this.addEventListener(r, { callback: e2, once: t2 }, false);
    }
  }

  class l {
    constructor() {
      this._dispatchEvent = document.dispatchEvent.bind(document);
    }
    dispatch(e2, t2) {
      this._dispatchEvent(new c(e2, t2));
    }
    dispatchSessionCreatedEvent(e2) {
      this.dispatch(s, e2);
    }
    dispatchSessionExpiredEvent() {
      this.dispatch(i, null);
    }
    dispatchUserLoggedOutEvent() {
      this.dispatch(n, null);
    }
    dispatchUserDeletedEvent() {
      this.dispatch(o, null);
    }
    dispatchAfterStateChangeEvent(e2) {
      this.dispatch(a, e2);
    }
    dispatchBeforeStateChangeEvent(e2) {
      this.dispatch(r, e2);
    }
  }

  class d extends Error {
    constructor(e2, t2, s2) {
      super(e2), this.code = undefined, this.cause = undefined, this.code = t2, this.cause = s2, Object.setPrototypeOf(this, d.prototype);
    }
  }

  class u extends d {
    constructor(e2) {
      super("Technical error", "somethingWentWrong", e2), Object.setPrototypeOf(this, u.prototype);
    }
  }
  class v extends d {
    constructor(e2) {
      super("Request timed out error", "requestTimeout", e2), Object.setPrototypeOf(this, v.prototype);
    }
  }
  class b extends d {
    constructor(e2) {
      super("Unauthorized error", "unauthorized", e2), Object.setPrototypeOf(this, b.prototype);
    }
  }
  function L(e2) {
    for (var t2 = 1;t2 < arguments.length; t2++) {
      var s2 = arguments[t2];
      for (var i2 in s2)
        e2[i2] = s2[i2];
    }
    return e2;
  }
  var O = function e2(t2, s2) {
    function i2(e3, i3, n2) {
      if (typeof document != "undefined") {
        typeof (n2 = L({}, s2, n2)).expires == "number" && (n2.expires = new Date(Date.now() + 86400000 * n2.expires)), n2.expires && (n2.expires = n2.expires.toUTCString()), e3 = encodeURIComponent(e3).replace(/%(2[346B]|5E|60|7C)/g, decodeURIComponent).replace(/[()]/g, escape);
        var o2 = "";
        for (var a2 in n2)
          n2[a2] && (o2 += "; " + a2, n2[a2] !== true && (o2 += "=" + n2[a2].split(";")[0]));
        return document.cookie = e3 + "=" + t2.write(i3, e3) + o2;
      }
    }
    return Object.create({ set: i2, get: function(e3) {
      if (typeof document != "undefined" && (!arguments.length || e3)) {
        for (var s3 = document.cookie ? document.cookie.split("; ") : [], i3 = {}, n2 = 0;n2 < s3.length; n2++) {
          var o2 = s3[n2].split("="), a2 = o2.slice(1).join("=");
          try {
            var r2 = decodeURIComponent(o2[0]);
            if (i3[r2] = t2.read(a2, r2), e3 === r2)
              break;
          } catch (e4) {}
        }
        return e3 ? i3[e3] : i3;
      }
    }, remove: function(e3, t3) {
      i2(e3, "", L({}, t3, { expires: -1 }));
    }, withAttributes: function(t3) {
      return e2(this.converter, L({}, this.attributes, t3));
    }, withConverter: function(t3) {
      return e2(L({}, this.converter, t3), this.attributes);
    } }, { attributes: { value: Object.freeze(s2) }, converter: { value: Object.freeze(t2) } });
  }({ read: function(e3) {
    return e3[0] === '"' && (e3 = e3.slice(1, -1)), e3.replace(/(%[\dA-F]{2})+/gi, decodeURIComponent);
  }, write: function(e3) {
    return encodeURIComponent(e3).replace(/%(2[346BF]|3[AC-F]|40|5[BDE]|60|7[BCD])/g, decodeURIComponent);
  } }, { path: "/" });

  class T {
    constructor(e3) {
      var t2, s2;
      this.authCookieName = undefined, this.authCookieDomain = undefined, this.authCookieSameSite = undefined, this.authCookieName = (t2 = e3.cookieName) != null ? t2 : "hanko", this.authCookieDomain = e3.cookieDomain, this.authCookieSameSite = (s2 = e3.cookieSameSite) != null ? s2 : "lax";
    }
    getAuthCookie() {
      return O.get(this.authCookieName);
    }
    setAuthCookie(t2, s2) {
      const i2 = { secure: true, sameSite: this.authCookieSameSite };
      this.authCookieDomain !== undefined && (i2.domain = this.authCookieDomain);
      const n2 = e({}, i2, s2);
      if ((n2.sameSite === "none" || n2.sameSite === "None") && n2.secure === false)
        throw new u(new Error("Secure attribute must be set when SameSite=None"));
      O.set(this.authCookieName, t2, n2);
    }
    removeAuthCookie() {
      O.remove(this.authCookieName);
    }
  }

  class N {
    constructor(e3) {
      this.keyName = undefined, this.keyName = e3.keyName;
    }
    getSessionToken() {
      return sessionStorage.getItem(this.keyName);
    }
    setSessionToken(e3) {
      sessionStorage.setItem(this.keyName, e3);
    }
    removeSessionToken() {
      sessionStorage.removeItem(this.keyName);
    }
  }

  class P {
    constructor(e3) {
      this._xhr = undefined, this._xhr = e3;
    }
    getResponseHeader(e3) {
      return this._xhr.getResponseHeader(e3);
    }
  }

  class D {
    constructor(e3) {
      this.headers = undefined, this.ok = undefined, this.status = undefined, this.statusText = undefined, this.url = undefined, this._decodedJSON = undefined, this.xhr = undefined, this.headers = new P(e3), this.ok = e3.status >= 200 && e3.status <= 299, this.status = e3.status, this.statusText = e3.statusText, this.url = e3.responseURL, this.xhr = e3;
    }
    json() {
      return this._decodedJSON || (this._decodedJSON = JSON.parse(this.xhr.response)), this._decodedJSON;
    }
    parseNumericHeader(e3) {
      const t2 = parseInt(this.headers.getResponseHeader(e3), 10);
      return isNaN(t2) ? 0 : t2;
    }
  }

  class R {
    constructor(t2, s2) {
      var i2;
      this.timeout = undefined, this.api = undefined, this.dispatcher = undefined, this.cookie = undefined, this.sessionTokenStorage = undefined, this.lang = undefined, this.sessionTokenLocation = undefined, this.api = t2, this.timeout = (i2 = s2.timeout) != null ? i2 : 13000, this.dispatcher = new l, this.cookie = new T(e({}, s2)), this.sessionTokenStorage = new N({ keyName: s2.cookieName }), this.lang = s2.lang, this.sessionTokenLocation = s2.sessionTokenLocation;
    }
    _fetch(e3, t2, s2 = new XMLHttpRequest) {
      const i2 = this, n2 = this.api + e3, o2 = this.timeout, a2 = this.getAuthToken(), r2 = this.lang;
      return new Promise(function(e4, c2) {
        s2.open(t2.method, n2, true), s2.setRequestHeader("Accept", "application/json"), s2.setRequestHeader("Content-Type", "application/json"), s2.setRequestHeader("X-Language", r2), a2 && s2.setRequestHeader("Authorization", `Bearer ${a2}`), s2.timeout = o2, s2.withCredentials = true, s2.onload = () => {
          i2.processHeaders(s2), e4(new D(s2));
        }, s2.onerror = () => {
          c2(new u);
        }, s2.ontimeout = () => {
          c2(new v);
        }, s2.send(t2.body ? t2.body.toString() : null);
      });
    }
    processHeaders(e3) {
      let t2 = "", s2 = 0, i2 = "";
      if (e3.getAllResponseHeaders().split(`\r
`).forEach((n2) => {
        const o2 = n2.toLowerCase();
        o2.startsWith("x-auth-token") ? t2 = e3.getResponseHeader("X-Auth-Token") : o2.startsWith("x-session-lifetime") ? s2 = parseInt(e3.getResponseHeader("X-Session-Lifetime"), 10) : o2.startsWith("x-session-retention") && (i2 = e3.getResponseHeader("X-Session-Retention"));
      }), t2) {
        const e4 = new RegExp("^https://"), n2 = !!this.api.match(e4) && !!window.location.href.match(e4), o2 = i2 === "session" ? undefined : new Date(new Date().getTime() + 1000 * s2);
        this.setAuthToken(t2, { secure: n2, expires: o2 });
      }
    }
    get(e3) {
      return this._fetch(e3, { method: "GET" });
    }
    post(e3, t2) {
      return this._fetch(e3, { method: "POST", body: JSON.stringify(t2) });
    }
    put(e3, t2) {
      return this._fetch(e3, { method: "PUT", body: JSON.stringify(t2) });
    }
    patch(e3, t2) {
      return this._fetch(e3, { method: "PATCH", body: JSON.stringify(t2) });
    }
    delete(e3) {
      return this._fetch(e3, { method: "DELETE" });
    }
    getAuthToken() {
      let e3 = "";
      switch (this.sessionTokenLocation) {
        case "cookie":
        default:
          e3 = this.cookie.getAuthCookie();
          break;
        case "sessionStorage":
          e3 = this.sessionTokenStorage.getSessionToken();
      }
      return e3;
    }
    setAuthToken(e3, t2) {
      switch (this.sessionTokenLocation) {
        case "cookie":
        default:
          return this.cookie.setAuthCookie(e3, t2);
        case "sessionStorage":
          return this.sessionTokenStorage.setSessionToken(e3);
      }
    }
  }

  class j {
    constructor(e3, t2) {
      this.client = undefined, this.client = new R(e3, t2);
    }
  }

  class K extends j {
    async validate() {
      const e3 = await this.client.get("/sessions/validate");
      if (!e3.ok)
        throw new u;
      return await e3.json();
    }
  }

  class U {
    constructor(e3) {
      this.storageKey = undefined, this.defaultState = { expiration: 0, lastCheck: 0 }, this.storageKey = e3;
    }
    load() {
      const e3 = window.localStorage.getItem(this.storageKey);
      return e3 == null ? this.defaultState : JSON.parse(e3);
    }
    save(e3) {
      window.localStorage.setItem(this.storageKey, JSON.stringify(e3 || this.defaultState));
    }
  }

  class q {
    constructor(e3, t2) {
      this.onActivityCallback = undefined, this.onInactivityCallback = undefined, this.handleFocus = () => {
        this.onActivityCallback();
      }, this.handleBlur = () => {
        this.onInactivityCallback();
      }, this.handleVisibilityChange = () => {
        document.visibilityState === "visible" ? this.onActivityCallback() : this.onInactivityCallback();
      }, this.hasFocus = () => document.hasFocus(), this.onActivityCallback = e3, this.onInactivityCallback = t2, window.addEventListener("focus", this.handleFocus), window.addEventListener("blur", this.handleBlur), document.addEventListener("visibilitychange", this.handleVisibilityChange);
    }
  }

  class F {
    constructor(e3, t2, s2) {
      this.intervalID = null, this.timeoutID = null, this.checkInterval = undefined, this.checkSession = undefined, this.onSessionExpired = undefined, this.checkInterval = e3, this.checkSession = t2, this.onSessionExpired = s2;
    }
    scheduleSessionExpiry(e3) {
      var t2 = this;
      this.stop(), this.timeoutID = setTimeout(async function() {
        t2.stop(), t2.onSessionExpired();
      }, e3);
    }
    start(e3 = 0, t2 = 0) {
      var s2 = this;
      const i2 = this.calcTimeToNextCheck(e3);
      this.sessionExpiresSoon(t2) ? this.scheduleSessionExpiry(i2) : this.timeoutID = setTimeout(async function() {
        try {
          let e4 = await s2.checkSession();
          if (e4.is_valid) {
            if (s2.sessionExpiresSoon(e4.expiration))
              return void s2.scheduleSessionExpiry(e4.expiration - Date.now());
            s2.intervalID = setInterval(async function() {
              e4 = await s2.checkSession(), e4.is_valid ? s2.sessionExpiresSoon(e4.expiration) && s2.scheduleSessionExpiry(e4.expiration - Date.now()) : s2.stop();
            }, s2.checkInterval);
          } else
            s2.stop();
        } catch (e4) {
          console.log(e4);
        }
      }, i2);
    }
    stop() {
      this.timeoutID && (clearTimeout(this.timeoutID), this.timeoutID = null), this.intervalID && (clearInterval(this.intervalID), this.intervalID = null);
    }
    isRunning() {
      return this.timeoutID !== null || this.intervalID !== null;
    }
    sessionExpiresSoon(e3) {
      return e3 > 0 && e3 - Date.now() <= this.checkInterval;
    }
    calcTimeToNextCheck(e3) {
      const t2 = Date.now() - e3;
      return this.checkInterval >= t2 ? this.checkInterval - t2 % this.checkInterval : 0;
    }
  }

  class M {
    constructor(e3 = "hanko_session", t2, s2, i2) {
      this.channel = undefined, this.onSessionExpired = undefined, this.onSessionCreated = undefined, this.onLeadershipRequested = undefined, this.handleMessage = (e4) => {
        const t3 = e4.data;
        switch (t3.action) {
          case "sessionExpired":
            this.onSessionExpired(t3);
            break;
          case "sessionCreated":
            this.onSessionCreated(t3);
            break;
          case "requestLeadership":
            this.onLeadershipRequested(t3);
        }
      }, this.onSessionExpired = t2, this.onSessionCreated = s2, this.onLeadershipRequested = i2, this.channel = new BroadcastChannel(e3), this.channel.onmessage = this.handleMessage;
    }
    post(e3) {
      this.channel.postMessage(e3);
    }
  }

  class H extends l {
    constructor(e3, t2) {
      super(), this.listener = new h, this.checkInterval = 30000, this.client = undefined, this.sessionState = undefined, this.windowActivityManager = undefined, this.scheduler = undefined, this.sessionChannel = undefined, this.isLoggedIn = undefined, this.client = new K(e3, t2), t2.sessionCheckInterval && (this.checkInterval = t2.sessionCheckInterval < 3000 ? 3000 : t2.sessionCheckInterval), this.sessionState = new U(`${t2.cookieName}_session_state`), this.sessionChannel = new M(this.getSessionCheckChannelName(t2.sessionTokenLocation, t2.sessionCheckChannelName), () => this.onChannelSessionExpired(), (e4) => this.onChannelSessionCreated(e4), () => this.onChannelLeadershipRequested()), this.scheduler = new F(this.checkInterval, () => this.checkSession(), () => this.onSessionExpired()), this.windowActivityManager = new q(() => this.startSessionCheck(), () => this.scheduler.stop());
      const s2 = Date.now(), { expiration: i2 } = this.sessionState.load();
      this.isLoggedIn = s2 < i2, this.initializeEventListeners(), this.startSessionCheck();
    }
    initializeEventListeners() {
      this.listener.onSessionCreated((e3) => {
        const { claims: t2 } = e3, s2 = Date.parse(t2.expiration), i2 = Date.now();
        this.isLoggedIn = true, this.sessionState.save({ expiration: s2, lastCheck: i2 }), this.sessionChannel.post({ action: "sessionCreated", claims: t2 }), this.startSessionCheck();
      }), this.listener.onUserLoggedOut(() => {
        this.isLoggedIn = false, this.sessionChannel.post({ action: "sessionExpired" }), this.sessionState.save(null), this.scheduler.stop();
      }), window.addEventListener("beforeunload", () => this.scheduler.stop());
    }
    startSessionCheck() {
      if (!this.windowActivityManager.hasFocus())
        return;
      if (this.sessionChannel.post({ action: "requestLeadership" }), this.scheduler.isRunning())
        return;
      const { lastCheck: e3, expiration: t2 } = this.sessionState.load();
      this.isLoggedIn && this.scheduler.start(e3, t2);
    }
    async checkSession() {
      const e3 = Date.now(), { is_valid: t2, claims: s2, expiration_time: i2 } = await this.client.validate(), n2 = i2 ? Date.parse(i2) : 0;
      return !t2 && this.isLoggedIn && this.dispatchSessionExpiredEvent(), t2 ? (this.isLoggedIn = true, this.sessionState.save({ lastCheck: e3, expiration: n2 })) : (this.isLoggedIn = false, this.sessionState.save(null), this.sessionChannel.post({ action: "sessionExpired" })), { is_valid: t2, claims: s2, expiration: n2 };
    }
    onSessionExpired() {
      this.isLoggedIn && (this.isLoggedIn = false, this.sessionState.save(null), this.sessionChannel.post({ action: "sessionExpired" }), this.dispatchSessionExpiredEvent());
    }
    onChannelSessionExpired() {
      this.isLoggedIn && (this.isLoggedIn = false, this.dispatchSessionExpiredEvent());
    }
    onChannelSessionCreated(e3) {
      const { claims: t2 } = e3, s2 = Date.now(), i2 = Date.parse(t2.expiration) - s2;
      this.isLoggedIn = true, this.dispatchSessionCreatedEvent({ claims: t2, expirationSeconds: i2 });
    }
    onChannelLeadershipRequested() {
      this.windowActivityManager.hasFocus() || this.scheduler.stop();
    }
    getSessionCheckChannelName(e3, t2) {
      if (e3 !== "sessionStorage")
        return t2;
      let s2 = sessionStorage.getItem("sessionCheckChannelName");
      return s2 != null && s2 !== "" || (s2 = `${t2}-${Math.floor(100 * Math.random()) + 1}`, sessionStorage.setItem("sessionCheckChannelName", s2)), s2;
    }
  }

  class W {
    static supported() {
      return !!(navigator.credentials && navigator.credentials.create && navigator.credentials.get && window.PublicKeyCredential);
    }
    static async isPlatformAuthenticatorAvailable() {
      return !(!this.supported() || !window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) && window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }
    static async isSecurityKeySupported() {
      return window.PublicKeyCredential !== undefined && window.PublicKeyCredential.isExternalCTAP2SecurityKeySupported ? window.PublicKeyCredential.isExternalCTAP2SecurityKeySupported() : this.supported();
    }
    static async isConditionalMediationAvailable() {
      return !(!window.PublicKeyCredential || !window.PublicKeyCredential.isConditionalMediationAvailable) && window.PublicKeyCredential.isConditionalMediationAvailable();
    }
  }
  function z(e3) {
    const t2 = "==".slice(0, (4 - e3.length % 4) % 4), s2 = e3.replace(/-/g, "+").replace(/_/g, "/") + t2, i2 = atob(s2), n2 = new ArrayBuffer(i2.length), o2 = new Uint8Array(n2);
    for (let e4 = 0;e4 < i2.length; e4++)
      o2[e4] = i2.charCodeAt(e4);
    return n2;
  }
  function J(e3) {
    const t2 = new Uint8Array(e3);
    let s2 = "";
    for (const e4 of t2)
      s2 += String.fromCharCode(e4);
    return btoa(s2).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  var $ = "copy";
  var B = "convert";
  function V(e3, t2, s2) {
    if (t2 === $)
      return s2;
    if (t2 === B)
      return e3(s2);
    if (t2 instanceof Array)
      return s2.map((s3) => V(e3, t2[0], s3));
    if (t2 instanceof Object) {
      const i2 = {};
      for (const [n2, o2] of Object.entries(t2)) {
        if (o2.derive) {
          const e4 = o2.derive(s2);
          e4 !== undefined && (s2[n2] = e4);
        }
        if (n2 in s2)
          i2[n2] = s2[n2] != null ? V(e3, o2.schema, s2[n2]) : null;
        else if (o2.required)
          throw new Error(`Missing key: ${n2}`);
      }
      return i2;
    }
  }
  function X(e3, t2) {
    return { required: true, schema: e3, derive: t2 };
  }
  function G(e3) {
    return { required: true, schema: e3 };
  }
  function Q(e3) {
    return { required: false, schema: e3 };
  }
  var Y = { type: G($), id: G(B), transports: Q($) };
  var Z = { appid: Q($), appidExclude: Q($), credProps: Q($) };
  var ee = { appid: Q($), appidExclude: Q($), credProps: Q($) };
  var te = { publicKey: G({ rp: G($), user: G({ id: G(B), name: G($), displayName: G($) }), challenge: G(B), pubKeyCredParams: G($), timeout: Q($), excludeCredentials: Q([Y]), authenticatorSelection: Q($), attestation: Q($), extensions: Q(Z) }), signal: Q($) };
  var se = { type: G($), id: G($), rawId: G(B), authenticatorAttachment: Q($), response: G({ clientDataJSON: G(B), attestationObject: G(B), transports: X($, (e3) => {
    var t2;
    return ((t2 = e3.getTransports) == null ? undefined : t2.call(e3)) || [];
  }) }), clientExtensionResults: X(ee, (e3) => e3.getClientExtensionResults()) };
  var ie = { mediation: Q($), publicKey: G({ challenge: G(B), timeout: Q($), rpId: Q($), allowCredentials: Q([Y]), userVerification: Q($), extensions: Q(Z) }), signal: Q($) };
  var ne = { type: G($), id: G($), rawId: G(B), authenticatorAttachment: Q($), response: G({ clientDataJSON: G(B), authenticatorData: G(B), signature: G(B), userHandle: G(B) }), clientExtensionResults: X(ee, (e3) => e3.getClientExtensionResults()) };
  async function oe(e3) {
    const t2 = await navigator.credentials.get(function(e4) {
      return V(z, ie, e4);
    }(e3));
    return function(e4) {
      return V(J, ne, e4);
    }(t2);
  }

  class ae {
    constructor() {
      this.abortController = new AbortController;
    }
    static getInstance() {
      return ae.instance || (ae.instance = new ae), ae.instance;
    }
    createAbortSignal() {
      return this.abortController.abort(), this.abortController = new AbortController, this.abortController.signal;
    }
    async getWebauthnCredential(t2) {
      return await oe(e({}, t2, { signal: this.createAbortSignal() }));
    }
    async getConditionalWebauthnCredential(e3) {
      return await oe({ publicKey: e3, mediation: "conditional", signal: this.createAbortSignal() });
    }
    async createWebauthnCredential(t2) {
      return await async function(e3) {
        return t3 = await navigator.credentials.create(function(e4) {
          return V(z, te, e4);
        }(e3)), V(J, se, t3);
        var t3;
      }(e({}, t2, { signal: this.createAbortSignal() }));
    }
  }
  ae.instance = null;
  var re = "hanko_pkce_code_verifier";
  var le = () => typeof window != "undefined" && window.sessionStorage ? window.sessionStorage.getItem(re) : null;
  var de = () => {
    typeof window != "undefined" && window.sessionStorage && window.sessionStorage.removeItem(re);
  };
  async function ue(e3, t2, s2, i2 = "webauthn_credential_already_exists", n2 = "Webauthn credential already exists") {
    try {
      const i3 = await t2.createWebauthnCredential(s2);
      return await e3.actions.webauthn_verify_attestation_response.run({ public_key: i3 });
    } catch (t3) {
      const s3 = await e3.actions.back.run();
      return s3.error = { code: i2, message: n2 }, s3;
    }
  }
  var pe = { preflight: async (e3) => await e3.actions.register_client_capabilities.run({ webauthn_available: W.supported(), webauthn_conditional_mediation_available: await W.isConditionalMediationAvailable(), webauthn_platform_authenticator_available: await W.isPlatformAuthenticatorAvailable() }), login_passkey: async (e3) => {
    const t2 = ae.getInstance();
    try {
      const s2 = await t2.getWebauthnCredential(e3.payload.request_options);
      return await e3.actions.webauthn_verify_assertion_response.run({ assertion_response: s2 });
    } catch (t3) {
      const s2 = await e3.actions.back.run();
      return e3.error && (s2.error = e3.error), s2;
    }
  }, onboarding_verify_passkey_attestation: async (e3) => ue(e3, ae.getInstance(), e3.payload.creation_options), webauthn_credential_verification: async (e3) => ue(e3, ae.getInstance(), e3.payload.creation_options), async thirdparty(e3) {
    const t2 = new URLSearchParams(window.location.search), s2 = t2.get("hanko_token"), i2 = t2.get("error"), n2 = (e4) => {
      e4.forEach((e5) => t2.delete(e5));
      const s3 = t2.toString() ? `?${t2.toString()}` : "";
      history.replaceState(null, null, `${window.location.pathname}${s3}`);
    };
    if ((s2 == null ? undefined : s2.length) > 0) {
      n2(["hanko_token"]);
      const t3 = le();
      try {
        return await e3.actions.exchange_token.run({ token: s2, code_verifier: t3 || undefined });
      } finally {
        de();
      }
    }
    if ((i2 == null ? undefined : i2.length) > 0) {
      const s3 = i2 === "access_denied" ? "third_party_access_denied" : "technical_error", o2 = t2.get("error_description");
      n2(["error", "error_description"]);
      const a2 = await e3.actions.back.run(null, { dispatchAfterStateChangeEvent: false });
      return a2.error = { code: s3, message: o2 }, a2.dispatchAfterStateChangeEvent(), a2;
    }
    return e3.isCached ? await e3.actions.back.run() : (e3.saveToLocalStorage(), window.location.assign(e3.payload.redirect_url), e3);
  }, success: async (e3) => {
    const { claims: t2 } = e3.payload, s2 = Date.parse(t2.expiration) - Date.now();
    return e3.removeFromLocalStorage(), e3.hanko.relay.dispatchSessionCreatedEvent({ claims: t2, expirationSeconds: s2 }), e3;
  }, account_deleted: async (e3) => (e3.removeFromLocalStorage(), e3.hanko.relay.dispatchUserDeletedEvent(), e3) };
  var ve = { login_init: async (e3) => {
    (async function() {
      const t2 = ae.getInstance();
      if (e3.payload.request_options)
        try {
          const { publicKey: s2 } = e3.payload.request_options, i2 = await t2.getConditionalWebauthnCredential(s2);
          return await e3.actions.webauthn_verify_assertion_response.run({ assertion_response: i2 });
        } catch (e4) {
          return;
        }
    })();
  } };

  class ge {
    constructor(e3, t2, s2, i2 = {}) {
      if (this.name = undefined, this.flowName = undefined, this.error = undefined, this.payload = undefined, this.actions = undefined, this.csrfToken = undefined, this.status = undefined, this.previousAction = undefined, this.isCached = undefined, this.cacheKey = undefined, this.hanko = undefined, this.invokedAction = undefined, this.excludeAutoSteps = undefined, this.autoStep = undefined, this.passkeyAutofillActivation = undefined, this.flowName = t2, this.name = s2.name, this.error = s2.error, this.payload = s2.payload, this.csrfToken = s2.csrf_token, this.status = s2.status, this.hanko = e3, this.actions = this.buildActionMap(s2.actions), this.name in pe) {
        const e4 = pe[this.name];
        this.autoStep = () => e4(this);
      }
      if (this.name in ve) {
        const e4 = ve[this.name];
        this.passkeyAutofillActivation = () => e4(this);
      }
      const { dispatchAfterStateChangeEvent: n2 = true, excludeAutoSteps: o2 = null, previousAction: a2 = null, isCached: r2 = false, cacheKey: c2 = "hanko-flow-state" } = i2;
      this.excludeAutoSteps = o2, this.previousAction = a2, this.isCached = r2, this.cacheKey = c2, n2 && this.dispatchAfterStateChangeEvent();
    }
    buildActionMap(e3) {
      const t2 = {};
      return Object.keys(e3).forEach((s2) => {
        t2[s2] = new ye(e3[s2], this);
      }), new Proxy(t2, { get: (e4, t3) => {
        if (t3 in e4)
          return e4[t3];
        const s2 = typeof t3 == "string" ? t3 : t3.toString();
        return ye.createDisabled(s2, this);
      } });
    }
    dispatchAfterStateChangeEvent() {
      this.hanko.relay.dispatchAfterStateChangeEvent({ state: this });
    }
    serialize() {
      return { flow_name: this.flowName, name: this.name, error: this.error, payload: this.payload, csrf_token: this.csrfToken, status: this.status, previous_action: this.previousAction, actions: Object.fromEntries(Object.entries(this.actions).map(([e3, t2]) => [e3, { action: t2.name, href: t2.href, inputs: t2.inputs, description: null }])) };
    }
    saveToLocalStorage() {
      localStorage.setItem(this.cacheKey, JSON.stringify(e({}, this.serialize(), { is_cached: true })));
    }
    removeFromLocalStorage() {
      localStorage.removeItem(this.cacheKey);
    }
    static async initializeFlowState(e3, t2, s2, i2 = {}) {
      let n2 = new ge(e3, t2, s2, i2);
      if (n2.excludeAutoSteps != "all")
        for (;n2 && n2.autoStep && ((o2 = n2.excludeAutoSteps) == null || !o2.includes(n2.name)); ) {
          var o2;
          const e4 = await n2.autoStep();
          if (e4.name == n2.name)
            return e4;
          n2 = e4;
        }
      return n2;
    }
    static readFromLocalStorage(e3) {
      const t2 = localStorage.getItem(e3);
      if (t2)
        try {
          return JSON.parse(t2);
        } catch (e4) {
          return;
        }
    }
    static async create(t2, s2, i2 = {}) {
      const { cacheKey: n2 = "hanko-flow-state", loadFromCache: o2 = true } = i2;
      if (o2) {
        const s3 = ge.readFromLocalStorage(n2);
        if (s3)
          return ge.deserialize(t2, s3, e({}, i2, { cacheKey: n2 }));
      }
      const a2 = await ge.fetchState(t2, `/${s2}`);
      return ge.initializeFlowState(t2, s2, a2, e({}, i2, { cacheKey: n2 }));
    }
    static async deserialize(t2, s2, i2 = {}) {
      return ge.initializeFlowState(t2, s2.flow_name, s2, e({}, i2, { previousAction: s2.previous_action, isCached: s2.is_cached }));
    }
    static async fetchState(e3, t2, s2) {
      try {
        return (await e3.client.post(t2, s2)).json();
      } catch (e4) {
        return ge.createErrorResponse(e4);
      }
    }
    static createErrorResponse(e3) {
      return { actions: null, csrf_token: "", name: "error", payload: null, status: 0, error: e3 };
    }
  }

  class ye {
    constructor(e3, t2, s2 = true) {
      this.enabled = undefined, this.href = undefined, this.name = undefined, this.inputs = undefined, this.parentState = undefined, this.enabled = s2, this.href = e3.href, this.name = e3.action, this.inputs = e3.inputs, this.parentState = t2;
    }
    static createDisabled(e3, t2) {
      return new ye({ action: e3, href: "", inputs: {}, description: "Disabled action" }, t2, false);
    }
    async run(t2 = null, s2 = {}) {
      const { name: i2, hanko: n2, flowName: o2, csrfToken: a2, invokedAction: r2, excludeAutoSteps: c2, cacheKey: h2 } = this.parentState, { dispatchAfterStateChangeEvent: l2 = true } = s2;
      if (!this.enabled)
        throw new Error(`Action '${this.name}' is not enabled in state '${i2}'`);
      if (r2)
        throw new Error(`An action '${r2.name}' has already been invoked on state '${r2.relatedStateName}'. No further actions can be run.`);
      this.parentState.invokedAction = { name: this.name, relatedStateName: i2 }, n2.relay.dispatchBeforeStateChangeEvent({ state: this.parentState });
      const d2 = { input_data: e({}, Object.keys(this.inputs).reduce((e3, t3) => {
        const s3 = this.inputs[t3];
        return s3.value !== undefined && (e3[t3] = s3.value), e3;
      }, {}), t2), csrf_token: a2 }, u2 = await ge.fetchState(n2, this.href, d2);
      return this.parentState.removeFromLocalStorage(), ge.initializeFlowState(n2, o2, u2, { dispatchAfterStateChangeEvent: l2, excludeAutoSteps: c2, previousAction: r2, cacheKey: h2 });
    }
  }

  class me extends j {
    async getCurrent() {
      const e3 = await this.client.get("/me");
      if (e3.status === 401)
        throw this.client.dispatcher.dispatchSessionExpiredEvent(), new b;
      if (!e3.ok)
        throw new u;
      const t2 = e3.json(), s2 = await this.client.get(`/users/${t2.id}`);
      if (s2.status === 401)
        throw this.client.dispatcher.dispatchSessionExpiredEvent(), new b;
      if (!s2.ok)
        throw new u;
      return s2.json();
    }
    async getCurrentUser() {
      const e3 = await this.client.get("/me");
      if (e3.status === 401)
        throw this.client.dispatcher.dispatchSessionExpiredEvent(), new b;
      if (!e3.ok)
        throw new u;
      return e3.json();
    }
    async logout() {
      const e3 = await this.client.post("/logout");
      if (this.client.sessionTokenStorage.removeSessionToken(), this.client.cookie.removeAuthCookie(), this.client.dispatcher.dispatchUserLoggedOutEvent(), e3.status !== 401 && !e3.ok)
        throw new u;
    }
  }

  class fe extends h {
    constructor(t2, s2) {
      super(), this.session = undefined, this.user = undefined, this.cookie = undefined, this.client = undefined, this.relay = undefined;
      const i2 = e({ timeout: 13000, cookieName: "hanko", localStorageKey: "hanko", sessionCheckInterval: 30000, sessionCheckChannelName: "hanko-session-check" }, s2);
      this.client = new R(t2, i2), this.session = new K(t2, i2), this.user = new me(t2, i2), this.relay = new H(t2, i2), this.cookie = new T(i2);
    }
    setLang(e3) {
      this.client.lang = e3;
    }
    createState(e3, t2 = {}) {
      return ge.create(this, e3, t2);
    }
    async getUser() {
      return this.user.getCurrent();
    }
    async getCurrentUser() {
      return this.user.getCurrentUser();
    }
    async validateSession() {
      return this.session.validate();
    }
    getSessionToken() {
      return this.cookie.getAuthCookie();
    }
    async logout() {
      return this.user.logout();
    }
  }

  // src/providers/hanko.ts
  var Hanko = fe;

  class HankoProvider {
    apiUrl;
    hanko;
    constructor(apiUrl, locale) {
      this.apiUrl = apiUrl.replace(/\/$/, "");
      this.hanko = new Hanko(this.apiUrl, locale ? { lang: locale } : undefined);
      if (locale) {
        this.hanko.setLang?.(locale);
      }
    }
    async init(flow) {
      return this.hanko.createState(flow);
    }
    async logout() {
      await fetch(this.apiUrl + "/logout", {
        method: "POST",
        credentials: "include",
        mode: "cors"
      });
    }
    onSessionCreated(cb) {
      this.hanko.onSessionCreated(cb);
    }
  }
  // src/umd.ts
  function bootstrap() {
    const config = AuthDOMController.readConfig();
    if (!config?.apiUrl) {
      return;
    }
    const provider = new HankoProvider(config.apiUrl, config.locale);
    const flow = new AuthFlow(provider, config);
    const controller = new AuthDOMController(flow);
    controller.mount().catch(() => {});
  }
  if (typeof window !== "undefined" && typeof document !== "undefined") {
    bootstrap();
  }
})();

//# debugId=8D04D09199990AA864756E2164756E21
//# sourceMappingURL=umd.js.map
