(function () {
  var namespace = "ui8kit";
  var existing = window[namespace];
  if (!existing) {
    existing = {};
    window[namespace] = existing;
  }
  if (existing.ready) {
    return;
  }

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
      return;
    }
    fn();
  }

  function byAttr(name, root) {
    var scope = root || document;
    return scope.querySelectorAll("[data-" + name + "]");
  }

  existing.core = {
    ready: ready,
    byAttr: byAttr,
  };
  existing.ready = function (fn) {
    ready(fn);
  };
})();
(function () {
  var root = document.documentElement;
  var themeStorageKey = "ui8kit-theme";

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
      return;
    }
    fn();
  }

  function readStoredTheme() {
    try {
      return localStorage.getItem(themeStorageKey);
    } catch (_) {
      return null;
    }
  }

  function writeStoredTheme(value) {
    try {
      localStorage.setItem(themeStorageKey, value);
    } catch (_) {}
  }

  function resolvePreferredTheme() {
    var storedTheme = readStoredTheme();
    if (storedTheme === "dark" || storedTheme === "light") {
      return storedTheme;
    }

    var prefersDark =
      window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    return prefersDark ? "dark" : "light";
  }

  function applyTheme(theme) {
    root.classList.toggle("dark", theme === "dark");
  }

  function applyThemeButtonState() {
    var icon = document.getElementById("theme-toggle-icon");
    var button = document.getElementById("ui8kit-theme-toggle");
    var dark = root.classList.contains("dark");
    var switchToDark =
      button && button.dataset.switchToDarkLabel
        ? button.dataset.switchToDarkLabel
        : "Switch to dark theme";
    var switchToLight =
      button && button.dataset.switchToLightLabel
        ? button.dataset.switchToLightLabel
        : "Switch to light theme";

    if (icon) {
      icon.className = dark
        ? "ui-theme-icon latty latty-sun"
        : "ui-theme-icon latty latty-moon";
    }

    if (button) {
      button.setAttribute("aria-pressed", dark ? "true" : "false");
      button.setAttribute("title", dark ? switchToLight : switchToDark);
      button.setAttribute("aria-label", dark ? switchToLight : switchToDark);
    }
  }

  applyTheme(resolvePreferredTheme());

  ready(function () {
    var themeButton = document.getElementById("ui8kit-theme-toggle");

    if (themeButton) {
      themeButton.addEventListener("click", function () {
        var nextTheme = root.classList.contains("dark") ? "light" : "dark";
        applyTheme(nextTheme);
        writeStoredTheme(nextTheme);
        applyThemeButtonState();
      });
    }

    applyThemeButtonState();
  });
})();
(function () {
  var namespace = window.ui8kit || {};
  window.ui8kit = namespace;
  if (namespace.dialog) {
    return;
  }

  var OPEN_ATTR = "data-state";
  var OPEN_VALUE = "open";
  var CLOSED_VALUE = "closed";

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
      return;
    }
    fn();
  }

  function toDialog(node) {
    if (!node) {
      return null;
    }
    if (typeof node === "string") {
      return document.querySelector('[data-ui8kit-dialog][id="' + node + '"]');
    }
    if (node.matches('[data-ui8kit="dialog"], [data-ui8kit="sheet"], [data-ui8kit="alertdialog"]')) {
      return node;
    }
    var target = node.getAttribute && node.getAttribute("data-ui8kit-dialog-target");
    if (target) {
      return document.getElementById(target);
    }
  if (node.closest) {
    return node.closest('[data-ui8kit="dialog"], [data-ui8kit="sheet"], [data-ui8kit="alertdialog"]');
  }
    return null;
  }

  function setDialogState(dialog, open) {
    if (!dialog) {
      return;
    }
    var overlay = dialog.querySelector("[data-ui8kit-dialog-overlay]");
    var closeable = open ? true : false;
    dialog.setAttribute(OPEN_ATTR, open ? OPEN_VALUE : CLOSED_VALUE);

    if (open) {
      dialog.removeAttribute("hidden");
      if (overlay) {
        overlay.removeAttribute("hidden");
      }
      dialog.dataset.wasHidden = "true";
      trapFocus(dialog);
    } else {
      dialog.setAttribute("hidden", "hidden");
      if (overlay) {
        overlay.setAttribute("hidden", "hidden");
      }
      if (closeable) {
        releaseFocus(dialog);
      }
      if (dialog.dataset.lastFocus) {
        var last = document.getElementById(dialog.dataset.lastFocus);
        if (last && typeof last.focus === "function") {
          last.focus();
        }
      }
      delete dialog.dataset.lastFocus;
    }
  }

  function openDialog(dialog, trigger) {
    if (!dialog) {
      return;
    }
    if (trigger && trigger.getAttribute) {
      var id = trigger.getAttribute("id");
      if (id) {
        dialog.dataset.lastFocus = id;
      }
    }
    setDialogState(dialog, true);
  }

  function closeDialog(dialog) {
    setDialogState(dialog, false);
  }

  function trapFocus(dialog) {
    if (!dialog || dialog.dataset.trapped === "1") {
      return;
    }
    dialog.dataset.trapped = "1";
    var first = findFocusable(dialog)[0];
    if (first && typeof first.focus === "function") {
      first.focus();
    }
  }

  function releaseFocus(dialog) {
    delete dialog.dataset.trapped;
  }

  function findFocusable(dialog) {
    return dialog.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
  }

  function handleTabKey(event, dialog) {
    if (event.key !== "Tab" || !dialog || dialog.getAttribute(OPEN_ATTR) !== OPEN_VALUE) {
      return;
    }
    var focusable = findFocusable(dialog);
    if (!focusable.length) {
      event.preventDefault();
      return;
    }
    var first = focusable[0];
    var last = focusable[focusable.length - 1];
    var target = document.activeElement;
    if (event.shiftKey) {
      if (target === first || target === dialog) {
        last.focus();
        event.preventDefault();
      }
    } else if (target === last || target === dialog) {
      first.focus();
      event.preventDefault();
    }
  }

  function isOpen(dialog) {
    return dialog && dialog.getAttribute(OPEN_ATTR) === OPEN_VALUE;
  }

  function onDocumentClick(event) {
    var openButton = event.target.closest("[data-ui8kit-dialog-open], [data-ui8kit-dialog-target]");
    if (openButton && openButton.matches("[data-ui8kit-dialog-open]")) {
      var dialog = toDialog(openButton);
      if (dialog) {
        openDialog(dialog, openButton);
      }
      return;
    }
    var closeButton = event.target.closest("[data-ui8kit-dialog-close]");
    if (closeButton) {
      closeDialog(toDialog(closeButton));
      return;
    }
    if (event.target.closest("[data-ui8kit-dialog-overlay]")) {
      var overlayDialog = event.target.closest("[data-ui8kit-dialog], [data-ui8kit=sheet], [data-ui8kit=alertdialog]");
      closeDialog(overlayDialog);
    }
  }

  function onDocumentKeydown(event) {
    if (event.key === "Escape") {
      var dialogs = document.querySelectorAll('[data-ui8kit="dialog"], [data-ui8kit="sheet"], [data-ui8kit="alertdialog"]');
      for (var i = 0; i < dialogs.length; i += 1) {
        var dialog = dialogs[i];
        if (isOpen(dialog)) {
          closeDialog(dialog);
          event.preventDefault();
          return;
        }
      }
      return;
    }

    var dialogs = document.querySelectorAll('[data-ui8kit="dialog"], [data-ui8kit="sheet"], [data-ui8kit="alertdialog"]');
    for (var i = 0; i < dialogs.length; i += 1) {
      if (isOpen(dialogs[i]) && dialogs[i].contains(event.target)) {
        handleTabKey(event, dialogs[i]);
      }
    }
  }

  ready(function () {
    var dialogs = document.querySelectorAll('[data-ui8kit="dialog"], [data-ui8kit="sheet"], [data-ui8kit="alertdialog"]');
    for (var i = 0; i < dialogs.length; i += 1) {
      setDialogState(dialogs[i], dialogs[i].getAttribute(OPEN_ATTR) === OPEN_VALUE);
    }
    document.addEventListener("click", onDocumentClick);
    document.addEventListener("keydown", onDocumentKeydown);
  });

  namespace.dialog = {
    open: function (id) {
      openDialog(toDialog(id));
    },
    close: function (id) {
      closeDialog(toDialog(id));
    },
  };
  namespace.ready = function (fn) {
    ready(fn);
  };
})();
(function () {
  var namespace = window.ui8kit || {};
  window.ui8kit = namespace;
  if (namespace.accordion) {
    return;
  }

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
      return;
    }
    fn();
  }

  function getAccordionRoots() {
    return document.querySelectorAll('[data-ui8kit="accordion"]');
  }

  function isMultiple(root) {
    return (root.getAttribute("data-accordion-type") || "single") === "multiple";
  }

  function setItemState(item, open) {
    var trigger = item.querySelector('[data-ui8kit-accordion-trigger]');
    var panel = item.querySelector('[data-ui8kit-accordion-content]');
    if (!trigger || !panel) {
      return;
    }
    item.setAttribute("data-state", open ? "open" : "closed");
    if (trigger) {
      trigger.setAttribute("aria-expanded", open ? "true" : "false");
    }
    if (panel) {
      if (open) {
        panel.removeAttribute("hidden");
      } else {
        panel.setAttribute("hidden", "hidden");
      }
    }
  }

  function closeOthers(root, currentItem) {
    var items = root.querySelectorAll('[data-accordion-item]');
    for (var i = 0; i < items.length; i += 1) {
      if (items[i] !== currentItem) {
        setItemState(items[i], false);
      }
    }
  }

  function toggle(root, trigger, panel, item, open) {
    var current = item.getAttribute("data-state") === "open";
    var next = typeof open === "boolean" ? open : !current;
    if (!isMultiple(root)) {
      closeOthers(root, item);
    }
    setItemState(item, next);
  }

  ready(function () {
    var roots = getAccordionRoots();
    for (var i = 0; i < roots.length; i += 1) {
      var root = roots[i];
      var items = root.querySelectorAll('[data-accordion-item]');
      for (var j = 0; j < items.length; j += 1) {
        var item = items[j];
        var trigger = item.querySelector('[data-ui8kit-accordion-trigger]');
        var panel = item.querySelector('[data-ui8kit-accordion-content]');
        if (!trigger || !panel) {
          continue;
        }
        var openByDefault = item.getAttribute("data-state") === "open";
        setItemState(item, openByDefault);
        trigger.setAttribute("type", "button");
        trigger.addEventListener("click", function (evt) {
          evt.preventDefault();
          var itemNode = evt.currentTarget.closest('[data-accordion-item]');
          if (!itemNode) {
            return;
          }
          var accordionRoot = evt.currentTarget.closest('[data-ui8kit="accordion"]');
          toggle(accordionRoot, evt.currentTarget, itemNode.querySelector('[data-ui8kit-accordion-content]'), itemNode);
        });
        trigger.addEventListener("keydown", function (evt) {
          if (evt.key !== "Enter" && evt.key !== " ") {
            return;
          }
          evt.preventDefault();
          evt.currentTarget.click();
        });
      }
    }
  });

  namespace.accordion = { init: function () {} };
})();
(function () {
  var namespace = window.ui8kit || {};
  window.ui8kit = namespace;
  if (namespace.tabs) {
    return;
  }

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
      return;
    }
    fn();
  }

  function activateTab(tabRoot, value, useFocus) {
    var triggers = tabRoot.querySelectorAll('[data-tabs-trigger]');
    var panels = tabRoot.querySelectorAll('[data-tabs-panel]');
    for (var i = 0; i < triggers.length; i += 1) {
      var trigger = triggers[i];
      var isActive = trigger.getAttribute("data-tabs-value") === value;
      trigger.setAttribute("aria-selected", isActive ? "true" : "false");
      trigger.setAttribute("tabindex", isActive ? "0" : "-1");
      if (isActive && useFocus && typeof trigger.focus === "function") {
        trigger.focus();
      }
    }

    for (i = 0; i < panels.length; i += 1) {
      var panel = panels[i];
      var active = panel.getAttribute("data-tabs-value") === value;
      panel.hidden = !active;
    }
  }

  function defaultValue(root) {
    var active = root.getAttribute("data-tabs-value");
    if (active) {
      return active;
    }
    var selected = root.querySelector('[data-tabs-trigger][aria-selected="true"]');
    if (selected && selected.getAttribute("data-tabs-value")) {
      return selected.getAttribute("data-tabs-value");
    }
    var first = root.querySelector('[data-tabs-trigger]');
    return first ? first.getAttribute("data-tabs-value") : "";
  }

  function onKeydown(event, root) {
    var trigger = event.target.closest('[data-tabs-trigger]');
    if (!trigger || !root.contains(trigger)) {
      return;
    }
    var triggers = root.querySelectorAll('[data-tabs-trigger]');
    if (!triggers.length) {
      return;
    }
    var list = Array.prototype.slice.call(triggers);
    var index = list.indexOf(trigger);
    if (index === -1) {
      return;
    }
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      event.preventDefault();
      var next = (index + 1) % list.length;
      activateTab(root, list[next].getAttribute("data-tabs-value"), true);
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      event.preventDefault();
      var previous = (index - 1 + list.length) % list.length;
      activateTab(root, list[previous].getAttribute("data-tabs-value"), true);
    }
  }

  ready(function () {
    var roots = document.querySelectorAll('[data-ui8kit="tabs"]');
    for (var i = 0; i < roots.length; i += 1) {
      var root = roots[i];
      var value = defaultValue(root);
      if (value) {
        activateTab(root, value, false);
      }

      root.addEventListener("click", (function (activeRoot) {
        return function (event) {
        var trigger = event.target.closest('[data-tabs-trigger]');
        if (!trigger || !activeRoot) {
          return;
        }
        var target = trigger.getAttribute("data-tabs-value");
        if (!target) {
          return;
        }
        event.preventDefault();
        activateTab(activeRoot, target, false);
      };
      })(root));

      root.addEventListener("keydown", (function (activeRoot) {
        return function (event) {
          onKeydown(event, activeRoot);
        };
      })(root));
    }
  });

  namespace.tabs = { init: function () {} };
})();
(function () {
  var namespace = window.ui8kit || {};
  window.ui8kit = namespace;
  if (namespace.combobox) {
    return;
  }

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
      return;
    }
    fn();
  }

  function hideAll(roots) {
    for (var i = 0; i < roots.length; i += 1) {
      var list = roots[i].querySelector('[role="listbox"], ul');
      if (list) {
        list.setAttribute("hidden", "hidden");
      }
    }
  }

  function optionText(item) {
    return (item.textContent || "").toLowerCase().trim();
  }

  function open(root) {
    var list = root.querySelector('[role="listbox"], ul');
    if (list) {
      list.removeAttribute("hidden");
    }
    var input = root.querySelector('input');
    var trigger = root.querySelector('[data-combobox-toggle]');
    if (trigger) {
      trigger.setAttribute("aria-expanded", "true");
    }
    if (input) {
      input.setAttribute("aria-expanded", "true");
    }
    root.setAttribute("data-state", "open");
  }

  function close(root) {
    var list = root.querySelector('[role="listbox"], ul');
    if (list) {
      list.setAttribute("hidden", "hidden");
    }
    var trigger = root.querySelector('[data-combobox-toggle]');
    if (trigger) {
      trigger.setAttribute("aria-expanded", "false");
    }
    var input = root.querySelector('input');
    if (input) {
      input.setAttribute("aria-expanded", "false");
    }
    root.setAttribute("data-state", "closed");
  }

  function filterOptions(root) {
    var input = root.querySelector('input');
    var options = root.querySelectorAll('[data-combobox-option]');
    var phrase = (input && input.value ? input.value : "").toLowerCase().trim();
    for (var i = 0; i < options.length; i += 1) {
      var option = options[i];
      var text = optionText(option);
      var visible = !phrase || text.indexOf(phrase) >= 0;
      option.style.display = visible ? "" : "none";
    }
  }

  function findFirstVisibleOption(root) {
    var options = root.querySelectorAll('[data-combobox-option]');
    for (var i = 0; i < options.length; i += 1) {
      var option = options[i];
      if (option.style.display !== "none") {
        return option;
      }
    }
    return null;
  }

  function syncFocus(root, option) {
    var options = root.querySelectorAll('[data-combobox-option]');
    for (var i = 0; i < options.length; i += 1) {
      options[i].classList.remove("ui-combobox-option-active");
      options[i].setAttribute("aria-selected", "false");
    }
    if (option) {
      option.classList.add("ui-combobox-option-active");
      option.setAttribute("aria-selected", "true");
      if (typeof option.scrollIntoView === "function") {
        option.scrollIntoView({ block: "nearest" });
      }
    }
  }

  function selectOption(root, option) {
    if (!option || option.getAttribute("aria-disabled") === "true") {
      return;
    }
    var input = root.querySelector('input');
    var value = option.getAttribute("data-combobox-value") || option.textContent || "";
    if (input) {
      input.value = value;
    }
    close(root);
  }

  function findOptionsBelow(root) {
    return root.querySelectorAll('[data-combobox-option]:not([aria-disabled="true"]):not([style*="none"])');
  }

  ready(function () {
    var roots = document.querySelectorAll('[data-ui8kit="combobox"]');
    for (var i = 0; i < roots.length; i += 1) {
      var root = roots[i];
      var input = root.querySelector("input");
      var toggle = root.querySelector('[data-combobox-toggle]');
      var options = root.querySelectorAll('[data-combobox-option]');

      if (!input || !options.length) {
        continue;
      }

      (function (activeRoot, activeInput, activeToggle, activeOptions) {
        activeInput.addEventListener("focus", function () {
          open(activeRoot);
        });
        activeInput.addEventListener("input", function () {
          open(activeRoot);
          filterOptions(activeRoot);
        });
        activeInput.addEventListener("keydown", function (event) {
          if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            var visible = findOptionsBelow(activeRoot);
            if (!visible.length) {
              return;
            }
            var direction = event.key === "ArrowDown" ? 1 : -1;
            var current = activeRoot.querySelector(".ui-combobox-option-active");
            var currentIndex = current ? Array.prototype.indexOf.call(visible, current) : -1;
            if (currentIndex < 0) {
              currentIndex = direction > 0 ? -1 : 0;
            }
            var nextIndex = (currentIndex + direction + visible.length) % visible.length;
            syncFocus(activeRoot, visible[nextIndex]);
            event.preventDefault();
          } else if (event.key === "Enter" && activeRoot.querySelector(".ui-combobox-option-active")) {
            selectOption(activeRoot, activeRoot.querySelector(".ui-combobox-option-active"));
            event.preventDefault();
          } else if (event.key === "Escape") {
            close(activeRoot);
            event.preventDefault();
          }
        });

        for (var j = 0; j < activeOptions.length; j += 1) {
          activeOptions[j].addEventListener("mousedown", function (event) {
            event.preventDefault();
          });
          activeOptions[j].addEventListener("click", function (event) {
            selectOption(activeRoot, event.currentTarget);
          });
        }

        if (activeToggle) {
          activeToggle.addEventListener("click", function () {
            if (activeRoot.getAttribute("data-state") === "open") {
              close(activeRoot);
            } else {
              open(activeRoot);
            }
          });
        }

        activeRoot.dataset.hasBinding = "true";
        filterOptions(activeRoot);
      })(root, input, toggle, options);
    }

    document.addEventListener("click", function (event) {
      var current = event.target.closest('[data-ui8kit="combobox"]');
      if (!current) {
        hideAll(document.querySelectorAll('[data-ui8kit="combobox"]'));
      }
    });
  });

  namespace.combobox = { init: function () {} };
})();
(function () {
  var namespace = window.ui8kit || {};
  window.ui8kit = namespace;
  if (namespace.tooltip) {
    return;
  }

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
      return;
    }
    fn();
  }

  function openTooltip(tooltip) {
    var content = tooltip.querySelector('[role="tooltip"]');
    if (!content) {
      return;
    }
    content.removeAttribute("hidden");
    tooltip.setAttribute("data-state", "open");
    content.setAttribute("aria-hidden", "false");
  }

  function closeTooltip(tooltip) {
    var content = tooltip.querySelector('[role="tooltip"]');
    if (!content) {
      return;
    }
    content.setAttribute("hidden", "hidden");
    tooltip.setAttribute("data-state", "closed");
    content.setAttribute("aria-hidden", "true");
  }

  ready(function () {
    var tooltips = document.querySelectorAll('[data-ui8kit="tooltip"]');
    for (var i = 0; i < tooltips.length; i += 1) {
      var root = tooltips[i];
      root.addEventListener("mouseenter", function () {
        openTooltip(this);
      });
      root.addEventListener("focusin", function () {
        openTooltip(this);
      });
      root.addEventListener("mouseleave", function () {
        closeTooltip(this);
      });
      root.addEventListener("focusout", function () {
        closeTooltip(this);
      });
    }
  });

  namespace.tooltip = { init: function () {} };
})();
(function () {
  var namespace = window.ui8kit || {};
  window.ui8kit = namespace;
  if (namespace.alert) {
    return;
  }

  namespace.alert = {
    init: function () {
      // Placeholder for future alert enhancement logic.
      return;
    },
  };
})();
(function () {
  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
      return;
    }
    fn();
  }

  function normalizeLocale(value, allowedLocales) {
    var locale = (value || "").toLowerCase();
    return allowedLocales.indexOf(locale) !== -1 ? locale : "";
  }

  function parseLocales(raw) {
    return (raw || "")
      .split(",")
      .map(function (item) {
        return item.trim().toLowerCase();
      })
      .filter(function (item, index, list) {
        return item && list.indexOf(item) === index;
      });
  }

  function browserLocales() {
    var values = [];

    if (Array.isArray(navigator.languages)) {
      values = values.concat(navigator.languages);
    }

    if (typeof navigator.language === "string") {
      values.push(navigator.language);
    }

    return values
      .map(function (item) {
        return String(item || "")
          .trim()
          .toLowerCase()
          .replace(/_/g, "-");
      })
      .filter(function (item, index, list) {
        return item && list.indexOf(item) === index;
      });
  }

  function detectPreferredLocale(allowedLocales, defaultLocale) {
    var locales = browserLocales();

    for (var i = 0; i < locales.length; i += 1) {
      var locale = locales[i];
      if (allowedLocales.indexOf(locale) !== -1) {
        return locale;
      }

      var baseLocale = locale.split("-")[0];
      if (allowedLocales.indexOf(baseLocale) !== -1) {
        return baseLocale;
      }
    }

    return defaultLocale;
  }

  function buttonDefaultLocale(toggle) {
    var available = parseLocales(toggle.dataset.availableLocales);
    return normalizeLocale(toggle.dataset.defaultLocale, available) || available[0] || "";
  }

  function buttonCurrentLocale(toggle, availableLocales) {
    return normalizeLocale(toggle.dataset.currentLocale, availableLocales) || buttonDefaultLocale(toggle);
  }

  function buttonNextLocale(toggle, currentLocale) {
    var availableLocales = parseLocales(toggle.dataset.availableLocales);
    var next = currentLocale;

    for (var i = 0; i < availableLocales.length; i += 1) {
      if (availableLocales[i] !== currentLocale) {
        next = availableLocales[i];
        break;
      }
    }

    return next;
  }

  function readStoredLocale(toggle) {
    var availableLocales = parseLocales(toggle.dataset.availableLocales);
    try {
      return normalizeLocale(localStorage.getItem("framework-language"), availableLocales);
    } catch (_) {
      return "";
    }
  }

  function writeStoredLocale(locale) {
    try {
      localStorage.setItem("framework-language", locale);
    } catch (_) {}
  }

  function localeURL(toggle, locale) {
    var next = new URL(window.location.href);
    if (locale === buttonDefaultLocale(toggle)) {
      next.searchParams.delete("lang");
    } else {
      next.searchParams.set("lang", locale);
    }
    return next.toString();
  }

  ready(function () {
    var toggle = document.getElementById("web-language-toggle");

    if (!toggle) {
      return;
    }

    var availableLocales = parseLocales(toggle.dataset.availableLocales);
    var defaultLocale = buttonDefaultLocale(toggle);
    var currentLocale = buttonCurrentLocale(toggle, availableLocales);
    var hasExplicitLocaleParam = new URL(window.location.href).searchParams.has("lang");
    var storedLocale = readStoredLocale(toggle);

    if (hasExplicitLocaleParam) {
      writeStoredLocale(currentLocale);
    } else {
      var preferredLocale = storedLocale || detectPreferredLocale(availableLocales, defaultLocale);
      if (preferredLocale) {
        writeStoredLocale(preferredLocale);
      }

      if (
        preferredLocale &&
        preferredLocale !== defaultLocale &&
        preferredLocale !== currentLocale
      ) {
        var targetURL = localeURL(toggle, preferredLocale);
        if (targetURL !== window.location.href) {
          window.location.replace(targetURL);
          return;
        }
      }

      if (preferredLocale) {
        currentLocale = preferredLocale;
      }
    }

    toggle.addEventListener("click", function () {
      var nextLocale = buttonNextLocale(toggle, currentLocale);
      if (!nextLocale || nextLocale === currentLocale) {
        return;
      }
      writeStoredLocale(nextLocale);
      window.location.assign(localeURL(toggle, nextLocale));
    });
  });
})();
