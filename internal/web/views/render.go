package views

import (
	"log"
	"net/http"

	"idp-cyberos/internal/config"
	"idp-cyberos/internal/i18n"
)

func resolveLocale(r *http.Request) string {
	if cookie, err := r.Cookie("locale"); err == nil {
		return i18n.NormalizeLocale(cookie.Value)
	}
	accept := r.Header.Get("Accept-Language")
	if len(accept) >= 2 && (accept[:2] == "ru") {
		return "ru"
	}
	return "en"
}

func buildLayoutData(r *http.Request, cfg *config.Config, title string) LayoutData {
	locale := resolveLocale(r)
	l, err := i18n.Load(locale)
	if err != nil {
		log.Printf("i18n load error for %s: %v", locale, err)
		locale = "en"
		l, _ = i18n.Load("en")
	}

	return LayoutData{
		Title:       title + " — " + l.Common.BrandName,
		Locale:      locale,
		BrandName:   l.Common.BrandName,
		HankoAPIURL: cfg.HankoAPIURL,
		Features:    cfg.Features,
		ThemeToggle: ThemeToggleData{
			Label:              l.Common.Theme.Label,
			SwitchToDarkLabel:  l.Common.Theme.SwitchToDarkLabel,
			SwitchToLightLabel: l.Common.Theme.SwitchToLightLabel,
		},
		LanguageToggle: LanguageToggleData{
			Label:            l.Common.Language.Label,
			CurrentLocale:    locale,
			CurrentLabel:     l.Common.Language.CurrentLabel,
			NextLocale:       l.Common.Language.NextLocale,
			NextLabel:        l.Common.Language.NextLabel,
			DefaultLocale:    "en",
			AvailableLocales: l.Common.Language.Available,
		},
	}
}

func RenderLogin(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	locale := resolveLocale(r)
	l, _ := i18n.Load(locale)

	data := LoginPageData{
		Layout:  buildLayoutData(r, cfg, l.Common.Login.Title),
		Strings: l.Common.Login,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := LoginPage(data).Render(r.Context(), w); err != nil {
		log.Printf("render login: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func RenderLogout(w http.ResponseWriter, r *http.Request, cfg *config.Config, returnTo string) {
	locale := resolveLocale(r)
	l, _ := i18n.Load(locale)

	data := LogoutPageData{
		Layout:   buildLayoutData(r, cfg, l.Common.Logout.Title),
		Strings:  l.Common.Logout,
		ReturnTo: returnTo,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := LogoutPage(data).Render(r.Context(), w); err != nil {
		log.Printf("render logout: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func RenderError(w http.ResponseWriter, r *http.Request, cfg *config.Config, message string, statusCode int) {
	locale := resolveLocale(r)
	l, _ := i18n.Load(locale)

	data := ErrorPageData{
		Layout:  buildLayoutData(r, cfg, l.Common.Errors.GenericTitle),
		Strings: l.Common.Errors,
		Message: message,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := ErrorPage(data).Render(r.Context(), w); err != nil {
		log.Printf("render error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}
