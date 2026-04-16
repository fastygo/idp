package authkit

import (
	"log"
	"net/http"

	"idp-cyberos/pkg/authkit/views"
)

func resolveLocale(r *http.Request) string {
	if cookie, err := r.Cookie("locale"); err == nil {
		return NormalizeLocale(cookie.Value)
	}

	accept := r.Header.Get("Accept-Language")
	if len(accept) >= 2 && accept[:2] == "ru" {
		return "ru"
	}

	return "en"
}

func (r *renderer) buildLayoutData(req *http.Request, title string) views.LayoutData {
	locale := resolveLocale(req)
	l, err := Load(locale)
	if err != nil {
		log.Printf("authkit i18n load error for %s: %v", locale, err)
		locale = "en"
		l, _ = Load("en")
	}

	brandName := r.cfg.BrandName
	if brandName == "" {
		brandName = l.Common.BrandName
	}

	availableLocales := r.cfg.Locales
	if len(availableLocales) == 0 {
		availableLocales = l.Common.Language.Available
	}

	return views.LayoutData{
		Title:     title + " — " + brandName,
		Locale:    locale,
		BrandName: brandName,
		Flow:      r.cfg.Flow,
		Features:  r.cfg.Features,
		ThemeToggle: views.ThemeToggleData{
			Label:              l.Common.Theme.Label,
			SwitchToDarkLabel:  l.Common.Theme.SwitchToDarkLabel,
			SwitchToLightLabel: l.Common.Theme.SwitchToLightLabel,
		},
		LanguageToggle: views.LanguageToggleData{
			Label:            l.Common.Language.Label,
			CurrentLocale:    locale,
			CurrentLabel:     l.Common.Language.CurrentLabel,
			NextLocale:       l.Common.Language.NextLocale,
			NextLabel:        l.Common.Language.NextLabel,
			DefaultLocale:    "en",
			AvailableLocales: availableLocales,
		},
	}
}

func (r *renderer) RenderLogin(w http.ResponseWriter, req *http.Request) {
	locale := resolveLocale(req)
	l, _ := Load(locale)

	data := views.LoginPageData{
		Layout: r.buildLayoutData(req, l.Common.Login.Title),
		Strings: views.LoginStrings{
			Title:                   l.Common.Login.Title,
			EmailLabel:              l.Common.Login.EmailLabel,
			PasswordLabel:           l.Common.Login.PasswordLabel,
			Submit:                  l.Common.Login.Submit,
			ErrorInvalidCredentials: l.Common.Login.ErrorInvalidCredentials,
			ErrorAccountNotFound:    l.Common.Login.ErrorAccountNotFound,
			Loading:                 l.Common.Login.Loading,
		},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.LoginPage(data).Render(req.Context(), w); err != nil {
		log.Printf("authkit render login: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (r *renderer) RenderLogout(w http.ResponseWriter, req *http.Request, returnTo string) {
	locale := resolveLocale(req)
	l, _ := Load(locale)

	data := views.LogoutPageData{
		Layout: r.buildLayoutData(req, l.Common.Logout.Title),
		Strings: views.LogoutStrings{
			Title:   l.Common.Logout.Title,
			Message: l.Common.Logout.Message,
		},
		ReturnTo: returnTo,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.LogoutPage(data).Render(req.Context(), w); err != nil {
		log.Printf("authkit render logout: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (r *renderer) RenderError(w http.ResponseWriter, req *http.Request, message string, statusCode int) {
	locale := resolveLocale(req)
	l, _ := Load(locale)

	data := views.ErrorPageData{
		Layout: r.buildLayoutData(req, l.Common.Errors.GenericTitle),
		Strings: views.ErrorStrings{
			GenericTitle:   l.Common.Errors.GenericTitle,
			GenericMessage: l.Common.Errors.GenericMessage,
			BackLink:       l.Common.Errors.BackLink,
		},
		Message: message,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := views.ErrorPage(data).Render(req.Context(), w); err != nil {
		log.Printf("authkit render error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}
