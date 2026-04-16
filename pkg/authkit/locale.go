package authkit

import (
	"encoding/json"
	"fmt"
	"sync"
)

type localized struct {
	Common commonFixture `json:"common"`
}

type commonFixture struct {
	BrandName string        `json:"brand_name"`
	Theme     themeFixture  `json:"theme"`
	Language  langFixture   `json:"language"`
	Login     loginFixture  `json:"login"`
	Logout    logoutFixture `json:"logout"`
	Errors    errorFixture  `json:"errors"`
}

type loginFixture struct {
	Title                   string `json:"title"`
	EmailLabel              string `json:"email_label"`
	PasswordLabel           string `json:"password_label"`
	Submit                  string `json:"submit"`
	ErrorInvalidCredentials string `json:"error_invalid_credentials"`
	ErrorAccountNotFound    string `json:"error_account_not_found"`
	Loading                 string `json:"loading"`
}

type logoutFixture struct {
	Title   string `json:"title"`
	Message string `json:"message"`
}

type errorFixture struct {
	GenericTitle   string `json:"generic_title"`
	GenericMessage string `json:"generic_message"`
	BackLink       string `json:"back_link"`
}

type themeFixture struct {
	Label              string `json:"label"`
	SwitchToDarkLabel  string `json:"switch_to_dark_label"`
	SwitchToLightLabel string `json:"switch_to_light_label"`
}

type langFixture struct {
	Label        string            `json:"label"`
	CurrentLabel string            `json:"current_label"`
	NextLabel    string            `json:"next_label"`
	NextLocale   string            `json:"next_locale"`
	Available    []string          `json:"available"`
	LocaleLabels map[string]string `json:"locale_labels"`
}

var supportedLocales = []string{"en", "ru"}
var preloadOnce sync.Once
var preloadErr error
var cachedLocales map[string]localized

func Locales() []string {
	return append([]string{}, supportedLocales...)
}

func Load(locale string) (localized, error) {
	preload()
	if preloadErr != nil {
		return localized{}, preloadErr
	}

	loaded, ok := cachedLocales[NormalizeLocale(locale)]
	if !ok {
		return localized{}, fmt.Errorf("unsupported locale: %s", locale)
	}

	return loaded, nil
}

func NormalizeLocale(locale string) string {
	if locale == "ru" || locale == "en" {
		return locale
	}

	return "en"
}

func preload() {
	preloadOnce.Do(func() {
		cachedLocales = make(map[string]localized, len(supportedLocales))
		for _, locale := range supportedLocales {
			common, err := decode[commonFixture](locale, "common")
			if err != nil {
				preloadErr = err
				return
			}

			cachedLocales[locale] = localized{Common: common}
		}
	})
}

func decode[T any](locale string, section string) (T, error) {
	var zero T

	path := fmt.Sprintf("i18n/%s/%s.json", NormalizeLocale(locale), section)
	raw, err := embeddedFS.ReadFile(path)
	if err != nil {
		return zero, err
	}

	var decoded T
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return zero, err
	}

	return decoded, nil
}
