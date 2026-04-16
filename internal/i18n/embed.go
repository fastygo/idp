package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed en/*.json ru/*.json
var fixtureFS embed.FS

type Localized struct {
	Common CommonFixture `json:"common"`
}

type CommonFixture struct {
	BrandName string        `json:"brand_name"`
	Theme     ThemeFixture  `json:"theme"`
	Language  LangFixture   `json:"language"`
	Login     LoginFixture  `json:"login"`
	Logout    LogoutFixture `json:"logout"`
	Errors    ErrorFixture  `json:"errors"`
}

type LoginFixture struct {
	Title                   string `json:"title"`
	EmailLabel              string `json:"email_label"`
	PasswordLabel           string `json:"password_label"`
	Submit                  string `json:"submit"`
	ErrorInvalidCredentials string `json:"error_invalid_credentials"`
	ErrorAccountNotFound    string `json:"error_account_not_found"`
	Loading                 string `json:"loading"`
}

type LogoutFixture struct {
	Title   string `json:"title"`
	Message string `json:"message"`
}

type ErrorFixture struct {
	GenericTitle   string `json:"generic_title"`
	GenericMessage string `json:"generic_message"`
	BackLink       string `json:"back_link"`
}

type ThemeFixture struct {
	Label              string `json:"label"`
	SwitchToDarkLabel  string `json:"switch_to_dark_label"`
	SwitchToLightLabel string `json:"switch_to_light_label"`
}

type LangFixture struct {
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
var cachedLocales map[string]Localized

func init() {
	preload()
}

func Locales() []string {
	return append([]string{}, supportedLocales...)
}

func Load(locale string) (Localized, error) {
	preload()
	if preloadErr != nil {
		return Localized{}, preloadErr
	}

	cachedLocale := normalizeLocale(locale)
	loaded, ok := cachedLocales[cachedLocale]
	if !ok {
		return Localized{}, fmt.Errorf("unsupported locale: %s", locale)
	}

	return loaded, nil
}

func preload() {
	preloadOnce.Do(func() {
		cachedLocales = make(map[string]Localized, len(supportedLocales))
		for _, locale := range supportedLocales {
			common, err := Decode[CommonFixture](locale, "common")
			if err != nil {
				preloadErr = err
				return
			}
			cachedLocales[locale] = Localized{
				Common: common,
			}
		}
	})
}

func Decode[T any](locale string, section string) (T, error) {
	var zero T
	if len(locale) == 0 {
		locale = "en"
	}

	path := fmt.Sprintf("%s/%s.json", locale, section)
	raw, err := fixtureFS.ReadFile(path)
	if err != nil {
		return zero, err
	}

	var decoded T
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return zero, err
	}

	return decoded, nil
}

func NormalizeLocale(locale string) string {
	return normalizeLocale(locale)
}

func normalizeLocale(locale string) string {
	if locale == "ru" || locale == "en" {
		return locale
	}
	return "en"
}
