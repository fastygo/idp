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
	Admin     AdminFixture  `json:"admin"`
	Mailer    MailerFixture `json:"mailer"`
	Errors    ErrorFixture  `json:"errors"`
}

type LoginFixture struct {
	Title                string `json:"title"`
	EmailLabel           string `json:"email_label"`
	PasswordLabel        string `json:"password_label"`
	Submit               string `json:"submit"`
	ErrorInvalidCredentials string `json:"error_invalid_credentials"`
	ErrorAccountNotFound string `json:"error_account_not_found"`
	Loading              string `json:"loading"`
}

type LogoutFixture struct {
	Title   string `json:"title"`
	Message string `json:"message"`
}

type AdminFixture struct {
	Title           string `json:"title"`
	CreateUser      string `json:"create_user"`
	EmailLabel      string `json:"email_label"`
	UsersTableTitle string `json:"users_table_title"`
	SubmitCreate    string `json:"submit_create"`
	ColumnEmail     string `json:"column_email"`
	ColumnID        string `json:"column_id"`
	ColumnCreated   string `json:"column_created"`
	NoUsers         string `json:"no_users"`
	NavUsers        string `json:"nav_users"`
	NavMailer       string `json:"nav_mailer"`
}

type MailerFixture struct {
	Title        string `json:"title"`
	ToLabel      string `json:"to_label"`
	SubjectLabel string `json:"subject_label"`
	BodyLabel    string `json:"body_label"`
	Submit       string `json:"submit"`
	Success      string `json:"success"`
	Error        string `json:"error"`
	LogTitle     string `json:"log_title"`
	ColumnTo     string `json:"column_to"`
	ColumnSubject string `json:"column_subject"`
	ColumnSentAt string `json:"column_sent_at"`
	ColumnStatus string `json:"column_status"`
	NoMessages   string `json:"no_messages"`
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
