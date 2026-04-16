package views

import "idp-cyberos/pkg/core"

type ThemeToggleData struct {
	Label              string
	SwitchToDarkLabel  string
	SwitchToLightLabel string
}

type LanguageToggleData struct {
	Label            string
	CurrentLocale    string
	CurrentLabel     string
	NextLocale       string
	NextLabel        string
	DefaultLocale    string
	AvailableLocales []string
}

type LayoutData struct {
	Title          string
	Locale         string
	Active         string
	BrandName      string
	ThemeToggle    ThemeToggleData
	LanguageToggle LanguageToggleData
	Flow           core.FlowConfig
	Features       core.FeatureFlags
}

type LoginStrings struct {
	Title                   string
	EmailLabel              string
	PasswordLabel           string
	Submit                  string
	ErrorInvalidCredentials string
	ErrorAccountNotFound    string
	Loading                 string
}

type LogoutStrings struct {
	Title   string
	Message string
}

type ErrorStrings struct {
	GenericTitle   string
	GenericMessage string
	BackLink       string
}

type LoginPageData struct {
	Layout  LayoutData
	Strings LoginStrings
}

type LogoutPageData struct {
	Layout   LayoutData
	Strings  LogoutStrings
	ReturnTo string
}

type ErrorPageData struct {
	Layout  LayoutData
	Strings ErrorStrings
	Message string
}
