package views

import (
	"idp-cyberos/internal/config"
	"idp-cyberos/internal/i18n"
)

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
	HankoAPIURL    string
	Features       config.Features
}

type LoginPageData struct {
	Layout  LayoutData
	Strings i18n.LoginFixture
}

type LogoutPageData struct {
	Layout   LayoutData
	Strings  i18n.LogoutFixture
	ReturnTo string
}

type ErrorPageData struct {
	Layout  LayoutData
	Strings i18n.ErrorFixture
	Message string
}
