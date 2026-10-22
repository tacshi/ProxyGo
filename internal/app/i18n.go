package app

import (
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/i18n"
	ui "github.com/egoist/mygo/proxygoui"

	"proxygo/internal/rules"
	"proxygo/internal/settings"
	"proxygo/internal/store"
	"proxygo/locales"
)

func toolName(id string) string {
	switch id {
	case rules.ToolBreakpoint:
		return locales.ToolBreakpoint()
	case rules.ToolMapLocal:
		return locales.ToolMapLocal()
	case rules.ToolMapRemote:
		return locales.ToolMapRemote()
	case rules.ToolScripting:
		return locales.ToolScripting()
	case rules.ToolBlock:
		return locales.ToolBlockList()
	case rules.ToolAllow:
		return locales.ToolAllowList()
	case rules.ToolNetwork:
		return locales.ToolNetworkConditions()
	case rules.ToolDNS:
		return locales.ToolDNSSpoofing()
	case rules.ToolReverse:
		return locales.ToolReverseProxy()
	}
	for _, t := range rules.AllTools {
		if t.ID == id {
			return t.Name
		}
	}
	return id
}

func colorName(color string) string {
	switch color {
	case "red":
		return locales.ColorRed()
	case "yellow":
		return locales.ColorYellow()
	case "green":
		return locales.ColorGreen()
	case "blue":
		return locales.ColorBlue()
	case "purple":
		return locales.ColorPurple()
	case "gray":
		return locales.ColorGray()
	}
	return title(color)
}

func exportTitle(format string) string {
	switch format {
	case "har":
		return locales.ExportHAR()
	case "csv":
		return locales.ExportCSV()
	case "postman":
		return locales.ExportPostman()
	case "openapi":
		return locales.ExportOpenAPIYAML()
	case "openapi-html":
		return locales.ExportOpenAPIHTML()
	case "raw":
		return locales.ExportRawHTTP()
	}
	return exportFormats[format].title
}

func orText(f, fallback func() string) string {
	if f != nil {
		if s := f(); s != "" {
			return s
		}
	}
	return fallback()
}

func inspectorTabLabel(id string) string {
	switch id {
	case "Header":
		return locales.TabHeader()
	case "Query":
		return locales.TabQuery()
	case "Body":
		return locales.TabBody()
	case "Raw":
		return locales.TabRaw()
	case "Cookies":
		return locales.TabCookies()
	case "Summary":
		return locales.TabSummary()
	case "Comment":
		return locales.TabComment()
	case "Timing":
		return locales.TabTiming()
	case "Messages":
		return locales.TabMessages()
	case "Headers":
		return locales.TabHeaders()
	}
	return id
}

func inspectorTabLabels(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = inspectorTabLabel(id)
	}
	return out
}

func flowToolName(name string) string {
	switch name {
	case "Breakpoint":
		return locales.ToolBreakpoint()
	case "Breakpoint Answer":
		return locales.BreakpointAnswer()
	case "Map Local":
		return locales.ToolMapLocal()
	case "Map Remote":
		return locales.ToolMapRemote()
	case "Script":
		return locales.Script()
	case "Mock API":
		return locales.MockAPI()
	case "Blocked":
		return locales.Blocked()
	case "Blocked App":
		return locales.BlockedApp()
	case "Network Conditions":
		return locales.ToolNetworkConditions()
	case "DNS Spoofing":
		return locales.ToolDNSSpoofing()
	}
	return name
}

func flowToolNames(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = flowToolName(n)
	}
	return out
}

func flowColumnTitle(col ui.TableColumn) string {
	switch col.ID {
	case store.SortClient:
		return locales.Client()
	case store.SortMethod:
		return locales.ColumnMethod()
	case store.SortStatus:
		return locales.ColumnStatus()
	case "code":
		return locales.Code()
	case store.SortTime:
		return locales.Time()
	case store.SortDuration:
		return locales.Duration()
	case store.SortRequest:
		return locales.ColumnRequestSize()
	case store.SortResponse:
		return locales.ColumnResponseSize()
	case "protocol":
		return locales.Protocol()
	case "host":
		return locales.ColumnHost()
	case "path":
		return locales.Path()
	case "contentType":
		return locales.ContentType()
	case "serverIP":
		return locales.ServerIP()
	case "edited":
		return locales.ColumnEdited()
	case store.SortComment:
		return locales.Comment()
	}
	return col.Title
}

func columnSourceName(id, fallback string) string {
	switch id {
	case settings.SourceHeader:
		return locales.TabHeader()
	case settings.SourceQuery:
		return locales.QueryParameter()
	case settings.SourceKeyPath:
		return locales.JSONBodyKeyPath()
	case settings.SourceJQ:
		return locales.JSONBodyJq()
	case settings.SourceJSONPath:
		return locales.JSONBodyJSONPath()
	}
	return fallback
}

func columnLabel(c settings.Column) string {
	switch {
	case c.Source == settings.SourceQuery:
		return locales.QueryColumnLabel(c.Name)
	case c.Response:
		return locales.ResponseColumnLabel(c.Name)
	}
	return locales.RequestColumnLabel(c.Name)
}

func columnProblem(s string) string {
	switch s {
	case "":
		return ""
	case "Enter the column's name.":
		return locales.EnterTheColumnsName()
	case "Enter the header, parameter or query to show.":
		return locales.EnterTheHeaderParameterOrQuery()
	case "Choose where the value comes from.":
		return locales.ChooseWhereTheValueComesFrom()
	}
	if rest, ok := strings.CutPrefix(s, "Invalid query: "); ok {
		return locales.InvalidQuery(rest)
	}
	return s
}

func kindLabel(k string) string {
	switch k {
	case "Form":
		return locales.KindForm()
	case "Document":
		return locales.KindDocument()
	case "Media":
		return locales.KindMedia()
	case "Other":
		return locales.Other()
	case "Encrypted":
		return locales.KindEncrypted()
	}
	return k
}

func fieldLabel(f store.Field) string {
	switch f {
	case store.FieldHost:
		return locales.ColumnHost()
	case store.FieldPath:
		return locales.Path()
	case store.FieldMethod:
		return locales.ColumnMethod()
	case store.FieldStatus:
		return locales.StatusCode()
	case store.FieldClient:
		return locales.Client()
	case store.FieldContentType:
		return locales.ContentType()
	case store.FieldRequestHeader:
		return locales.RequestHeader()
	case store.FieldResponseHeader:
		return locales.ResponseHeader()
	case store.FieldRequestBody:
		return locales.RequestBody()
	case store.FieldResponseBody:
		return locales.ResponseBodyLabel()
	case store.FieldGraphQL:
		return locales.GraphQLOperation()
	case store.FieldComment:
		return locales.Comment()
	case store.FieldDuration:
		return locales.DurationMs()
	case store.FieldSize:
		return locales.ResponseSizeBytes()
	case store.FieldQuery:
		return locales.TabQuery()
	case store.FieldRequestJQ:
		return locales.RequestJSONJq()
	case store.FieldResponseJQ:
		return locales.ResponseJSONJq()
	case store.FieldRequestJSONPath:
		return locales.RequestJSONPath()
	case store.FieldResponseJSONPath:
		return locales.ResponseJSONPath()
	}
	return string(f)
}

func opLabel(o store.Op) string {
	switch o {
	case store.OpContains:
		return locales.OpContains()
	case store.OpNotContains:
		return locales.OpDoesNotContain()
	case store.OpEquals:
		return locales.OpIs()
	case store.OpNotEquals:
		return locales.OpIsNot()
	case store.OpStartsWith:
		return locales.OpStartsWith()
	case store.OpEndsWith:
		return locales.OpEndsWith()
	case store.OpRegex:
		return locales.OpMatchesRegex()
	case store.OpGreater:
		return locales.OpGreaterThan()
	case store.OpLess:
		return locales.OpLessThan()
	}
	return string(o)
}

func bodyKindLabels() []string {
	return []string{locales.BodyText(), "JSON", locales.KindForm(), locales.BodyMultipart()}
}

func composeTemplateLabel(name string) string {
	switch name {
	case "Empty Request":
		return locales.EmptyRequest()
	case "GET with Query":
		return locales.GETWithQuery()
	case "POST with JSON":
		return locales.POSTWithJSON()
	case "POST with Form":
		return locales.POSTWithForm()
	case "POST with Multipart":
		return locales.POSTWithMultipart()
	}
	return name
}

func formatClock(t time.Time, layout string) string {
	locale := i18n.Locale()
	if !strings.Contains(layout, "Jan") || locale == "" || strings.HasPrefix(locale, "en") {
		return t.Format(layout)
	}
	skeleton := "MMMdHHmm"
	if strings.Contains(layout, ":05") {
		skeleton = "MMMdHHmmss"
	}
	return i18n.FormatDate(locale, t, i18n.DateOptions{Skeleton: skeleton})
}

func bodyModeLabel(mode string) string {
	switch mode {
	case modePretty:
		return locales.ModePretty()
	case modeTree:
		return locales.ModeTree()
	case modeRaw:
		return locales.TabRaw()
	case modeImage:
		return locales.ModeImage()
	case modeForm:
		return locales.KindForm()
	case modeParts:
		return locales.BodyMultipart()
	case modeSSE:
		return locales.ModeEvents()
	}
	return mode
}

func bodyModeLabels(modes []string) []string {
	out := make([]string, len(modes))
	for i, m := range modes {
		out[i] = bodyModeLabel(m)
	}
	return out
}

func appIconName(id, fallback string) string {
	switch id {
	case "sunset":
		return locales.IconSunset()
	case "neon":
		return locales.IconNeon()
	case "lime":
		return locales.IconLime()
	case "mint":
		return locales.IconMint()
	case "grape":
		return locales.IconGrape()
	case "paper":
		return locales.IconPaper()
	case "graphite":
		return locales.IconGraphite()
	case "sakura":
		return locales.IconSakura()
	}
	return fallback
}

func localeName(tag string) string {
	if tag == "" {
		return locales.FollowSystem()
	}
	return i18n.Autonym(tag)
}

func (a *App) languageSetting(c *ui.Context) {
	tags := append([]string{""}, mygo.App.Languages()...)
	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = localeName(tag)
	}
	choice := localeName(a.set.Language)
	if !slices.Contains(tags, a.set.Language) {
		choice = names[0]
	}
	a.settingRow(c, locales.Language(), "", func() {
		if ui.Select(c, &choice, names).Label(locales.Language()).Width(180).Changed() {
			if i := slices.Index(names, choice); i >= 0 {
				a.setLanguage(tags[i])
			}
		}
	})
}

func (a *App) setLanguage(tag string) {
	a.updateSettings(func(s *settings.Settings) { s.Language = tag })
	mygo.App.SetLocale(tag)
}

func (a *App) watchLocale() {
	mygo.App.OnLocaleChanged(func(string) {
		a.installMenu()
		a.setMenuDots()
		if a.tray != nil {
			a.tray.SetMenu(a.trayMenu())
		}
		for kind, w := range a.windows {
			if spec, ok := windowSpecs[kind]; ok {
				w.SetTitle(spec.title())
			}
		}
		a.invalidate()
	})
}
