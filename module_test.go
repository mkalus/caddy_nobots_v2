package caddy_nobots_v2

import (
	"regexp"
	"testing"
)

func TestBotUA_IsPublicURI(t *testing.T) {
	ttable := []struct {
		name     string
		botua    *BotUA
		expected bool
	}{
		{name: "empty", botua: &BotUA{}, expected: false}, // test non-initialized arrays
		{name: "public", botua: &BotUA{
			Public: []*regexp.Regexp{
				regexp.MustCompile("/public"),
			},
		}, expected: true},
		{name: "public2", botua: &BotUA{
			Public: []*regexp.Regexp{
				regexp.MustCompile("/private"),
				regexp.MustCompile("/public"),
			},
		}, expected: true},
		{name: "private", botua: &BotUA{
			Public: []*regexp.Regexp{
				regexp.MustCompile("/private"),
			},
		}, expected: false},
	}

	for _, tt := range ttable {
		result := tt.botua.IsPublicURI("/public")
		if result != tt.expected {
			t.Errorf("%s: got %v, want %v", tt.name, result, tt.expected)
		}
	}
}

func TestBotUA_IsEvil(t *testing.T) {
	ttable := []struct {
		name     string
		ua       string
		botua    *BotUA
		expected bool
	}{
		{name: "empty", ua: "GoogleBot", botua: &BotUA{}, expected: false}, // test non-initialized arrays
		{name: "evil1", ua: "GoogleBot", botua: &BotUA{
			Uas: []string{"GoogleBot", "BingBot"},
		}, expected: true},
		{name: "evil2", ua: "GoogleBot", botua: &BotUA{
			Re: []*regexp.Regexp{
				regexp.MustCompile("[Bb]ot"),
			},
		}, expected: true},
		{name: "nice1", ua: "NiceBrowser", botua: &BotUA{
			Uas: []string{"GoogleBot", "BingBot"},
		}, expected: false},
		{name: "nice2", ua: "NiceBrowser", botua: &BotUA{
			Re: []*regexp.Regexp{
				regexp.MustCompile("[Bb]ot"),
			},
		}, expected: false},
	}

	for _, tt := range ttable {
		result := tt.botua.IsEvil(tt.ua)
		if result != tt.expected {
			t.Errorf("%s (UA: %s): got %v, want %v", tt.name, tt.ua, result, tt.expected)
		}
	}
}
