package caddy_nobots_v2

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mkalus/caddy_nobots_v2/bombs"
	"go.uber.org/zap"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func init() {
	caddy.RegisterModule(BotUA{})
	httpcaddyfile.RegisterHandlerDirective("nobots", parseCaddyfileForNoBots)
}

// BotUA is a Caddy Server plugin to protect your website against web crawlers and bots. It is an enhancement of the
// v1 version https://github.com/caddy-plugins/nobots
type BotUA struct {
	Logger *zap.Logger // Logger instance

	// Set to true to log hits (blocked requests)
	ShowHits bool `json:"show_hits"`

	// Set to true to log misses (non-blocked requests)
	ShowMisses bool `json:"show_misses"`

	// Set to true to log requests to public directories
	ShowPublic bool `json:"show_public"`

	// User-Agents to block (full name)
	Uas []string `json:"uas"`

	// Partial strings for user-agents to block
	Contains []string `json:"contains"`

	// Bomb file or string. Should be a gzipped file. Allowed predefined bomb strings are: 1G, 10G, 1T
	Bomb string `json:"bomb"`

	// Regular expressions for user-agents to block
	Re []*regexp.Regexp `json:"re"`

	// Public directories to exclude from blocking (regular expressions)
	Public []*regexp.Regexp `json:"public"`
}

// CaddyModule returns the Caddy module information.
func (BotUA) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.nobots",
		New: func() caddy.Module { return new(BotUA) },
	}
}

func (ua *BotUA) Provision(ctx caddy.Context) error {
	ua.Logger = ctx.Logger()

	return nil
}

// IsPublicURI check if the requested URI is defined as public or not
func (ua BotUA) IsPublicURI(uri string) bool {
	for _, re := range ua.Public {
		if re.MatchString(uri) {
			return true
		}
	}

	return false
}

// IsEvil check the remote UA against evil UAs
func (ua BotUA) IsEvil(rua string) bool {
	// In case there are strings
	for _, agent := range ua.Uas {
		if agent == rua {
			return true
		}
	}
	// In case there are partial strings
	for _, partial := range ua.Contains {
		if strings.Contains(rua, partial) {
			return true
		}
	}
	// In case there are regexp
	for _, re := range ua.Re {
		if re.MatchString(rua) {
			return true
		}
	}
	// UA is not evil
	return false
}

func (ua BotUA) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Get request UA
	rua := r.UserAgent()

	// Avoid ban UA for public URI
	if !ua.IsPublicURI(r.URL.Path) {
		// Check if the UA is an evil one
		if ua.IsEvil(rua) {
			// logging active?
			if ua.ShowHits && ua.Logger != nil {
				ua.Logger.Warn("Evil UA", zap.String("ua", rua), zap.String("path", r.URL.Path))
			}
			return serveBomb(w, r, ua.Bomb)
		}

		// logging active?
		if ua.ShowMisses && ua.Logger != nil {
			ua.Logger.Info("Nice UA", zap.String("ua", rua), zap.String("path", r.URL.Path))
		}
	} else if ua.ShowPublic && ua.Logger != nil {
		ua.Logger.Info("Public URI access", zap.String("ua", rua), zap.String("path", r.URL.Path))
	}

	// Nothing happens carry on with next stuff
	return next.ServeHTTP(w, r)
}

func (ua *BotUA) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// expecting argument for Bomb
		if !d.NextArg() {
			return d.Errf("expected argument for Bomb")
		}
		ua.Bomb = d.Val()

		for d.NextBlock(0) {
			switch d.Val() {
			case "contains":
				if !d.NextArg() {
					return d.Errf("expected argument for string to check for")
				}
				ua.Contains = append(ua.Contains, d.Val())
			case "regexp":
				if !d.NextArg() {
					return d.Errf("expected argument for regular expression")
				}
				re, err := regexp.Compile(d.Val())
				if err != nil {
					return d.Errf("invalid regular expression after regexp in line %d: %v", d.Line(), err)
				}
				ua.Re = append(ua.Re, re)
			case "public":
				if !d.NextArg() {
					return d.Errf("expected argument for public directory")
				}
				re, err := regexp.Compile(d.Val())
				if err != nil {
					return d.Errf("invalid regular expression after regexp in line %d: %v", d.Line(), err)
				}
				ua.Public = append(ua.Public, re)
			case "showHits":
				ua.ShowHits = true
			case "showMisses":
				ua.ShowMisses = true
			case "showPublic":
				ua.ShowPublic = true
			default:
				ua.Uas = append(ua.Uas, d.Val())
			}
		}
	}

	return nil
}

// parseCaddyfileForNoBots unmarshals tokens from h into a new Middleware.
func parseCaddyfileForNoBots(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m BotUA
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// serveBomb delivers the bomb to front-end
func serveBomb(w http.ResponseWriter, _ *http.Request, bomb string) error {
	var cbytes []byte
	var err error
	if bombs.Exists(bomb) {
		cbytes, err = bombs.Bombs.ReadFile(bomb + `.gzip`)
	} else {
		cbytes, err = os.ReadFile(bomb)
	}
	if err != nil {
		return http.ErrMissingFile
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(cbytes)))
	_, err = w.Write(cbytes)
	return err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*BotUA)(nil)
	_ caddyhttp.MiddlewareHandler = (*BotUA)(nil)
	_ caddyfile.Unmarshaler       = (*BotUA)(nil)
)
