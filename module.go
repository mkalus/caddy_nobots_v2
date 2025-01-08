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
)

func init() {
	caddy.RegisterModule(BotUA{})
	httpcaddyfile.RegisterHandlerDirective("nobots", parseCaddyfileForNoBots)
}

// BotUA plugin struct, including config
type BotUA struct {
	Logger     *zap.Logger      // Logger instance
	ShowHits   bool             // log UA hits?
	ShowMisses bool             // log UA misses?
	ShowPublic bool             // log access to public directories
	Uas        []string         // user-agents to block
	Bomb       string           // Bomb file or string
	Re         []*regexp.Regexp // regular expressions for user-agents to block
	Public     []*regexp.Regexp // public directories
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
	// In case there are regexp
	for _, re := range ua.Re {
		if re.MatchString(rua) {
			return true
		}
	}
	// In case there are strings
	for _, agent := range ua.Uas {
		if agent == rua {
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
				ua.Logger.Warn("Evil UA", zap.String("ua", rua))
			}
			return serveBomb(w, r, ua.Bomb)
		}

		// logging active?
		if ua.ShowMisses && ua.Logger != nil {
			ua.Logger.Info("Nice UA", zap.String("ua", rua))
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
