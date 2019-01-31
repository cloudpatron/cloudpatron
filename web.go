package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	humanize "github.com/dustin/go-humanize"
	httprouter "github.com/julienschmidt/httprouter"
	bluemonday "github.com/microcosm-cc/bluemonday"
	stripe "github.com/stripe/stripe-go"
	blackfriday "gopkg.in/russross/blackfriday.v2"
)

var (
	sessionCookieName                            = "__cloudpatron"
	blackfridayFlags      blackfriday.HTMLFlags  = blackfriday.UseXHTML | blackfriday.HrefTargetBlank | blackfriday.Safelink | blackfriday.SkipHTML | blackfriday.SkipImages
	blackfridayExtensions blackfriday.Extensions = blackfriday.NoIntraEmphasis | blackfriday.Strikethrough | blackfriday.SpaceHeadings | blackfriday.BackslashLineBreak | blackfriday.HardLineBreak | blackfriday.Autolink
	sanitizer                                    = bluemonday.UGCPolicy()
)

type Session struct {
	Admin     bool
	PatronID  string
	NotBefore time.Time
	NotAfter  time.Time
}

func init() {
	gob.Register(Session{})
}

func newSessionCookie(r *http.Request, patronID string, admin bool) (*http.Cookie, error) {
	expires := time.Now().Add(720 * time.Hour)

	session := Session{
		Admin:     admin,
		PatronID:  patronID,
		NotBefore: time.Now(),
		NotAfter:  expires,
	}

	encoded, err := securetoken.Encode(sessionCookieName, session)
	if err != nil {
		return nil, fmt.Errorf("auth: encoding error: %s", err)
	}

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  expires,
	}
	return cookie, nil
}

func newDeletionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	}
}

func validateSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("auth: missing cookie")
	}
	session := &Session{}
	if err := securetoken.Decode(sessionCookieName, cookie.Value, session); err != nil {
		return nil, err
	}
	if time.Now().Before(session.NotBefore) {
		return nil, fmt.Errorf("invalid session (before valid)")
	}
	if time.Now().After(session.NotAfter) {
		return nil, fmt.Errorf("invalid session (expired session.NotAfter is %s and now is %s)", session.NotAfter, time.Now())
	}
	return session, nil
}

type Web struct {
	// Internal
	w        http.ResponseWriter
	r        *http.Request
	ps       httprouter.Params
	template string

	// Default
	HTTPHost string
	Backlink string
	Version  string
	Request  *http.Request
	Section  string
	Time     time.Time

	// Paging
	Limit    int
	Page     int
	LastPage bool

	// Additional
	Admin  bool
	Info   Info
	Amount uint64

	Patron  Patron
	Patrons []Patron

	Post  Post
	Posts []Post

	Level  Level
	Levels []Level

	Goal  Goal
	Goals []Goal

	Payment  Payment
	Payments []Payment

	// Stripe
	StripeCustomer       *stripe.Customer
	StripePaymentSources []*stripe.PaymentSource
}

func (w *Web) JSON() {
	w.w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w.w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(w); err != nil {
		logger.Error(err)
	}
}

func (w *Web) HTML() {
	t := template.New(w.template).Funcs(template.FuncMap{
		"videoembed": func(videoURL string) string {
			u, err := url.Parse(videoURL)
			if err != nil {
				return ""
			}
			videoID := func() string {
				if u.Host == "youtu.be" {
					// https://youtu.be/X0g4AVCVt6g
					return strings.TrimPrefix(u.Path, "/")
				}
				if u.Host == "youtube.com" || u.Host == "www.youtube.com" {
					// https://www.youtube.com/watch?v=X0g4AVCVt6g
					return u.Query().Get("v")
				}
				return ""
			}()
			if videoID == "" {
				return ""
			}
			return "https://www.youtube.com/embed/" + videoID
		},
		"markdown": func(s string) template.HTML {
			r := blackfriday.NewHTMLRenderer(blackfriday.HTMLRendererParameters{Flags: blackfridayFlags})
			h := blackfriday.Run(
				[]byte(s),
				blackfriday.WithNoExtensions(),
				blackfriday.WithExtensions(blackfridayExtensions),
				blackfriday.WithRenderer(r),
			)
			return template.HTML(sanitizer.SanitizeBytes(h))
		},
		"hasprefix": strings.HasPrefix,
		"hassuffix": strings.HasSuffix,
		"toupper":   strings.ToUpper,
		"tolower":   strings.ToLower,
		"amount": func(amount uint64) string {
			return fmt.Sprintf("$%0.2f", float64(amount)/100)
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"add": func(a, b int) int {
			return a + b
		},
		"safe": func(s string) template.HTML {
			return template.HTML(s)
		},
		"percent": func(a, b int64) float64 {
			return (float64(a) / float64(b)) * 100
		},
		"bytes": func(n int64) string {
			return fmt.Sprintf("%.2f GB", float64(n)/1024/1024/1024)
		},
		"nextbillingdate": func() string {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, 1, 0).Add(time.Nanosecond)
			return next.Format("Jan _2, 2006")
		},
		"time": humanize.Time,
		"comma": func(n uint64) string {
			return humanize.Comma(int64(n))
		},
		"commaint": func(n int) string {
			return humanize.Comma(int64(n))
		},
		"tsdate": func(timestamp int64) string {
			return time.Unix(timestamp, 0).Format("Jan _2, 2006")
		},
		"date": func(t time.Time) string {
			return t.Format("Jan _2, 2006")
		},
		"datemy": func(t time.Time) string {
			return t.Format("Jan 2006")
		},
	})

	for _, filename := range AssetNames() {
		if !strings.HasPrefix(filename, "templates/") {
			continue
		}
		name := strings.TrimPrefix(filename, "templates/")
		b, err := Asset(filename)
		if err != nil {
			Error(w.w, err)
			return
		}

		var tmpl *template.Template
		if name == t.Name() {
			tmpl = t
		} else {
			tmpl = t.New(name)
		}
		if _, err := tmpl.Parse(string(b)); err != nil {
			Error(w.w, err)
			return
		}
	}

	w.w.Header().Set("Content-Type", "text/html")
	if err := t.Execute(w.w, w); err != nil {
		Error(w.w, err)
		return
	}
}

func (w *Web) Redirect(format string, a ...interface{}) {
	location := fmt.Sprintf(format, a...)
	logger.Debugf("redirect %q => %q", w.r.RequestURI, location)
	http.Redirect(w.w, w.r, location, http.StatusFound)
}

func WebHandler(h func(*Web), section string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		web := &Web{
			w:        w,
			r:        r,
			ps:       ps,
			template: section + ".html",

			HTTPHost: httpHost,
			Backlink: backlink,
			Time:     time.Now(),
			Version:  version,
			Request:  r,
			Section:  section,
			Info:     database.FindInfo(),
		}
		if session, err := validateSession(r); err == nil {
			if session.Admin {
				web.Admin = true
			} else if patron, err := database.FindPatron(session.PatronID); err == nil {
				web.Patron = patron
			}
		}

		if strings.HasPrefix(section, "patron/") {
			if web.Patron.ID == "" {
				web.Redirect("/signin?error=required")
				return
			}
		} else if strings.HasPrefix(section, "admin/") {
			if web.Admin == false {
				if section == "admin/configure" && !web.Info.Configured {
					// Allow exception
				} else {
					web.Redirect("/signin?error=required")
					return
				}
			}
		}
		h(web)
	}
}

func Log(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		start := time.Now()
		h(w, r, ps)
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		ua := r.Header.Get("User-Agent")
		xff := r.Header.Get("X-Forwarded-For")
		xrealip := r.Header.Get("X-Real-IP")
		rang := r.Header.Get("Range")

		logger.Infof("%s %q %q %q %q %q %q %s %q %d ms", start, ip, xff, xrealip, ua, rang, r.Referer(), r.Method, r.RequestURI, int64(time.Since(start)/time.Millisecond))
	}
}

func Error(w http.ResponseWriter, err error) {
	logger.Error(err)
	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, errorPageHTML+"\n")
}

func staticHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	path := "static" + ps.ByName("path")
	b, err := Asset(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fi, err := AssetInfo(path)
	if err != nil {
		Error(w, err)
		return
	}
	http.ServeContent(w, r, path, fi.ModTime(), bytes.NewReader(b))
}
