package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/armon/circbuf"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/gorilla/securecookie"
	"github.com/julienschmidt/httprouter"
	stripe "github.com/stripe/stripe-go"
	"golang.org/x/crypto/acme/autocert"
)

var (
	// Flags
	cli = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// app data directory
	datadir string

	// The version is set by the build command
	version string

	// show version
	showVersion bool

	// show help
	showHelp bool

	// debug logging
	debug bool

	// Let's Encrypt
	letsencrypt bool

	// logger
	logger  *zap.SugaredLogger
	logtail *logtailer

	// HTTP read limit
	httpReadLimit int64 = 2 * (1024 * 1024)

	// database
	database *Database

	// mailer
	mailer *Mailer

	// securetoken
	securetoken *securecookie.SecureCookie

	// Error page HTML
	errorPageHTML = `<html><head><title>Error Page</title></head><body><h1>Error. Please try again.</h1></body></html>`

	thumbnailFilename string
	bannerFilename    string

	// backlink
	backlink string

	// httpd
	httpAddr   string
	httpHost   string
	httpPrefix string

	// set based on httpAddr
	httpIP   string
	httpPort string
)

func NewLogtailer(size int64) (*logtailer, error) {
	buf, err := circbuf.NewBuffer(size)
	if err != nil {
		return nil, err
	}
	return &logtailer{tail: buf}, nil
}

type logtailer struct {
	sync.RWMutex

	tail *circbuf.Buffer
}

func (l *logtailer) Lines() []string {
	l.RLock()
	buf := l.tail.Bytes()
	l.RUnlock()

	s := string(buf)
	start := 0
	if nl := strings.Index(s, "\n"); nl != -1 {
		start = nl + len("\n")
	}
	return strings.Split(s[start:], "\n")
}

func (l *logtailer) Write(buf []byte) (int, error) {
	l.Lock()
	n, err := l.tail.Write(buf)
	l.Unlock()
	return n, err
}

func (l *logtailer) Sync() error {
	return nil
}

func init() {
	cli.StringVar(&datadir, "datadir", "/data", "data dir")
	cli.StringVar(&backlink, "backlink", "", "backlink (optional)")
	cli.BoolVar(&showVersion, "version", false, "display version and exit")
	cli.BoolVar(&showHelp, "help", false, "display help and exit")
	cli.BoolVar(&debug, "debug", false, "debug mode")
	cli.BoolVar(&letsencrypt, "letsencrypt", false, "enable TLS using Let's Encrypt on port 443")
	cli.StringVar(&httpAddr, "http-addr", ":80", "HTTP listen address")
	cli.StringVar(&httpHost, "http-host", "", "HTTP host (required)")
}

//
// main
//

func main() {
	var err error
	cli.Parse(os.Args[1:])
	usage := func(msg string) {
		if msg != "" {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", msg)
		}
		fmt.Fprintf(os.Stderr, "Usage: %s [...]\n", os.Args[0])
		cli.PrintDefaults()
	}
	thumbnailFilename = filepath.Join(datadir, "thumbnail")
	bannerFilename = filepath.Join(datadir, "banner")

	if showHelp {
		usage("Help info")
		os.Exit(0)
	}

	if showVersion {
		fmt.Printf("cloudpatron %s\n", version)
		os.Exit(0)
	}

	logtail, err = NewLogtailer(200 * 1024)
	if err != nil {
		panic(err)
	}

	// logger
	atomlevel := zap.NewAtomicLevel()
	l := zap.New(
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
			zapcore.NewMultiWriteSyncer(zapcore.Lock(zapcore.AddSync(os.Stdout)), logtail),
			atomlevel,
		),
	)
	defer l.Sync()
	logger = l.Sugar()

	// debug logging
	if debug {
		atomlevel.SetLevel(zap.DebugLevel)
	}
	logger.Debugf("debug logging is enabled")

	if httpHost == "" {
		usage("missing HTTP host")
		os.Exit(1)
	}

	// http port
	httpIP, httpPort, err := net.SplitHostPort(httpAddr)
	if err != nil {
		usage("invalid --http-addr: " + err.Error())
	}

	// Create datadir if it doesn't exist.
	if _, err := os.Stat(datadir); err != nil {
		if err := os.MkdirAll(datadir, 0750); err != nil {
			logger.Fatalf("failed to create datadir %q: %s", datadir, err)
		}
	}

	// Database
	database, err = NewDatabase("database.json")
	if err != nil {
		logger.Fatal(err)
	}

	// Mailer
	mailer = NewMailer()

	// Secure token
	securetoken = securecookie.New([]byte(database.FindInfo().SecureToken.HashKey), []byte(database.FindInfo().SecureToken.BlockKey))

	// Stripe
	stripe.Key = database.FindInfo().Stripe.SecretKey

	// Paymaster
	go paymaster()

	//
	// Routes
	//
	r := &httprouter.Router{}
	r.GET("/", Log(WebHandler(indexHandler, "index")))
	r.GET("/posts", Log(WebHandler(postsHandler, "posts")))
	r.GET("/posts/:post", Log(WebHandler(postsHandler, "posts")))

	r.GET("/thumbnail", WebHandler(thumbnailHandler, "thumbnail"))
	r.GET("/banner", WebHandler(bannerHandler, "banner"))

	r.GET("/signup", Log(WebHandler(signupHandler, "signup")))
	r.POST("/signup", Log(WebHandler(signupHandler, "signup")))

	r.GET("/signin", Log(WebHandler(signinHandler, "signin")))
	r.POST("/signin", Log(WebHandler(signinHandler, "signin")))

	r.GET("/forgot", Log(WebHandler(forgotHandler, "forgot")))
	r.POST("/forgot", Log(WebHandler(forgotHandler, "forgot")))

	r.GET("/signout", Log(WebHandler(signoutHandler, "signout")))

	// Patron
	r.GET("/patron", Log(WebHandler(patronIndexHandler, "patron/index")))
	r.GET("/patron/support", Log(WebHandler(patronSupportHandler, "patron/support")))
	r.POST("/patron/support", Log(WebHandler(patronSupportHandler, "patron/support")))
	r.GET("/patron/payments", Log(WebHandler(patronPaymentsHandler, "patron/payments")))
	r.POST("/patron/edit", Log(WebHandler(patronEditHandler, "patron/edit")))
	r.POST("/patron/password", Log(WebHandler(patronPasswordHandler, "patron/password")))
	r.POST("/patron/addcard", Log(WebHandler(patronAddcardHandler, "patron/addcard")))

	// Admin
	r.GET("/admin/configure", Log(WebHandler(adminConfigureHandler, "admin/configure")))
	r.POST("/admin/configure", Log(WebHandler(adminConfigureHandler, "admin/configure")))

	r.GET("/admin", Log(WebHandler(adminIndexHandler, "admin/index")))

	r.POST("/admin/edit", Log(WebHandler(adminEditHandler, "admin/edit")))
	r.POST("/admin/password", Log(WebHandler(adminPasswordHandler, "admin/password")))

	// Patrons
	r.GET("/admin/patrons", Log(WebHandler(adminPatronsIndexHandler, "admin/patrons/index")))
	r.GET("/admin/patrons/export", Log(WebHandler(adminPatronsExportHandler, "admin/patrons/export")))
	r.GET("/admin/patrons/view/:patron", Log(WebHandler(adminPatronsViewHandler, "admin/patrons/view")))

	// Posts
	r.GET("/admin/posts", Log(WebHandler(adminPostsIndexHandler, "admin/posts/index")))
	r.POST("/admin/posts/create", Log(WebHandler(adminPostsCreateHandler, "admin/posts/create")))
	r.POST("/admin/posts/delete", Log(WebHandler(adminPostsDeleteHandler, "admin/posts/delete")))
	r.GET("/admin/posts/edit/:post", Log(WebHandler(adminPostsEditHandler, "admin/posts/edit")))
	r.POST("/admin/posts/edit", Log(WebHandler(adminPostsEditHandler, "admin/posts/edit")))

	// Levels
	r.GET("/admin/levels", Log(WebHandler(adminLevelsIndexHandler, "admin/levels/index")))
	r.POST("/admin/levels/create", Log(WebHandler(adminLevelsCreateHandler, "admin/levels/create")))
	r.POST("/admin/levels/delete", Log(WebHandler(adminLevelsDeleteHandler, "admin/levels/delete")))
	r.GET("/admin/levels/edit/:level", Log(WebHandler(adminLevelsEditHandler, "admin/levels/edit")))
	r.POST("/admin/levels/edit", Log(WebHandler(adminLevelsEditHandler, "admin/levels/edit")))

	// Goals
	r.GET("/admin/goals", Log(WebHandler(adminGoalsIndexHandler, "admin/goals/index")))
	r.POST("/admin/goals/create", Log(WebHandler(adminGoalsCreateHandler, "admin/goals/create")))
	r.POST("/admin/goals/delete", Log(WebHandler(adminGoalsDeleteHandler, "admin/goals/delete")))
	r.GET("/admin/goals/edit/:goal", Log(WebHandler(adminGoalsEditHandler, "admin/goals/edit")))
	r.POST("/admin/goals/edit", Log(WebHandler(adminGoalsEditHandler, "admin/goals/edit")))

	// Assets
	r.GET("/static/*path", staticHandler)

	//
	// Server
	//
	httpTimeout := 1 * time.Hour
	maxHeaderBytes := 10 * (1024 * 1024) // 10 MB

	// Plain text web server for use behind a reverse proxy.
	if !letsencrypt {
		httpd := &http.Server{
			Handler:        r,
			Addr:           net.JoinHostPort(httpIP, httpPort),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		hostport := net.JoinHostPort(httpHost, httpPort)
		if httpPort == "80" {
			hostport = httpHost
		}
		logger.Infof("CloudPatron version: %s %s", version, &url.URL{
			Scheme: "http",
			Host:   hostport,
			Path:   httpPrefix,
		})
		logger.Fatal(httpd.ListenAndServe())
	}

	// Let's Encrypt TLS mode

	// autocert
	certmanager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(datadir, "letsencrypt")),
		HostPolicy: func(_ context.Context, host string) error {
			host = strings.TrimPrefix(host, "www.")
			if host == httpHost {
				return nil
			}
			if host == database.FindInfo().Domain {
				return nil
			}
			return fmt.Errorf("acme/autocert: host %q not permitted by HostPolicy", host)
		},
	}

	// http redirect to https and Let's Encrypt auth
	go func() {
		redir := httprouter.New()
		redir.GET("/*path", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			r.URL.Scheme = "https"
			r.URL.Host = net.JoinHostPort(httpHost, httpPort)
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		})

		httpd := &http.Server{
			Handler:        certmanager.HTTPHandler(redir),
			Addr:           net.JoinHostPort(httpIP, "80"),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		if err := httpd.ListenAndServe(); err != nil {
			logger.Fatalf("http server on port 80 failed: %s", err)
		}
	}()
	// TLS
	tlsConfig := tls.Config{
		GetCertificate: certmanager.GetCertificate,
		NextProtos:     []string{"http/1.1"},
		Rand:           rand.Reader,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Override default for TLS.
	if httpPort == "80" {
		httpPort = "443"
		httpAddr = net.JoinHostPort(httpIP, httpPort)
	}

	httpsd := &http.Server{
		Handler:        r,
		Addr:           httpAddr,
		WriteTimeout:   httpTimeout,
		ReadTimeout:    httpTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}

	// Enable TCP keep alives on the TLS connection.
	tcpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		logger.Fatalf("listen failed: %s", err)
		return
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{tcpListener.(*net.TCPListener)}, &tlsConfig)

	hostport := net.JoinHostPort(httpHost, httpPort)
	if httpPort == "443" {
		hostport = httpHost
	}
	logger.Infof("CloudPatron version: %s %s", version, &url.URL{
		Scheme: "https",
		Host:   hostport,
		Path:   httpPrefix + "/",
	})
	logger.Fatal(httpsd.Serve(tlsListener))
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := l.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(10 * time.Minute)
	return tc, nil
}
