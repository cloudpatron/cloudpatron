package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	stripe "github.com/stripe/stripe-go"
	"golang.org/x/crypto/bcrypt"

	stripecustomer "github.com/stripe/stripe-go/customer"
)

var (
	validEmail    = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword = regexp.MustCompile(`^[ -~]{6,200}$`)
	validString   = regexp.MustCompile(`^[ -~]{1,200}$`)
)

func indexHandler(w *Web) {
	if !database.FindInfo().Configured {
		w.Redirect("/admin/configure")
		return
	}
	if !database.FindInfo().Completed {
		w.template = "incomplete.html"
		w.HTML()
		return
	}

	posts := database.ListPosts()
	if len(w.Posts) > 5 {
		posts = posts[:4]
	}

	w.Posts = posts
	w.Patrons = database.ListActivePatrons()
	w.Levels = database.ListLevels()
	w.Goals = database.ListGoals()
	w.HTML()
}

func forgotHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	secret := w.r.FormValue("secret")
	password := w.r.FormValue("password")

	if email != "" && !validEmail.MatchString(email) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if secret != "" && !validString.MatchString(secret) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if email != "" && secret != "" && !validPassword.MatchString(password) {
		w.Redirect("/forgot?error=invalid&email=%s&secret=%s", email, secret)
		return
	}

	// Admin
	if email == database.FindInfo().Email {
		if secret == "" {
			secret := GenerateRandom(32)
			database.UpdateInfo(func(i *Info) error {
				if i.Secret == "" {
					i.Secret = secret
				}
				return nil
			})

			go func() {
				if err := mailer.Forgot(email, secret); err != nil {
					logger.Error(err)
				}
			}()

			w.Redirect("/forgot?success=forgot")
			return
		}

		if secret != database.FindInfo().Secret {
			w.Redirect("/forgot?error=invalid")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			w.Redirect("/forgot?error=bcrypt")
			return
		}
		database.UpdateInfo(func(i *Info) error {
			i.Password = hashedPassword
			i.Secret = ""
			return nil
		})

		sessionCookie, err := newSessionCookie(w.r, "", true)
		if err != nil {
			panic(err)
		}
		http.SetCookie(w.w, sessionCookie)
		logger.Infof("admin %q signed in", email)

		w.Redirect("/admin")
		return
	}

	// Patron
	patron, err := database.FindPatronByEmail(email)
	if err != nil {
		w.Redirect("/forgot?error=invalid")
		return
	}

	if secret == "" {
		secret := GenerateRandom(32)
		database.UpdatePatron(patron.ID, func(p *Patron) error {
			if p.Secret == "" {
				p.Secret = secret
			}
			return nil
		})
		go func() {
			if err := mailer.Forgot(email, secret); err != nil {
				logger.Error(err)
			}
		}()
		w.Redirect("/forgot?success=forgot")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}

	database.UpdatePatron(patron.ID, func(p *Patron) error {
		p.Password = hashedPassword
		p.Secret = ""
		return nil
	})

	sessionCookie, err := newSessionCookie(w.r, patron.ID, false)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	logger.Infof("patron %q signed in", patron.ID)

	w.Redirect("/patron")
}

func postsHandler(w *Web) {
	if !database.FindInfo().Completed {
		w.template = "incomplete.html"
		w.HTML()
		return
	}

	if postID := w.ps.ByName("post"); postID != "" {
		post, err := database.FindPost(postID)
		if err != nil {
			w.Redirect("/")
			return
		}
		w.Posts = append(w.Posts, post)
	} else {
		w.Posts = database.ListPosts()
	}

	w.template = "index.html"
	w.Patrons = database.ListActivePatrons()
	w.Levels = database.ListLevels()
	w.Goals = database.ListGoals()
	w.HTML()
}

func thumbnailHandler(w *Web) {
	if _, err := os.Stat(thumbnailFilename); err != nil {
		w.Redirect("/static/favicon.png")
		return
	}
	http.ServeFile(w.w, w.r, thumbnailFilename)
}

func bannerHandler(w *Web) {
	if _, err := os.Stat(bannerFilename); err != nil {
		w.Redirect("/static/banner.jpg")
		return
	}
	http.ServeFile(w.w, w.r, bannerFilename)
}

func adminPasswordHandler(w *Web) {
	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")

	success := false

	if email != "" {
		if !validEmail.MatchString(email) {
			w.Redirect("/admin?error=invalid")
			return
		}
		if _, err := database.FindPatronByEmail(email); err == nil {
			w.Redirect("/admin?error=email")
			return
		}
		database.UpdateInfo(func(i *Info) error {
			i.Email = email
			return nil
		})
		success = true
	}

	if currentPassword != "" && newPassword != "" {
		if !validPassword.MatchString(newPassword) {
			w.Redirect("/admin?error=invalid")
			return
		}
		if err := bcrypt.CompareHashAndPassword(database.FindInfo().Password, []byte(currentPassword)); err != nil {
			w.Redirect("/admin?error=invalid")
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			w.Redirect("/admin?error=bcrypt")
			return
		}
		database.UpdateInfo(func(i *Info) error {
			i.Password = hashedPassword
			return nil
		})
		success = true
	}

	if success {
		w.Redirect("/admin?success=changes")
		return
	}

	w.Redirect("/admin")
}

func adminConfigureHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	emailConfirm := strings.ToLower(strings.TrimSpace(w.r.FormValue("email_confirm")))
	password := w.r.FormValue("password")

	if !validEmail.MatchString(email) || !validPassword.MatchString(password) || email != emailConfirm {
		w.Redirect("/admin/configure?error=invalid")
		return
	}

	// Default post
	post, _ := database.AddPost("Welcome to my new Cloud Patron page!", "Please support me by becoming a patron.")
	database.UpdatePost(post.ID, func(p *Post) error {
		p.Unlocked = true
		return nil
	})

	// Default levels
	database.AddLevel("Patron 1", 5)
	database.AddLevel("Patron 2", 10)
	database.AddLevel("Patron 3", 15)
	database.AddLevel("Patron 4", 25)
	database.AddLevel("Patron 5", 50)
	database.AddLevel("Patron 6", 100)
	database.AddLevel("Patron 7", 200)
	database.AddLevel("Patron 8", 500)

	// Default goals
	database.AddGoal(100, "Create more")
	database.AddGoal(500, "Create even more")
	database.AddGoal(1000, "Create even more and more")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/admin/configure?error=bcrypt")
		return
	}

	database.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Password = hashedPassword
		i.Configured = true
		return nil
	})

	sessionCookie, err := newSessionCookie(w.r, "", true)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)

	w.Redirect("/admin")
}

//
// Admin Patrons
//

func adminPatronsIndexHandler(w *Web) {
	keywords := strings.Fields(strings.ToLower(strings.TrimSpace(w.r.FormValue("q"))))
	patrons := database.ListPatrons()

	// Search
	if len(keywords) > 0 {
		var filtered []Patron
		for _, p := range patrons {
			var matched bool
			for _, keyword := range keywords {
				if strings.Contains(p.ID, keyword) {
					matched = true
				}
				if strings.Contains(p.Email, keyword) {
					matched = true
				}
				if strings.Contains(p.FirstName, keyword) {
					matched = true
				}
				if strings.Contains(p.LastName, keyword) {
					matched = true
				}
				if strings.Contains(p.IPAddress, keyword) {
					matched = true
				}
				if strings.Contains(p.Stripe, keyword) {
					matched = true
				}
			}

			if !matched {
				continue
			}
			filtered = append(filtered, p)
		}
		patrons = filtered
	}

	limit := 50
	page, _ := strconv.Atoi(strings.TrimSpace(w.r.FormValue("p")))
	if page == 0 {
		page = 1
	}

	lastPage := true
	if len(patrons) > limit {
		lastPage = false

		start := 0
		if page > 1 {
			start = (page - 1) * limit
		}
		end := start + limit
		if end > len(patrons) {
			end = len(patrons)
		}
		patrons = patrons[start:end]
	}

	w.Patrons = patrons
	w.Page = page
	w.Limit = limit
	w.LastPage = lastPage
	w.HTML()
}

func adminPatronsExportHandler(w *Web) {
	now := time.Now()
	filename := fmt.Sprintf("patrons-email-export-%s-%d.csv", now.Format("2006-01-02"), now.Unix())

	w.w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.w.Header().Set("Content-Type", "text/csv")

	cw := csv.NewWriter(w.w)

	record := []string{"Email Address", "First Name", "Last Name"}
	if err := cw.Write(record); err != nil {
		logger.Error(err)
		Error(w.w, err)
		return
	}

	for _, p := range database.ListActivePatrons() {
		record := []string{p.Email, p.FirstName, p.LastName}
		if err := cw.Write(record); err != nil {
			logger.Error(err)
			Error(w.w, err)
			return
		}
	}

	cw.Flush()

	if err := cw.Error(); err != nil {
		logger.Error(err)
		Error(w.w, err)
	}
}

func adminPatronsViewHandler(w *Web) {
	patron, err := database.FindPatron(w.ps.ByName("patron"))
	if err != nil {
		w.Redirect("/admin/patrons?error=missing")
		return
	}
	w.Patron = patron
	w.Payments = database.ListPaymentsByPatron(patron.ID)
	w.HTML()
}

//
// Admin Posts
//

func adminPostsIndexHandler(w *Web) {
	w.Posts = database.ListPosts()
	w.HTML()
}

func adminPostsCreateHandler(w *Web) {
	title := strings.TrimSpace(w.r.FormValue("title"))

	if title == "" {
		title = "Untitled Post"
	}

	post, err := database.AddPost(title, "")
	if err != nil {
		w.Redirect("/admin/posts?error=database")
		return
	}

	w.Redirect("/admin/posts/edit/%s", post.ID)
}

func adminPostsDeleteHandler(w *Web) {
	post, err := database.FindPost(w.r.FormValue("post"))
	if err != nil {
		w.Redirect("/admin/posts?error=notfound")
		return
	}
	database.DeletePost(post.ID)
	w.Redirect("/admin/posts?success=delete")
}

func adminPostsEditHandler(w *Web) {
	postID := w.ps.ByName("post")
	if postID == "" {
		postID = w.r.FormValue("post")
	}
	post, err := database.FindPost(postID)
	if err != nil {
		w.Redirect("/admin/posts")
		return
	}

	if w.r.Method == "GET" {
		w.Post = post
		w.HTML()
		return
	}

	title := strings.TrimSpace(w.r.FormValue("title"))
	body := strings.TrimSpace(w.r.FormValue("body"))
	videoURL := strings.TrimSpace(w.r.FormValue("video_url"))
	pinned := w.r.FormValue("pinned") == "yes"
	unlocked := w.r.FormValue("unlocked") == "yes"

	if title == "" {
		title = "Untitled Post"
	}
	if pinned {
		database.PinnedPost(post.ID)
		// Unlock any pinned post
		unlocked = true
	}
	database.UpdatePost(post.ID, func(p *Post) error {
		p.Title = title
		p.VideoURL = videoURL
		p.Body = body
		p.Unlocked = unlocked
		return nil
	})

	w.Redirect("/admin/posts/edit/%s?success=changes", post.ID)
}

//
// Admin Levels
//

func adminLevelsIndexHandler(w *Web) {
	w.Levels = database.ListLevels()
	w.HTML()
}

func adminLevelsCreateHandler(w *Web) {
	name := strings.TrimSpace(w.r.FormValue("name"))
	if name == "" {
		name = "Unamed Level"
	}

	level, err := database.AddLevel(name, 0)
	if err != nil {
		w.Redirect("/admin/levels?error=database")
		return
	}

	w.Redirect("/admin/levels/edit/%s?success=changes", level.ID)
}

func adminLevelsDeleteHandler(w *Web) {
	level, err := database.FindLevel(w.r.FormValue("level"))
	if err != nil {
		w.Redirect("/admin/levels?error=notfound")
		return
	}
	database.DeleteLevel(level.ID)
	w.Redirect("/admin/levels?success=delete")
}

func adminLevelsEditHandler(w *Web) {
	levelID := w.ps.ByName("level")
	if levelID == "" {
		levelID = w.r.FormValue("level")
	}
	level, err := database.FindLevel(levelID)
	if err != nil {
		w.Redirect("/admin/levels")
		return
	}

	if w.r.Method == "GET" {
		w.Level = level
		w.HTML()
		return
	}

	name := strings.TrimSpace(w.r.FormValue("name"))
	description := strings.TrimSpace(w.r.FormValue("description"))
	amount, _ := strconv.ParseUint(strings.TrimSpace(strings.Replace(w.r.FormValue("amount"), ",", "", -1)), 10, 64)
	if name == "" {
		name = "Unamed Level"
	}

	if amount == 0 {
		amount = 1
	}

	database.UpdateLevel(level.ID, func(p *Level) error {
		p.Name = name
		p.Description = description
		p.Amount = amount
		return nil
	})

	w.Redirect("/admin/levels?success=changes")
}

//
// Admin Goals
//

func adminGoalsIndexHandler(w *Web) {
	w.Goals = database.ListGoals()
	w.HTML()
}

func adminGoalsCreateHandler(w *Web) {
	target, _ := strconv.ParseUint(strings.TrimSpace(w.r.FormValue("target")), 10, 64)

	goal, err := database.AddGoal(target, "")
	if err != nil {
		w.Redirect("/admin/goals?error=database")
		return
	}

	w.Redirect("/admin/goals/edit/%s", goal.ID)
}

func adminGoalsDeleteHandler(w *Web) {
	goal, err := database.FindGoal(w.r.FormValue("goal"))
	if err != nil {
		w.Redirect("/admin/goals?error=notfound")
		return
	}
	database.DeleteGoal(goal.ID)
	w.Redirect("/admin/goals?success=delete")
}

func adminGoalsEditHandler(w *Web) {
	goalID := w.ps.ByName("goal")
	if goalID == "" {
		goalID = w.r.FormValue("goal")
	}
	goal, err := database.FindGoal(goalID)
	if err != nil {
		w.Redirect("/admin/goals")
		return
	}

	if w.r.Method == "GET" {
		w.Goal = goal
		w.HTML()
		return
	}

	target, _ := strconv.ParseUint(strings.TrimSpace(w.r.FormValue("target")), 10, 64)
	description := strings.TrimSpace(w.r.FormValue("description"))

	database.UpdateGoal(goal.ID, func(p *Goal) error {
		p.Target = target
		p.Description = description
		return nil
	})

	w.Redirect("/admin/goals?success=changes")
}

func adminIndexHandler(w *Web) {
	w.Patrons = database.ListActivePatrons()
	w.Posts = database.ListPosts()
	w.Amount = database.MonthlyRevenue()

	w.HTML()
}

func adminEditHandler(w *Web) {
	name := strings.TrimSpace(w.r.FormValue("name"))
	description := strings.TrimSpace(w.r.FormValue("description"))
	facebookURL := strings.TrimSpace(w.r.FormValue("facebook_url"))
	instagramURL := strings.TrimSpace(w.r.FormValue("instagram_url"))
	twitterURL := strings.TrimSpace(w.r.FormValue("twitter_url"))
	youtubeURL := strings.TrimSpace(w.r.FormValue("youtube_url"))
	githubURL := strings.TrimSpace(w.r.FormValue("github_url"))

	mailFrom := strings.TrimSpace(w.r.FormValue("mail_from"))
	mailServer := strings.TrimSpace(w.r.FormValue("mail_server"))
	mailPort, _ := strconv.Atoi(strings.TrimSpace(w.r.FormValue("mail_port")))
	mailUsername := strings.TrimSpace(w.r.FormValue("mail_username"))
	mailPassword := strings.TrimSpace(w.r.FormValue("mail_password"))

	stripePublishableKey := strings.TrimSpace(w.r.FormValue("stripe_publishable_key"))
	stripeSecretKey := strings.TrimSpace(w.r.FormValue("stripe_secret_key"))

	domain := strings.TrimSpace(w.r.FormValue("domain"))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimRight(domain, "/")

	// Thumbnail
	if file, fileHeader, err := w.r.FormFile("thumbnail"); fileHeader != nil && err == nil {
		defer file.Close()

		thumbnail, err := os.Create(thumbnailFilename)
		if err != nil {
			w.Redirect("/admin?error=thumbnail")
			return
		}
		if _, err := io.Copy(thumbnail, file); err != nil {
			w.Redirect("/admin?error=thumbnail")
			return
		}
		if err := thumbnail.Close(); err != nil {
			w.Redirect("/admin?error=thumbnail")
			return
		}
	}

	// Banner
	if file, fileHeader, err := w.r.FormFile("banner"); fileHeader != nil && err == nil {
		defer file.Close()

		banner, err := os.Create(bannerFilename)
		if err != nil {
			w.Redirect("/admin?error=banner")
			return
		}
		if _, err := io.Copy(banner, file); err != nil {
			w.Redirect("/admin?error=banner")
			return
		}
		if err := banner.Close(); err != nil {
			w.Redirect("/admin?error=banner")
			return
		}
	}

	completed := false

	if name != "" && description != "" &&
		stripePublishableKey != "" && stripeSecretKey != "" &&
		mailFrom != "" && mailServer != "" && mailPort != 0 &&
		mailUsername != "" && mailPassword != "" {
		completed = true
	}

	database.UpdateInfo(func(i *Info) error {
		i.Name = name
		i.Description = description

		i.Social.FacebookURL = facebookURL
		i.Social.InstagramURL = instagramURL
		i.Social.TwitterURL = twitterURL
		i.Social.YoutubeURL = youtubeURL
		i.Social.GithubURL = githubURL

		i.Stripe.PublishableKey = stripePublishableKey
		i.Stripe.SecretKey = stripeSecretKey

		i.Mail.From = mailFrom
		i.Mail.Server = mailServer
		i.Mail.Port = mailPort
		i.Mail.Username = mailUsername
		i.Mail.Password = mailPassword

		i.Domain = domain

		i.Completed = completed

		return nil
	})

	// Update the Stripe API key
	stripe.Key = stripeSecretKey

	sessionCookie, err := newSessionCookie(w.r, "", true)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)

	w.Redirect("/admin?success=changes")
}

func patronPaymentsHandler(w *Web) {
	if w.Patron.Amount == 0 && !w.Patron.Canceled {
		w.Redirect("/patron/support")
		return
	}

	w.Payments = database.ListPaymentsByPatron(w.Patron.ID)

	if w.Patron.Stripe != "" {
		customer, err := stripecustomer.Get(w.Patron.Stripe, nil)
		if err != nil {
			logger.Warn(err)
			Error(w.w, fmt.Errorf("stripe data error"))
			return
		}
		w.StripeCustomer = customer
		if customer.Sources != nil {
			for _, source := range customer.Sources.Data {
				w.StripePaymentSources = append(w.StripePaymentSources, source)
			}
		}
	}
	w.HTML()
}

func patronIndexHandler(w *Web) {
	if w.Patron.Amount == 0 && !w.Patron.Canceled {
		w.Redirect("/patron/support")
		return
	}
	w.Levels = database.ListLevels()
	w.HTML()
}

func patronSupportHandler(w *Web) {
	if w.r.Method == "GET" {
		w.Levels = database.ListLevels()
		w.HTML()
		return
	}

	amount, _ := strconv.ParseUint(strings.TrimSpace(w.r.FormValue("amount")), 10, 64)

	// TODO: Check what the lowest level is and enforce that.

	var lowestAmount uint64 = 100000
	for _, level := range database.ListLevels() {
		if level.Amount < lowestAmount {
			lowestAmount = level.Amount
		}
	}
	if amount > 0 && amount < lowestAmount {
		amount = lowestAmount
	}

	if amount > 100000 {
		amount = 100000
	}

	var canceled bool
	if amount == 0 {
		canceled = true
	}

	database.UpdatePatron(w.Patron.ID, func(p *Patron) error {
		p.Amount = amount
		p.Canceled = canceled
		return nil
	})

	if w.Patron.Stripe == "" {
		w.Redirect("/patron/payments")
		return
	}
	w.Redirect("/patron/support?success=changes")
}

func patronEditHandler(w *Web) {
	firstName := strings.TrimSpace(w.r.FormValue("first_name"))
	lastName := strings.TrimSpace(w.r.FormValue("last_name"))
	moniker := strings.TrimSpace(w.r.FormValue("moniker"))
	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))

	if !validEmail.MatchString(email) {
		w.Redirect("/patron?error=invalid")
		return
	}

	if email != w.Patron.Email {
		if _, err := database.FindPatronByEmail(email); err == nil {
			w.Redirect("/patron?error=email")
			return
		}
	}

	database.UpdatePatron(w.Patron.ID, func(p *Patron) error {
		p.FirstName = firstName
		p.LastName = lastName
		p.Moniker = moniker
		p.Email = email
		return nil
	})

	w.Redirect("/patron?success=changes")
}

func patronPasswordHandler(w *Web) {
	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")

	if !validPassword.MatchString(newPassword) {
		w.Redirect("/admin?error=invalid")
		return
	}

	if err := bcrypt.CompareHashAndPassword(w.Patron.Password, []byte(currentPassword)); err != nil {
		w.Redirect("/patron?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/patron?error=bcrypt")
		return
	}

	database.UpdatePatron(w.Patron.ID, func(p *Patron) error {
		p.Password = hashedPassword
		return nil
	})
	w.Redirect("/patron?success=password")
}

func patronAddcardHandler(w *Web) {
	stripeToken := w.r.FormValue("stripeToken")

	var customer *stripe.Customer
	if w.Patron.Stripe == "" {
		customerParams := &stripe.CustomerParams{
			Email: stripe.String(w.Patron.Email),
		}
		customerParams.SetSource(stripeToken)
		var err error
		customer, err = stripecustomer.New(customerParams)
		if err != nil {
			logger.Warn(err)
			w.Redirect("/patron/payments?error=card")
			return
		}
		database.UpdatePatron(w.Patron.ID, func(p *Patron) error {
			p.Stripe = customer.ID
			return nil
		})
	} else {
		// Update card
		customerParams := &stripe.CustomerParams{}
		customerParams.SetSource(stripeToken)
		if _, err := stripecustomer.Update(w.Patron.Stripe, customerParams); err != nil {
			logger.Warn(err)
			w.Redirect("/patron/payments?error=card")
			return
		}
	}
	w.Redirect("/patron/payments?success=changes")
}

func signupHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	firstName := strings.TrimSpace(w.r.FormValue("first_name"))
	lastName := strings.TrimSpace(w.r.FormValue("last_name"))
	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	password := w.r.FormValue("password")

	if firstName != "" && !validString.MatchString(firstName) {
		w.Redirect("/signup?error=invalid")
		return
	}
	if lastName != "" && !validString.MatchString(lastName) {
		w.Redirect("/signup?error=invalid")
		return
	}

	if !validEmail.MatchString(email) || !validPassword.MatchString(password) {
		w.Redirect("/signup?error=invalid")
		return
	}

	if _, err := database.FindPatronByEmail(email); err == nil {
		w.Redirect("/signup?error=exists")
		return
	}

	// Add patron
	patron, err := database.AddPatron(email, password, firstName, lastName, w.r.Header.Get("X-Forwarded-For"), w.r.FormValue("referrer"), w.r.Header.Get("User-Agent"), "UTC")
	if err != nil {
		logger.Errorf("add patron failed: %s", err)
		w.Redirect("/signup?error=matrix")
		return
	}

	// Success, create session cookie.
	sessionCookie, err := newSessionCookie(w.r, patron.ID, false)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)

	w.Redirect("/patron")
}

func signinHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	password := w.r.FormValue("password")

	// Admin sign in
	if email == database.FindInfo().Email {
		if err := bcrypt.CompareHashAndPassword(database.FindInfo().Password, []byte(password)); err != nil {
			w.Redirect("/signin?error=invalid")
			return
		}
		sessionCookie, err := newSessionCookie(w.r, "", true)
		if err != nil {
			panic(err)
		}
		http.SetCookie(w.w, sessionCookie)
		logger.Infof("admin %q signed in", email)

		w.Redirect("/admin")
		return
	}

	// Patron sign in
	patron, err := database.FindPatronByEmail(email)
	if err != nil {
		w.Redirect("/signin?error=invalid")
		return
	}

	if err := bcrypt.CompareHashAndPassword(patron.Password, []byte(password)); err != nil {
		logger.Warnf("patron %q wrong password: %s", patron.ID, err)
		w.Redirect("/signin?error=invalid")
		return
	}

	sessionCookie, err := newSessionCookie(w.r, patron.ID, false)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	logger.Infof("patron %q signed in", patron.ID)

	w.Redirect("/patron")
}

func signoutHandler(w *Web) {
	http.SetCookie(w.w, newDeletionCookie())
	w.Redirect("/")
}
