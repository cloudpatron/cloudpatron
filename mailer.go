package main

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	humanize "github.com/dustin/go-humanize"
	gomail "gopkg.in/gomail.v2"
)

type Mailer struct{}

func NewMailer() *Mailer {
	return mailer
}

func (m *Mailer) Forgot(email, secret string) error {
	subject := "Password reset link"

	params := struct {
		HTTPHost string
		Email    string
		Secret   string
	}{
		httpHost,
		email,
		secret,
	}
	return m.sendmail("forgot.html", email, subject, params)
}

func (m *Mailer) Contact(message string) error {
	email := "support@example.com"
	subject := "Customer support"

	params := struct {
		Message string
	}{
		message,
	}
	return m.sendmail("contact.html", email, subject, params)
}

func (m *Mailer) sendmail(tmpl, to, subject string, data interface{}) error {
	logger.Infof("sendmail top to %q Subject: %q", to, subject)

	info := database.FindInfo()

	body, err := m.Render(tmpl, data)
	if err != nil {
		return err
	}

	d := gomail.NewDialer(info.Mail.Server, info.Mail.Port, info.Mail.Username, info.Mail.Password)
	s, err := d.Dial()
	if err != nil {
		return err
	}
	emails := []string{to}

	for _, email := range emails {
		logger.Infof("sendmail from %q to %q Subject: %q", info.Mail.From, email, subject)

		msg := gomail.NewMessage()
		msg.SetHeader("From", info.Mail.From)
		msg.SetHeader("To", email)
		msg.SetHeader("Subject", subject)
		msg.SetBody("text/html", body)
		if err := gomail.Send(s, msg); err != nil {
			return fmt.Errorf("failed sending email to %q: %s", to, err)
		}
	}
	return nil
}

func (m *Mailer) Render(target string, data interface{}) (string, error) {
	t := template.New(target).Funcs(template.FuncMap{
		"time": humanize.Time,
		"tokenfmt": func(token string) string {
			return strings.ToUpper(token[0:3] + " " + token[3:6])
		},
	})
	for _, filename := range AssetNames() {
		if !strings.HasPrefix(filename, "email/") {
			continue
		}
		name := strings.TrimPrefix(filename, "email/")
		b, err := Asset(filename)
		if err != nil {
			return "", err
		}

		var tmpl *template.Template
		if name == t.Name() {
			tmpl = t
		} else {
			tmpl = t.New(name)
		}
		if _, err := tmpl.Parse(string(b)); err != nil {
			return "", err
		}
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
