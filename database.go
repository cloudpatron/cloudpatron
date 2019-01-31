package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPatronNotFound       = errors.New("patron not found")
	ErrPatronDuplicateID    = errors.New("patron id already in use")
	ErrPatronDuplicateEmail = errors.New("patron email is already in use")

	ErrGoalNotFound       = errors.New("goal not found")
	ErrGoalDuplicateID    = errors.New("goal id already in use")
	ErrGoalDuplicateEmail = errors.New("goal email is already in use")

	ErrLevelNotFound       = errors.New("level not found")
	ErrLevelDuplicateID    = errors.New("level id already in use")
	ErrLevelDuplicateEmail = errors.New("level email is already in use")

	ErrPostNotFound       = errors.New("post not found")
	ErrPostDuplicateID    = errors.New("post id already in use")
	ErrPostDuplicateEmail = errors.New("post email is already in use")

	ErrVideoNotFound       = errors.New("video not found")
	ErrVideoDuplicateID    = errors.New("video id already in use")
	ErrVideoDuplicateEmail = errors.New("video email is already in use")

	ErrPaymentNotFound       = errors.New("payment not found")
	ErrPaymentDuplicateID    = errors.New("payment id already in use")
	ErrPaymentDuplicateEmail = errors.New("payment email is already in use")
)

//
// Info
//

type Info struct {
	Email       string `json:"email"`
	Password    []byte `json:"password"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Domain      string `json:"domain"`
	Secret      string `json:"secret"`
	Configured  bool   `json:"configured"`
	Completed   bool   `json:"completed"`

	Social struct {
		YoutubeURL   string `json:"youtube_url"`
		GithubURL    string `json:"github_url"`
		TwitterURL   string `json:"twitter_url"`
		FacebookURL  string `json:"facebook_url"`
		InstagramURL string `json:"instagram_url"`
	} `json:"social"`

	Stripe struct {
		PublishableKey string `json:"publishable_key"`
		SecretKey      string `json:"secret_key"`
	} `json:"stripe"`

	SecureToken struct {
		HashKey  string `json:"hash_key"`
		BlockKey string `json:"block_key"`
	} `json:"secure_token"`

	Mail struct {
		From     string `json:"from"`
		Server   string `json:"server"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"mail"`
}

func (db *Database) FindInfo() Info {
	db.RLock("FindInfo")
	defer db.RUnlock("FindInfo")
	if db.Info == nil {
		return Info{}
	}
	info := *db.Info
	copy(db.Info.Password, info.Password)
	return info
}

func (db *Database) UpdateInfo(fn func(*Info) error) error {
	db.Lock("UpdateInfo")
	defer db.Unlock("UpdateInfo")
	return fn(db.Info)
}

//
// Database
//
func NewDatabase(filename string) (*Database, error) {
	filename = filepath.Join(datadir, filename)
	db := &Database{
		filename: filename,
	}
	// Create new database.
	if _, err := os.Stat(filename); err != nil {
		db.Info = &Info{}
		if db.Info.SecureToken.HashKey == "" {
			db.Info.SecureToken.HashKey = GenerateRandom(32)
		}
		if db.Info.SecureToken.BlockKey == "" {
			db.Info.SecureToken.BlockKey = GenerateRandom(32)
		}

		if err := db.Save(); err != nil {
			return nil, err
		}
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, db); err != nil {
		return nil, err
	}
	go db.manager()
	return db, nil
}

type Database struct {
	mu       sync.RWMutex
	filename string

	Info     *Info      `json:"info"`
	Patrons  []*Patron  `json:"patrons"`
	Levels   []*Level   `json:"levels"`
	Goals    []*Goal    `json:"goals"`
	Posts    []*Post    `json:"posts"`
	Videos   []*Video   `json:"videos"`
	Payments []*Payment `json:"payments"`
}

func (db *Database) Lock(loc string) {
	//logger.Debugf("database Lock %s", loc)
	db.mu.Lock()
}

func (db *Database) Unlock(loc string) {
	//logger.Debugf("database Unlock %s", loc)
	db.mu.Unlock()
}

func (db *Database) RLock(loc string) {
	//logger.Debugf("database RLock %s", loc)
	db.mu.RLock()
}

func (db *Database) RUnlock(loc string) {
	//logger.Debugf("database RUnlock %s", loc)
	db.mu.RUnlock()
}

func (db *Database) MonthlyRevenue() uint64 {
	db.RLock("MonthlyRevenue")
	defer db.RUnlock("MonthlyRevenue")

	var revenue uint64
	for _, p := range database.listActivePatrons() {
		revenue += p.Amount
	}
	return revenue
}

func (db *Database) Save() error {
	db.RLock("Save")
	defer db.RUnlock("Save")
	b, err := json.MarshalIndent(db, "", "    ")
	if err != nil {
		return err
	}
	return Overwrite(db.filename, b, 0600)
}

func (db *Database) manager() {
	for {
		time.Sleep(1 * time.Second)
		if err := db.Save(); err != nil {
			logger.Fatal(err)
		}
	}
}

//
// Payment
//

type Payment struct {
	ID       string    `json:"id"`
	PatronID string    `json:"patron_id"`
	Amount   uint64    `json:"amount"`
	Attempts int       `json:"attempts"`
	Paid     bool      `json:"paid"`
	Created  time.Time `json:"created"`

	Patron Patron `json:"-"`
}

func (db *Database) ListPaymentsByPatron(patron string) []Payment {
	db.RLock("ListPaymentsByPatron")
	defer db.RUnlock("ListPaymentsByPatron")
	var payments []Payment
	for _, p := range db.listPaymentsByPatron(patron) {
		payment := *p
		if patron, err := db.findPatron(p.PatronID); err == nil {
			payment.Patron = *patron
		}
		payments = append(payments, payment)
	}
	return payments
}

func (db *Database) listPaymentsByPatron(patron string) []*Payment {
	var payments []*Payment
	if patron == "" {
		return payments
	}
	for _, p := range db.Payments {
		if p.PatronID == patron {
			payments = append(payments, p)
		}
	}
	sort.Slice(payments, func(i, j int) bool { return payments[i].Created.After(payments[j].Created) })
	return payments
}

func (db *Database) ListPayments() []Payment {
	db.RLock("ListPayments")
	defer db.RUnlock("ListPayments")
	var payments []Payment
	for _, p := range db.Payments {
		payment := *p
		if patron, err := db.findPatron(p.PatronID); err == nil {
			payment.Patron = *patron
		}
		payments = append(payments, payment)
	}
	sort.Slice(payments, func(i, j int) bool { return payments[i].Created.After(payments[j].Created) })
	return payments
}

func (db *Database) AddPayment(patronID string, amount uint64) (Payment, error) {
	db.Lock("AddPayment")
	defer db.Unlock("AddPayment")

	paymentID, err := GenerateID("pa")
	if err != nil {
		return Payment{}, err
	}
	if _, err := db.findPayment(paymentID); err != ErrPaymentNotFound {
		return Payment{}, ErrPaymentDuplicateID
	}

	payment := Payment{
		ID:       paymentID,
		PatronID: patronID,
		Amount:   amount,
		Created:  time.Now(),
	}

	db.Payments = append(db.Payments, &payment)
	return payment, nil
}

func (db *Database) DeletePayment(id string) {
	db.Lock("DeletePayment")
	defer db.Unlock("DeletePayment")
	var payments []*Payment
	for _, p := range db.Payments {
		if p.ID == id {
			continue
		}
		payments = append(payments, p)
	}
	db.Payments = payments
}

func (db *Database) FindPayment(id string) (Payment, error) {
	db.RLock("FindPayment")
	defer db.RUnlock("FindPayment")
	p, err := db.findPayment(id)
	if err != nil {
		return Payment{}, err
	}
	return *p, nil
}

func (db *Database) findPayment(id string) (*Payment, error) {
	for _, t := range db.Payments {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, ErrPaymentNotFound
}

func (db *Database) UpdatePayment(id string, fn func(*Payment) error) error {
	db.Lock("UpdatePayment")
	defer db.Unlock("UpdatePayment")
	p, err := db.findPayment(id)
	if err != nil {
		return err
	}
	return fn(p)
}

//
// Patron
//

type Patron struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  []byte    `json:"password"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Moniker   string    `json:"moniker"`
	IPAddress string    `json:"ip_address"`
	Referrer  string    `json:"referrer"`
	UserAgent string    `json:"user_agent"`
	Timezone  string    `json:"time_zone"`
	Secret    string    `json:"secret"`
	Verified  bool      `json:"verified"`
	Canceled  bool      `json:"canceled"`
	Amount    uint64    `json:"amount"`
	Stripe    string    `json:"stripe"`
	Modified  time.Time `json:"modified"`
	Created   time.Time `json:"created"`

	Level Level `json:"-"`
}

func (p Patron) IsActive() bool {
	if p.ID == "" {
		return false
	}
	return !p.Canceled && p.Amount > 0 && p.Stripe != ""
}

func (db *Database) PatronIDAvailable(id string) bool {
	db.RLock("PatronIDAvailable")
	defer db.RUnlock("PatronIDAvailable")
	return db.patronIDAvailable(id)
}

func (db *Database) patronIDAvailable(id string) bool {
	for _, p := range db.Patrons {
		if id == p.ID {
			return false
		}
	}
	return true
}

func (db *Database) PatronEmailAvailable(email string) bool {
	db.RLock("PatronEmailAvailable")
	defer db.RUnlock("PatronEmailAvailable")
	for _, p := range db.Patrons {
		if !p.Verified {
			continue
		}
		if email == p.Email {
			return false
		}
	}
	return true
}

func (db *Database) ListActivePatrons() []Patron {
	db.RLock("ListActivePatrons")
	defer db.RUnlock("ListActivePatrons")
	var patrons []Patron
	for _, p := range db.listActivePatrons() {
		patrons = append(patrons, *p)
	}
	return patrons
}

func (db *Database) listActivePatrons() []*Patron {
	var patrons []*Patron
	for _, p := range db.Patrons {
		if p.Canceled || p.Amount == 0 || p.Stripe == "" {
			continue
		}
		patrons = append(patrons, p)
	}
	sort.Slice(patrons, func(i, j int) bool { return patrons[i].Created.After(patrons[j].Created) })
	return patrons
}

func (db *Database) ListPatrons() []Patron {
	db.RLock("ListPatrons")
	defer db.RUnlock("ListPatrons")
	var patrons []Patron
	for _, p := range db.Patrons {
		patrons = append(patrons, *p)
	}
	sort.Slice(patrons, func(i, j int) bool { return patrons[i].Created.After(patrons[j].Created) })
	return patrons
}

func (db *Database) AddPatron(email, password, firstName, lastName, ipAddress, referrer, userAgent, timezone string) (Patron, error) {
	db.Lock("AddPatron")
	defer db.Unlock("AddPatron")

	if _, err := db.findPatronByEmail(email); err == nil {
		return Patron{}, ErrPatronDuplicateEmail
	}
	secret, err := GenerateID("se")
	if err != nil {
		return Patron{}, err
	}
	patronID, err := GenerateID("pa")
	if err != nil {
		return Patron{}, err
	}
	if _, err := db.findPatron(patronID); err != ErrPatronNotFound {
		return Patron{}, ErrPatronDuplicateID
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return Patron{}, err
	}

	moniker, _ := GenerateNumericID()
	moniker = "patron" + moniker

	patron := Patron{
		ID:        patronID,
		FirstName: firstName,
		LastName:  lastName,
		Moniker:   moniker,
		Password:  hashedPassword,
		Email:     email,
		IPAddress: ipAddress,
		Referrer:  referrer,
		UserAgent: userAgent,
		Timezone:  timezone,
		Verified:  true,
		Secret:    secret,
		Modified:  time.Now(),
		Created:   time.Now(),
	}

	db.Patrons = append(db.Patrons, &patron)
	return patron, nil
}

func (db *Database) DeletePatron(id string) {
	db.Lock("DeletePatron")
	defer db.Unlock("DeletePatron")
	var patrons []*Patron
	for _, p := range db.Patrons {
		if p.ID == id {
			continue
		}
		patrons = append(patrons, p)
	}
	db.Patrons = patrons
}

func (db *Database) FindPatron(id string) (Patron, error) {
	db.RLock("FindPatron")
	defer db.RUnlock("FindPatron")
	p, err := db.findPatron(id)
	if err != nil {
		return Patron{}, err
	}
	return *p, nil
}

func (db *Database) findPatron(id string) (*Patron, error) {
	for _, p := range db.Patrons {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, ErrPatronNotFound
}

func (db *Database) FindPatronByEmail(email string) (Patron, error) {
	db.RLock("FindPatronByEmail")
	defer db.RUnlock("FindPatronByEmail")
	p, err := db.findPatronByEmail(email)
	if err != nil {
		return Patron{}, err
	}
	return *p, nil
}

func (db *Database) findPatronByEmail(email string) (*Patron, error) {
	if email == "" {
		return nil, ErrPatronNotFound
	}
	for _, p := range db.Patrons {
		if p.Email == email {
			return p, nil
		}
	}
	return nil, ErrPatronNotFound
}

func (db *Database) UpdatePatron(id string, fn func(*Patron) error) error {
	db.Lock("UpdatePatron")
	defer db.Unlock("UpdatePatron")
	p, err := db.findPatron(id)
	if err != nil {
		return err
	}
	p.Modified = time.Now()
	return fn(p)
}

//
// Goal
//

type Goal struct {
	ID          string    `json:"id"`
	Target      uint64    `json:"target"`
	Description string    `json:"description"`
	Created     time.Time `json:"created"`
}

func (db *Database) ListGoals() []Goal {
	db.RLock("ListGoals")
	defer db.RUnlock("ListGoals")
	var goals []Goal
	for _, g := range db.Goals {
		goals = append(goals, *g)
	}
	sort.Slice(goals, func(i, j int) bool { return goals[i].Target < goals[j].Target })
	return goals
}

func (db *Database) AddGoal(target uint64, description string) (Goal, error) {
	db.Lock("AddGoal")
	defer db.Unlock("AddGoal")

	goalID, err := GenerateID("go")
	if err != nil {
		return Goal{}, err
	}
	if _, err := db.findGoal(goalID); err != ErrGoalNotFound {
		return Goal{}, ErrGoalDuplicateID
	}

	goal := Goal{
		ID:          goalID,
		Description: description,
		Target:      target,
		Created:     time.Now(),
	}

	db.Goals = append(db.Goals, &goal)
	return goal, nil
}

func (db *Database) DeleteGoal(id string) {
	db.Lock("DeleteGoal")
	defer db.Unlock("DeleteGoal")
	var goals []*Goal
	for _, g := range db.Goals {
		if g.ID == id {
			continue
		}
		goals = append(goals, g)
	}
	db.Goals = goals
}

func (db *Database) FindGoal(id string) (Goal, error) {
	db.RLock("FindGoal")
	defer db.RUnlock("FindGoal")
	g, err := db.findGoal(id)
	if err != nil {
		return Goal{}, err
	}
	return *g, nil
}

func (db *Database) findGoal(id string) (*Goal, error) {
	for _, g := range db.Goals {
		if g.ID == id {
			return g, nil
		}
	}
	return nil, ErrGoalNotFound
}

func (db *Database) UpdateGoal(id string, fn func(*Goal) error) error {
	db.Lock("UpdateGoal")
	defer db.Unlock("UpdateGoal")
	g, err := db.findGoal(id)
	if err != nil {
		return err
	}
	return fn(g)
}

//
// Level
//

type Level struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Amount      uint64    `json:"amount"`
	Created     time.Time `json:"created"`
}

func (db *Database) ListLevels() []Level {
	db.RLock("ListLevels")
	defer db.RUnlock("ListLevels")
	var levels []Level
	for _, t := range db.Levels {
		levels = append(levels, *t)
	}
	sort.Slice(levels, func(i, j int) bool { return levels[i].Amount < levels[j].Amount })
	return levels
}

func (db *Database) AddLevel(name string, amount uint64) (Level, error) {
	db.Lock("AddLevel")
	defer db.Unlock("AddLevel")

	levelID, err := GenerateID("ti")
	if err != nil {
		return Level{}, err
	}
	if _, err := db.findLevel(levelID); err != ErrLevelNotFound {
		return Level{}, ErrLevelDuplicateID
	}

	level := Level{
		ID:      levelID,
		Name:    name,
		Amount:  amount,
		Created: time.Now(),
	}

	db.Levels = append(db.Levels, &level)
	return level, nil
}

func (db *Database) DeleteLevel(id string) {
	db.Lock("DeleteLevel")
	defer db.Unlock("DeleteLevel")
	var levels []*Level
	for _, t := range db.Levels {
		if t.ID == id {
			continue
		}
		levels = append(levels, t)
	}
	db.Levels = levels
}

func (db *Database) FindLevel(id string) (Level, error) {
	db.RLock("FindLevel")
	defer db.RUnlock("FindLevel")
	t, err := db.findLevel(id)
	if err != nil {
		return Level{}, err
	}
	return *t, nil
}

func (db *Database) findLevel(id string) (*Level, error) {
	for _, t := range db.Levels {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, ErrLevelNotFound
}

func (db *Database) UpdateLevel(id string, fn func(*Level) error) error {
	db.Lock("UpdateLevel")
	defer db.Unlock("UpdateLevel")
	t, err := db.findLevel(id)
	if err != nil {
		return err
	}
	return fn(t)
}

//
// Post
//

type Post struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Body     string    `json:"body"`
	VideoURL string    `json:"video_url"`
	VideoID  string    `json:"video_id"`
	Tags     string    `json:"tags"`
	Pinned   bool      `json:"pinned"`
	Unlocked bool      `json:"unlocked"`
	Created  time.Time `json:"created"`

	Video Video `json:"-"`
}

func (db *Database) ListPosts() []Post {
	db.RLock("ListPosts")
	defer db.RUnlock("ListPosts")
	var posts []Post
	for _, p := range db.Posts {
		post := *p
		if v, err := db.findVideo(p.VideoID); err == nil {
			post.Video = *v
		}
		posts = append(posts, post)
	}
	sort.Slice(posts, func(i, j int) bool {
		if posts[i].Pinned && !posts[j].Pinned {
			return true
		}
		if posts[j].Pinned && !posts[i].Pinned {
			return false
		}
		return posts[i].Created.After(posts[j].Created)
	})
	return posts
}

func (db *Database) AddPost(title, body string) (Post, error) {
	db.Lock("AddPost")
	defer db.Unlock("AddPost")

	postID, err := GenerateID("po")
	if err != nil {
		return Post{}, err
	}
	if _, err := db.findPost(postID); err != ErrPostNotFound {
		return Post{}, ErrPostDuplicateID
	}

	post := Post{
		ID:      postID,
		Title:   title,
		Body:    body,
		Created: time.Now(),
	}

	db.Posts = append(db.Posts, &post)
	return post, nil
}

func (db *Database) DeletePost(id string) {
	db.Lock("DeletePost")
	defer db.Unlock("DeletePost")
	var posts []*Post
	for _, p := range db.Posts {
		if p.ID == id {
			continue
		}
		posts = append(posts, p)
	}
	db.Posts = posts
}

func (db *Database) FindPost(id string) (Post, error) {
	db.RLock("FindPost")
	defer db.RUnlock("FindPost")
	p, err := db.findPost(id)
	if err != nil {
		return Post{}, err
	}
	if v, err := db.findVideo(p.VideoID); err == nil {
		p.Video = *v
	}
	return *p, nil
}

func (db *Database) findPost(id string) (*Post, error) {
	for _, p := range db.Posts {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, ErrPostNotFound
}

func (db *Database) PinnedPost(id string) {
	db.Lock("PinnedPost")
	defer db.Unlock("PinnedPost")
	for _, p := range db.Posts {
		if p.ID == id {
			p.Pinned = true
		} else {
			p.Pinned = false
		}
	}
}

func (db *Database) UpdatePost(id string, fn func(*Post) error) error {
	db.Lock("UpdatePost")
	defer db.Unlock("UpdatePost")
	t, err := db.findPost(id)
	if err != nil {
		return err
	}
	return fn(t)
}

//
// Post
//

type Video struct {
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Body    string    `json:"body"`
	VideoID string    `json:"video_id"`
	Tags    string    `json:"tags"`
	Created time.Time `json:"created"`
}

func (db *Database) ListVideos() []Video {
	db.RLock("ListVideos")
	defer db.RUnlock("ListVideos")
	var videos []Video
	for _, v := range db.Videos {
		videos = append(videos, *v)
	}
	sort.Slice(videos, func(i, j int) bool { return videos[i].Created.After(videos[j].Created) })
	return videos
}

func (db *Database) AddVideo(title, body string) (Video, error) {
	db.Lock("AddVideo")
	defer db.Unlock("AddVideo")

	videoID, err := GenerateID("vi")
	if err != nil {
		return Video{}, err
	}
	if _, err := db.findVideo(videoID); err != ErrVideoNotFound {
		return Video{}, ErrVideoDuplicateID
	}

	video := Video{
		ID:      videoID,
		Title:   title,
		Body:    body,
		Created: time.Now(),
	}

	db.Videos = append(db.Videos, &video)
	return video, nil
}

func (db *Database) DeleteVideo(id string) {
	db.Lock("DeleteVideo")
	defer db.Unlock("DeleteVideo")
	var videos []*Video
	for _, v := range db.Videos {
		if v.ID == id {
			continue
		}
		videos = append(videos, v)
	}
	db.Videos = videos
}

func (db *Database) FindVideo(id string) (Video, error) {
	db.RLock("FindVideo")
	defer db.RUnlock("FindVideo")
	t, err := db.findVideo(id)
	if err != nil {
		return Video{}, err
	}
	return *t, nil
}

func (db *Database) findVideo(id string) (*Video, error) {
	for _, v := range db.Videos {
		if v.ID == id {
			return v, nil
		}
	}
	return nil, ErrVideoNotFound
}

func (db *Database) UpdateVideo(id string, fn func(*Video) error) error {
	db.Lock("UpdateVideo")
	defer db.Unlock("UpdateVideo")
	t, err := db.findVideo(id)
	if err != nil {
		return err
	}
	return fn(t)
}
