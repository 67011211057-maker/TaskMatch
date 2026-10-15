package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var moneyPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,7})(\.[0-9]{1,2})?$`)

type User struct {
	ID                int
	Name, Email, Role string
}

type Category struct {
	ID   int
	Name string
}

type Job struct {
	ID, OwnerID, CategoryID                                                      int
	Title, Description, Price, Deadline, Status, ApprovalStatus, Category, Owner string
	ApplicantCount                                                               int
	ApplicationStatus, AppliedAt, JobStatus                                      string
	Applied                                                                      bool
}

type Application struct {
	ID, JobID, WorkerID     int
	Worker, Status, Created string
}

type AdminMember struct {
	ID                int
	Name, Email, Role string
}

type AdminApplication struct {
	ID, JobID                             int
	JobTitle, WorkerName, Status, Created string
}

type Profile struct {
	UserID                                                         int
	Name, Role, Occupation, Province, District, Phone, Skills, Bio string
}

type View struct {
	Title, Notice, Error, CSRF           string
	User                                 *User
	Jobs                                 []Job
	Job                                  Job
	Categories                           []Category
	Applications                         []Application
	IsOwner, CanApply, CanManage, IsEdit bool
	Counts                               map[string]int
	AdminMembers                         []AdminMember
	AdminApplications                    []AdminApplication
	Profile                              Profile
	IsMyProfile                          bool
	Search                               string
	SelectedCategoryID                   int
}

func main() {
	dsn := os.Getenv("MYSQL_URL")
	if dsn == "" {
		dsn = "root:@tcp(127.0.0.1:3306)/taskmatch?parseTime=true&charset=utf8mb4&loc=UTC"
	}

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Database Connection Error: ", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(3 * time.Minute)

	if err = db.Ping(); err != nil {
		log.Fatal("MySQL Ping Error: ", err)
	}

	mux := http.NewServeMux()

	// User Routes
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/logout", logout)
	mux.HandleFunc("/profile", myProfile)
	mux.HandleFunc("/profile/edit", editProfile)
	mux.HandleFunc("/profiles/", publicProfile)

	// Job & Application Routes
	mux.HandleFunc("/", home)
	mux.HandleFunc("/jobs/new", newJob)
	mux.HandleFunc("/jobs/", jobRoutes)
	mux.HandleFunc("/my/jobs", myJobs)
	mux.HandleFunc("/my/applications", myApplications)

	// Admin Routes
	mux.HandleFunc("/admin", admin)
	mux.HandleFunc("/admin/jobs/", adminJobRoutes)

	// Static Files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	addr := ":8080"
	log.Println("TaskMatch Server is running at http://localhost" + addr)

	server := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func secureCookie(r *http.Request) bool {
	return r.TLS != nil || os.Getenv("TASKMATCH_HTTPS") == "1"
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func tokenHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func csrfToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie("taskmatch_csrf"); err == nil && len(c.Value) == 64 {
		if _, err = hex.DecodeString(c.Value); err == nil {
			return c.Value, nil
		}
	}

	t, err := randomToken()
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "taskmatch_csrf",
		Value:    t,
		Path:     "/",
		MaxAge:   86400,
		Secure:   secureCookie(r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return t, nil
}

func checkPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "ข้อมูลไม่ถูกต้องหรือมีขนาดใหญ่เกินไป", http.StatusBadRequest)
		return false
	}

	c, err := r.Cookie("taskmatch_csrf")
	if err != nil || len(c.Value) != 64 ||
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) != 1 {
		http.Error(w, "คำขอไม่ปลอดภัย กรุณาโหลดหน้าใหม่แล้วลองอีกครั้ง", http.StatusForbidden)
		return false
	}
	return true
}

func currentUser(r *http.Request) (*User, error) {
	c, err := r.Cookie("taskmatch_session")
	if err != nil || len(c.Value) != 64 {
		return nil, nil
	}
	if _, err = hex.DecodeString(c.Value); err != nil {
		return nil, nil
	}

	u := new(User)
	err = db.QueryRowContext(r.Context(),
		`SELECT u.id, u.name, u.email, u.role
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP()`,
		tokenHash(c.Value),
	).Scan(&u.ID, &u.Name, &u.Email, &u.Role)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func requireRole(w http.ResponseWriter, r *http.Request, roles ...string) *User {
	u, err := currentUser(r)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return nil
	}
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	for _, role := range roles {
		if u.Role == role {
			return u
		}
	}
	http.Error(w, "ไม่มีสิทธิ์เข้าถึง", http.StatusForbidden)
	return nil
}

func render(w http.ResponseWriter, r *http.Request, page string, v View) {
	u, err := currentUser(r)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	v.User = u

	v.CSRF, err = csrfToken(w, r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	t, err := template.ParseFiles("templates/layout.html", "templates/"+page+".html")
	if err != nil {
		log.Println("Template error:", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err = t.ExecuteTemplate(w, "layout", v); err != nil {
		log.Println("Render error:", err)
	}
}

func onlyGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func getCategories(r *http.Request) ([]Category, error) {
	rows, err := db.QueryContext(r.Context(), "SELECT id, name FROM categories ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Category{}
	for rows.Next() {
		var c Category
		if err = rows.Scan(&c.ID, &c.Name); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !onlyGet(w, r) {
		return
	}

	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(search) > 100 {
		http.Error(w, "คำค้นหายาวเกิน 100 ตัวอักษร", http.StatusBadRequest)
		return
	}

	categories, err := getCategories(r)
	if err != nil {
		log.Println("Load home categories error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	selectedCategoryID := 0
	categoryParam := strings.TrimSpace(r.URL.Query().Get("category_id"))
	if categoryParam != "" {
		selectedCategoryID, err = strconv.Atoi(categoryParam)
		if err != nil || selectedCategoryID <= 0 {
			http.Error(w, "หมวดหมู่ไม่ถูกต้อง", http.StatusBadRequest)
			return
		}
		found := false
		for _, category := range categories {
			if category.ID == selectedCategoryID {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "ไม่พบหมวดหมู่ที่เลือก", http.StatusBadRequest)
			return
		}
	}

	query := `
        SELECT j.id, j.owner_id, j.category_id, j.title, j.description,
               j.price, j.deadline, j.status, j.approval_status,
               c.name, u.name,
               (SELECT COUNT(*) FROM applications a WHERE a.job_id = j.id)
        FROM jobs j
        JOIN categories c ON c.id = j.category_id
        JOIN users u ON u.id = j.owner_id
        WHERE j.status = 'open' AND j.approval_status = 'approved'`
	args := []any{}

	if search != "" {
		query += " AND (j.title LIKE ? OR j.description LIKE ?)"
		keyword := "%" + search + "%"
		args = append(args, keyword, keyword)
	}
	if selectedCategoryID != 0 {
		query += " AND j.category_id = ?"
		args = append(args, selectedCategoryID)
	}
	query += " ORDER BY j.created_at DESC LIMIT 100"

	rows, err := db.QueryContext(r.Context(), query, args...)
	if err != nil {
		log.Println("Search jobs error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	jobs := []Job{}
	for rows.Next() {
		var j Job
		var date time.Time
		if err = rows.Scan(
			&j.ID, &j.OwnerID, &j.CategoryID, &j.Title, &j.Description,
			&j.Price, &date, &j.Status, &j.ApprovalStatus,
			&j.Category, &j.Owner, &j.ApplicantCount,
		); err != nil {
			log.Println("Scan jobs error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		j.Deadline = date.Format("2006-01-02")
		jobs = append(jobs, j)
	}
	if err = rows.Err(); err != nil {
		log.Println("Search jobs rows error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	render(w, r, "home", View{
		Title:              "ตลาดงาน",
		Jobs:               jobs,
		Search:             search,
		Categories:         categories,
		SelectedCategoryID: selectedCategoryID,
	})
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		render(w, r, "register", View{Title: "สมัครสมาชิก"})
		return
	}
	if !checkPost(w, r) {
		return
	}

	name := strings.TrimSpace(r.PostFormValue("name"))
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	pass := r.PostFormValue("password")
	confirmPass := r.PostFormValue("confirm_password")
	role := r.PostFormValue("role")

	a, err := mail.ParseAddress(email)
	if name == "" || utf8.RuneCountInString(name) > 100 ||
		err != nil || a.Address != email || len(email) > 255 ||
		utf8.RuneCountInString(pass) < 8 || len(pass) > 72 ||
		pass != confirmPass ||
		(role != "customer" && role != "worker") {
		render(w, r, "register", View{
			Title: "สมัครสมาชิก",
			Error: "กรุณาตรวจสอบชื่อ อีเมล รหัสผ่าน 8–72 ไบต์ และประเภทผู้ใช้",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, err = db.ExecContext(r.Context(),
		"INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
		name, email, string(hash), role)
	if err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			render(w, r, "register", View{
				Title: "สมัครสมาชิก", Error: "อีเมลนี้ถูกใช้งานแล้ว",
			})
			return
		}
		log.Println("Register error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login?registered=1", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		v := View{Title: "เข้าสู่ระบบ"}
		if r.URL.Query().Get("registered") == "1" {
			v.Notice = "สมัครสมาชิกสำเร็จ กรุณาเข้าสู่ระบบ"
		}
		render(w, r, "login", v)
		return
	}
	if !checkPost(w, r) {
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	pass := r.PostFormValue("password")

	var id int
	var hash string
	err := db.QueryRowContext(r.Context(),
		"SELECT id,password_hash FROM users WHERE email=?", email,
	).Scan(&id, &hash)

	if errors.Is(err, sql.ErrNoRows) ||
		(err == nil && bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil) {
		render(w, r, "login", View{
			Title: "เข้าสู่ระบบ", Error: "อีเมลหรือรหัสผ่านไม่ถูกต้อง",
		})
		return
	}
	if err != nil {
		log.Println("Login error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	token, err := randomToken()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, err = db.ExecContext(r.Context(),
		`INSERT INTO sessions(user_id,token_hash,expires_at)
         VALUES(?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 24 HOUR))`,
		id, tokenHash(token))
	if err != nil {
		log.Println("Create session error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "taskmatch_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if !checkPost(w, r) {
		return
	}
	if c, err := r.Cookie("taskmatch_session"); err == nil && len(c.Value) == 64 {
		_, _ = db.ExecContext(r.Context(),
			"DELETE FROM sessions WHERE token_hash=?", tokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "taskmatch_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func jobByID(r *http.Request, id int) (Job, error) {
	var j Job
	var date time.Time
	err := db.QueryRowContext(r.Context(), `
        SELECT j.id,j.owner_id,j.category_id,j.title,j.description,j.price,
               j.deadline,j.status,j.approval_status,c.name,u.name,
               (SELECT COUNT(*) FROM applications a WHERE a.job_id=j.id)
        FROM jobs j
        JOIN categories c ON c.id=j.category_id
        JOIN users u ON u.id=j.owner_id
        WHERE j.id=?`, id).Scan(
		&j.ID, &j.OwnerID, &j.CategoryID, &j.Title, &j.Description,
		&j.Price, &date, &j.Status, &j.ApprovalStatus, &j.Category,
		&j.Owner, &j.ApplicantCount,
	)
	if err == nil {
		j.Deadline = date.Format("2006-01-02")
	}
	return j, err
}

func jobIDFromPath(path string) (int, string, bool) {
	s := strings.TrimPrefix(path, "/jobs/")
	parts := strings.Split(s, "/")
	if len(parts) > 2 || len(parts) == 0 {
		return 0, "", false
	}
	id, err := strconv.Atoi(parts[0])
	if err != nil || id <= 0 {
		return 0, "", false
	}
	if len(parts) == 1 {
		return id, "view", true
	}
	return id, parts[1], true
}

func jobRoutes(w http.ResponseWriter, r *http.Request) {
	id, action, ok := jobIDFromPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch action {
	case "view":
		showJob(w, r, id)
	case "edit":
		editJob(w, r, id)
	case "delete":
		deleteJob(w, r, id)
	case "apply":
		applyJob(w, r, id)
	case "accept":
		decideApplication(w, r, id, "accepted")
	case "reject":
		decideApplication(w, r, id, "rejected")
	case "complete":
		completeJob(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func showJob(w http.ResponseWriter, r *http.Request, id int) {
	if !onlyGet(w, r) {
		return
	}

	j, err := jobByID(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	u, err := currentUser(r)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if j.ApprovalStatus != "approved" &&
		(u == nil || (u.ID != j.OwnerID && u.Role != "admin")) {
		http.NotFound(w, r)
		return
	}

	v := View{Title: j.Title, Job: j}
	if u != nil {
		v.IsOwner = u.ID == j.OwnerID
		v.CanManage = v.IsOwner && j.Status != "completed"
		v.CanApply = u.Role == "worker" && j.Status == "open" &&
			j.ApprovalStatus == "approved" && u.ID != j.OwnerID

		if u.Role == "worker" {
			var n int
			err = db.QueryRowContext(r.Context(),
				"SELECT COUNT(*) FROM applications WHERE job_id=? AND worker_id=?",
				id, u.ID).Scan(&n)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			v.Job.Applied = n > 0
		}

		if v.IsOwner || u.Role == "admin" {
			rows, err := db.QueryContext(r.Context(), `
                SELECT a.id,a.job_id,a.worker_id,u.name,a.status,a.created_at
                FROM applications a
                JOIN users u ON u.id=a.worker_id
                WHERE a.job_id=?
                ORDER BY a.created_at DESC`, id)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			for rows.Next() {
				var a Application
				var created time.Time
				if err = rows.Scan(&a.ID, &a.JobID, &a.WorkerID,
					&a.Worker, &a.Status, &created); err != nil {
					http.Error(w, "Database error", http.StatusInternalServerError)
					return
				}
				a.Created = created.Format("2006-01-02 15:04")
				v.Applications = append(v.Applications, a)
			}
			if rows.Err() != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
		}
	}
	render(w, r, "job", v)
}

func jobFormData(r *http.Request) (Job, error) {
	var j Job
	j.Title = strings.TrimSpace(r.PostFormValue("title"))
	j.Description = strings.TrimSpace(r.PostFormValue("description"))
	j.Price = strings.TrimSpace(r.PostFormValue("price"))
	j.Deadline = r.PostFormValue("deadline")

	var err error
	j.CategoryID, err = strconv.Atoi(r.PostFormValue("category_id"))
	if err != nil {
		return j, errors.New("กรุณาเลือกหมวดหมู่")
	}
	if j.Title == "" || utf8.RuneCountInString(j.Title) > 200 ||
		j.Description == "" || len(j.Description) > 10000 ||
		!moneyPattern.MatchString(j.Price) {
		return j, errors.New("กรุณาตรวจสอบชื่อ รายละเอียด และราคา (ไม่เกิน 99,999,999.99 บาท)")
	}

	date, err := time.Parse("2006-01-02", j.Deadline)
	if err != nil || date.Before(time.Now().UTC().Truncate(24*time.Hour)) {
		return j, errors.New("กำหนดส่งงานต้องเป็นวันนี้หรือวันในอนาคต")
	}

	var count int
	err = db.QueryRowContext(r.Context(),
		"SELECT COUNT(*) FROM categories WHERE id=?", j.CategoryID).Scan(&count)
	if err != nil {
		return j, err
	}
	if count != 1 {
		return j, errors.New("หมวดหมู่ไม่ถูกต้อง")
	}
	return j, nil
}

func newJob(w http.ResponseWriter, r *http.Request) {
	u := requireRole(w, r, "customer")
	if u == nil {
		return
	}
	cats, err := getCategories(r)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodGet {
		render(w, r, "jobform", View{Title: "ลงประกาศงาน", Categories: cats})
		return
	}
	if !checkPost(w, r) {
		return
	}

	j, err := jobFormData(r)
	if err != nil {
		render(w, r, "jobform", View{
			Title: "ลงประกาศงาน", Categories: cats, Job: j, Error: err.Error(),
		})
		return
	}

	result, err := db.ExecContext(r.Context(), `
        INSERT INTO jobs(owner_id,category_id,title,description,price,deadline,status)
        VALUES(?,?,?,?,?,?,'open')`,
		u.ID, j.CategoryID, j.Title, j.Description, j.Price, j.Deadline)
	if err != nil {
		log.Println("Create job error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/jobs/%d", id), http.StatusSeeOther)
}

func editJob(w http.ResponseWriter, r *http.Request, id int) {
	u := requireRole(w, r, "customer")
	if u == nil {
		return
	}

	j, err := jobByID(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if j.OwnerID != u.ID {
		http.Error(w, "ไม่มีสิทธิ์", http.StatusForbidden)
		return
	}
	if j.Status != "open" {
		http.Error(w, "แก้ไขได้เฉพาะงานที่ยังเปิดรับสมัคร", http.StatusConflict)
		return
	}

	cats, err := getCategories(r)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodGet {
		render(w, r, "jobform", View{
			Title: "แก้ไขงาน", Categories: cats, Job: j, IsEdit: true,
		})
		return
	}
	if !checkPost(w, r) {
		return
	}

	updated, err := jobFormData(r)
	updated.ID = id
	updated.ApprovalStatus = j.ApprovalStatus
	updated.Status = j.Status
	if err != nil {
		render(w, r, "jobform", View{
			Title: "แก้ไขงาน", Categories: cats, Job: updated,
			IsEdit: true, Error: err.Error(),
		})
		return
	}

	result, err := db.ExecContext(r.Context(), `
        UPDATE jobs
        SET category_id=?,title=?,description=?,price=?,deadline=?,
            approval_status='pending'
        WHERE id=? AND owner_id=? AND status='open'`,
		updated.CategoryID, updated.Title, updated.Description,
		updated.Price, updated.Deadline, id, u.ID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if affected == 0 {
		http.Error(w, "งานนี้ไม่สามารถแก้ไขได้", http.StatusConflict)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/jobs/%d", id), http.StatusSeeOther)
}

func deleteJob(w http.ResponseWriter, r *http.Request, id int) {
	u := requireRole(w, r, "customer")
	if u == nil {
		return
	}
	if !checkPost(w, r) {
		return
	}

	result, err := db.ExecContext(r.Context(),
		"DELETE FROM jobs WHERE id=? AND owner_id=? AND status='open'",
		id, u.ID)
	if err != nil {
		log.Println("Delete job error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if affected == 0 {
		http.Error(w, "ลบได้เฉพาะงานของตนเองที่ยังเปิดรับสมัคร", http.StatusForbidden)
		return
	}
	http.Redirect(w, r, "/my/jobs", http.StatusSeeOther)
}

func applyJob(w http.ResponseWriter, r *http.Request, id int) {
	u := requireRole(w, r, "worker")
	if u == nil {
		return
	}
	if !checkPost(w, r) {
		return
	}

	result, err := db.ExecContext(r.Context(), `
        INSERT INTO applications(job_id,worker_id,status)
        SELECT id,?,'pending'
        FROM jobs
        WHERE id=? AND status='open'
          AND approval_status='approved' AND owner_id<>?`,
		u.ID, id, u.ID)
	if err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			http.Error(w, "คุณสมัครงานนี้ไปแล้ว", http.StatusConflict)
			return
		}
		log.Println("Apply job error:", err)
		http.Error(w, "ไม่สามารถสมัครงานได้", http.StatusConflict)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if affected == 0 {
		http.Error(w, "ไม่พบงานที่เปิดรับสมัครและผ่านอนุมัติ หรือคุณเป็นเจ้าของงานนี้", http.StatusConflict)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/jobs/%d", id), http.StatusSeeOther)
}

func decideApplication(w http.ResponseWriter, r *http.Request, jobID int, decision string) {
	u := requireRole(w, r, "customer")
	if u == nil {
		return
	}
	if decision != "accepted" && decision != "rejected" {
		http.Error(w, "สถานะไม่ถูกต้อง", http.StatusBadRequest)
		return
	}
	if !checkPost(w, r) {
		return
	}

	appID, err := strconv.Atoi(r.PostFormValue("application_id"))
	if err != nil || appID <= 0 {
		http.Error(w, "ข้อมูลใบสมัครไม่ถูกต้อง", http.StatusBadRequest)
		return
	}

	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var owner int
	var status, approvalStatus string
	err = tx.QueryRowContext(r.Context(),
		"SELECT owner_id,status,approval_status FROM jobs WHERE id=? FOR UPDATE", jobID,
	).Scan(&owner, &status, &approvalStatus)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if owner != u.ID {
		http.Error(w, "ไม่มีสิทธิ์", http.StatusForbidden)
		return
	}
	if status != "open" || approvalStatus != "approved" {
		http.Error(w, "งานนี้ยังไม่พร้อมพิจารณาใบสมัคร", http.StatusConflict)
		return
	}

	result, err := tx.ExecContext(r.Context(), `
        UPDATE applications SET status=?
        WHERE id=? AND job_id=? AND status='pending'`,
		decision, appID, jobID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if affected == 0 {
		http.Error(w, "ใบสมัครไม่อยู่ในสถานะรอพิจารณา", http.StatusConflict)
		return
	}

	if decision == "accepted" {
		_, err = tx.ExecContext(r.Context(),
			"UPDATE jobs SET status='assigned' WHERE id=? AND owner_id=? AND status='open'",
			jobID, u.ID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		_, err = tx.ExecContext(r.Context(),
			"UPDATE applications SET status='rejected' WHERE job_id=? AND id<>? AND status='pending'",
			jobID, appID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	if err = tx.Commit(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/jobs/%d", jobID), http.StatusSeeOther)
}

func completeJob(w http.ResponseWriter, r *http.Request, id int) {
	u := requireRole(w, r, "customer")
	if u == nil {
		return
	}
	if !checkPost(w, r) {
		return
	}

	result, err := db.ExecContext(r.Context(), `
        UPDATE jobs SET status='completed'
        WHERE id=? AND owner_id=? AND status='assigned'`,
		id, u.ID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if affected == 0 {
		http.Error(w, "ปิดงานไม่ได้", http.StatusConflict)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/jobs/%d", id), http.StatusSeeOther)
}

func myJobs(w http.ResponseWriter, r *http.Request) {
	u := requireRole(w, r, "customer")
	if u == nil {
		return
	}
	if !onlyGet(w, r) {
		return
	}

	rows, err := db.QueryContext(r.Context(), `
        SELECT j.id, j.title, j.price, j.status, j.approval_status, c.name,
               (SELECT COUNT(*) FROM applications a WHERE a.job_id = j.id)
        FROM jobs j
        JOIN categories c ON c.id = j.category_id
        WHERE j.owner_id = ?
        ORDER BY j.created_at DESC`, u.ID)
	if err != nil {
		log.Println("myJobs query error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	v := View{Title: "งานของฉัน", Jobs: []Job{}}
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Title, &j.Price, &j.Status,
			&j.ApprovalStatus, &j.Category, &j.ApplicantCount); err != nil {
			log.Println("myJobs scan error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		v.Jobs = append(v.Jobs, j)
	}
	if err := rows.Err(); err != nil {
		log.Println("myJobs rows error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	render(w, r, "myjobs", v)
}

func myApplications(w http.ResponseWriter, r *http.Request) {
	u := requireRole(w, r, "worker")
	if u == nil {
		return
	}
	if !onlyGet(w, r) {
		return
	}

	rows, err := db.QueryContext(r.Context(), `
        SELECT j.id, j.title, j.price, j.status, a.status, c.name, a.created_at
        FROM applications a
        JOIN jobs j ON j.id = a.job_id
        JOIN categories c ON c.id = j.category_id
        WHERE a.worker_id = ?
        ORDER BY a.created_at DESC`, u.ID)
	if err != nil {
		log.Println("myApplications query error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	v := View{Title: "งานที่ฉันสมัคร", Jobs: []Job{}}
	for rows.Next() {
		var j Job
		var appliedAt time.Time
		if err := rows.Scan(&j.ID, &j.Title, &j.Price, &j.JobStatus,
			&j.ApplicationStatus, &j.Category, &appliedAt); err != nil {
			log.Println("myApplications scan error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		j.AppliedAt = appliedAt.Format("2006-01-02 15:04")
		// Preserve the previous myjobs.html display until its template is updated.
		j.Status = j.ApplicationStatus
		v.Jobs = append(v.Jobs, j)
	}
	if err := rows.Err(); err != nil {
		log.Println("myApplications rows error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	// Continue using the existing template for now; we will update it next.
	render(w, r, "myjobs", v)
}

func admin(w http.ResponseWriter, r *http.Request) {
	if requireRole(w, r, "admin") == nil {
		return
	}
	if !onlyGet(w, r) {
		return
	}

	v := View{
		Title:  "Admin Dashboard",
		Counts: map[string]int{},
	}

	// 1. ดึงจำนวนนับ
	for _, table := range []string{"users", "jobs", "applications"} {
		var count int
		err := db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM "+table).Scan(&count)
		if err != nil {
			log.Println("Admin count error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		v.Counts[table] = count
	}

	// 2. ดึงรายชื่อผู้ใช้ทั้งหมด
	mRows, err := db.QueryContext(r.Context(), "SELECT id, name, email, role FROM users ORDER BY id DESC")
	if err != nil {
		log.Println("Admin members error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer mRows.Close()

	for mRows.Next() {
		var m AdminMember
		if err := mRows.Scan(&m.ID, &m.Name, &m.Email, &m.Role); err != nil {
			log.Println("Scan member error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		v.AdminMembers = append(v.AdminMembers, m)
	}

	// 3. ดึงรายการงานทั้งหมด
	jRows, err := db.QueryContext(r.Context(), `
		SELECT j.id, j.owner_id, j.category_id, j.title, j.description, j.price,
		       j.deadline, j.status, j.approval_status, c.name, u.name,
		       (SELECT COUNT(*) FROM applications a WHERE a.job_id = j.id)
		FROM jobs j
		JOIN categories c ON c.id = j.category_id
		JOIN users u ON u.id = j.owner_id
		ORDER BY j.created_at DESC`)
	if err != nil {
		log.Println("Admin jobs error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer jRows.Close()

	for jRows.Next() {
		var j Job
		var date time.Time
		if err := jRows.Scan(&j.ID, &j.OwnerID, &j.CategoryID, &j.Title, &j.Description,
			&j.Price, &date, &j.Status, &j.ApprovalStatus, &j.Category, &j.Owner, &j.ApplicantCount); err != nil {
			log.Println("Scan job error:", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		j.Deadline = date.Format("2006-01-02")
		v.Jobs = append(v.Jobs, j)
	}
	if err := jRows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if err := mRows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// ดึงใบสมัครทั้งหมดสำหรับตารางหน้าแอดมิน
	aRows, err := db.QueryContext(r.Context(), `
		SELECT a.id, a.job_id, j.title, u.name, a.status, a.created_at
		FROM applications a
		JOIN jobs j ON j.id = a.job_id
		JOIN users u ON u.id = a.worker_id
		ORDER BY a.created_at DESC`)
	if err != nil {
		log.Println("Admin applications error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer aRows.Close()
	for aRows.Next() {
		var a AdminApplication
		var created time.Time
		if err := aRows.Scan(&a.ID, &a.JobID, &a.JobTitle, &a.WorkerName, &a.Status, &created); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		a.Created = created.Format("2006-01-02 15:04")
		v.AdminApplications = append(v.AdminApplications, a)
	}
	if err := aRows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	render(w, r, "admin", v)
}

func adminJobRoutes(w http.ResponseWriter, r *http.Request) {
	u := requireRole(w, r, "admin")
	if u == nil {
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/jobs/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}

	id, err := strconv.Atoi(parts[0])
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}

	action := parts[1]
	if action != "approve" && action != "reject" {
		http.NotFound(w, r)
		return
	}

	if !checkPost(w, r) {
		return
	}

	status := "approved"
	if action == "reject" {
		status = "rejected"
	}

	// อนุมัติได้เฉพาะงานเปิดรับสมัครที่ยังไม่ได้อนุมัติ
	// ปฏิเสธได้เฉพาะงานเปิดรับสมัครที่ยังไม่ถูกปฏิเสธและไม่มีผู้สมัคร
	query := `UPDATE jobs SET approval_status=?
		WHERE id=? AND status='open' AND approval_status <> ?`
	args := []any{status, id, status}
	if status == "rejected" {
		query += ` AND NOT EXISTS (SELECT 1 FROM applications WHERE job_id=jobs.id)`
	}
	result, err := db.ExecContext(r.Context(), query, args...)
	if err != nil {
		log.Println("Admin approval error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if affected == 0 {
		http.Error(w, "ไม่สามารถเปลี่ยนสถานะอนุมัติของงานนี้ได้", http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func getProfileByUserID(r *http.Request, userID int) (Profile, error) {
	var p Profile
	err := db.QueryRowContext(r.Context(), `
		SELECT u.id, u.name, u.role,
		       COALESCE(p.occupation, ''), COALESCE(p.province, ''),
		       COALESCE(p.district, ''), COALESCE(p.phone, ''),
		       COALESCE(p.skills, ''), COALESCE(p.bio, '')
		FROM users u
		LEFT JOIN profiles p ON p.user_id = u.id
		WHERE u.id = ?`, userID).Scan(
		&p.UserID, &p.Name, &p.Role, &p.Occupation,
		&p.Province, &p.District, &p.Phone, &p.Skills, &p.Bio,
	)
	if err != nil {
		log.Println("getProfileByUserID error:", err)
	}
	return p, err
}

func myProfile(w http.ResponseWriter, r *http.Request) {
	u := requireRole(w, r, "customer", "worker", "admin")
	if u == nil {
		return
	}
	if !onlyGet(w, r) {
		return
	}

	p, err := getProfileByUserID(r, u.ID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	render(w, r, "profile", View{
		Title:       "โปรไฟล์ของฉัน",
		Profile:     p,
		IsMyProfile: true,
	})
}

func editProfile(w http.ResponseWriter, r *http.Request) {
	u := requireRole(w, r, "customer", "worker", "admin")
	if u == nil {
		return
	}

	if r.Method == http.MethodGet {
		p, err := getProfileByUserID(r, u.ID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		render(w, r, "profile_edit", View{
			Title:   "แก้ไขโปรไฟล์",
			Profile: p,
		})
		return
	}

	if !checkPost(w, r) {
		return
	}

	occupation := strings.TrimSpace(r.PostFormValue("occupation"))
	province := strings.TrimSpace(r.PostFormValue("province"))
	district := strings.TrimSpace(r.PostFormValue("district"))
	phone := strings.TrimSpace(r.PostFormValue("phone"))
	skills := strings.TrimSpace(r.PostFormValue("skills"))
	bio := strings.TrimSpace(r.PostFormValue("bio"))

	// ทักษะเป็นข้อมูลเฉพาะผู้รับงาน ตรวจสอบที่เซิร์ฟเวอร์ด้วย
	if u.Role != "worker" {
		skills = ""
	}

	// จำกัดความยาวให้ตรงกับแบบฟอร์ม และป้องกันข้อมูลเกินขนาด
	if utf8.RuneCountInString(occupation) > 150 ||
		utf8.RuneCountInString(province) > 100 ||
		utf8.RuneCountInString(district) > 100 ||
		utf8.RuneCountInString(phone) > 20 ||
		utf8.RuneCountInString(skills) > 255 ||
		utf8.RuneCountInString(bio) > 1000 {
		http.Error(w, "ข้อมูลโปรไฟล์ยาวเกินที่กำหนด", http.StatusBadRequest)
		return
	}

	_, err := db.ExecContext(r.Context(), `
        INSERT INTO profiles(user_id, occupation, province, district, phone, skills, bio)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            occupation=VALUES(occupation),
            province=VALUES(province),
            district=VALUES(district),
            phone=VALUES(phone),
            skills=VALUES(skills),
            bio=VALUES(bio)`,
		u.ID, occupation, province, district, phone, skills, bio,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func publicProfile(w http.ResponseWriter, r *http.Request) {
	if !onlyGet(w, r) {
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/profiles/")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}

	p, err := getProfileByUserID(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	u, err := currentUser(r)
	if err != nil {
		log.Println("publicProfile currentUser error:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	isMy := u != nil && u.ID == p.UserID
	if !isMy {
		// ไม่ส่งข้อมูลส่วนตัวให้เทมเพลตสำหรับผู้ชมคนอื่น
		p.Phone = ""
	}

	render(w, r, "profile", View{
		Title:       "โปรไฟล์ - " + p.Name,
		Profile:     p,
		IsMyProfile: isMy,
	})
}
