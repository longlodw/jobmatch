package main

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"

	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// simple JSON response structure
type apiResponse struct {
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
	Data   any    `json:"data,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, data any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		zap.L().Error("api error", zap.Int("status", status), zap.String("error", err.Error()))
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(apiResponse{Status: status, Error: err.Error()})
		return
	}
	zap.L().Info("api success", zap.Int("status", status))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiResponse{Status: status, Data: data})
}

func verifyAndGetUserID(r *http.Request, googleOAuth IOAuth) (string, error) {
	authH := r.Header.Get("Authorization")
	var token string
	if len(authH) > 7 && strings.ToLower(authH[:7]) == "bearer " {
		token = strings.TrimSpace(authH[7:])
	} else {
		token = r.URL.Query().Get("idToken")
	}
	if token == "" {
		return "", &argError{msg: "missing id token"}
	}
	idTok, err := googleOAuth.VerifyIDToken(r.Context(), token)
	if err != nil {
		return "", &argError{msg: "invalid id token"}
	}
	return idTok.Subject, nil
}

// helper to render error fragment consistently
func fragmentError(w http.ResponseWriter, tmpl *template.Template, status int, msg string) {
	zap.L().Error("fragment error", zap.Int("status", status), zap.String("message", msg))
	w.WriteHeader(status)
	_ = tmpl.ExecuteTemplate(w, "error_fragment", struct{ Message string }{Message: msg})
}

// getIDTokenSubject retrieves idToken cookie and verifies it, returning subject.
// It logs failures and distinguishes missing/invalid cookie uniformly as unauthorized.
func getIDTokenSubject(r *http.Request, oauth IOAuth, logger *zap.Logger) (string, int, error) {
	c, err := r.Cookie("idToken")
	if err != nil {
		logger.Info("idToken cookie retrieval failed", zap.Error(err))
		return "", http.StatusUnauthorized, errors.New("unauthorized")
	}
	if c == nil || c.Value == "" {
		logger.Info("idToken cookie missing or empty")
		return "", http.StatusUnauthorized, errors.New("unauthorized")
	}
	idTok, verr := oauth.VerifyIDToken(r.Context(), c.Value)
	if verr != nil {
		logger.Info("idToken verification failed", zap.Error(verr))
		return "", http.StatusUnauthorized, errors.New("unauthorized")
	}
	return idTok.Subject, http.StatusOK, nil
}

// dynamic errors
func errMissing(field string) error { return &argError{msg: "missing " + field} }

type argError struct{ msg string }

func (e *argError) Error() string { return e.msg }

// requireAuth wraps an htmx fragment handler requiring auth, injecting uid in context.
func requireAuth(logger *zap.Logger, oauth IOAuth, tmpl *template.Template, handler func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, st, err := getIDTokenSubject(r, oauth, logger)
		if err != nil {
			fragmentError(w, tmpl, st, err.Error())
			return
		}
		handler(w, r, uid)
	}
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("failed to init logger: " + err.Error())
	}
	zap.ReplaceGlobals(logger)
	defer logger.Sync()

	// Load environment configuration (fail fast on required values)
	getEnv := func(key string) string {
		val := os.Getenv(key)
		if val == "" {
			logger.Fatal("missing env var", zap.String("key", key))
		}
		return val
	}

	clientID := getEnv("GOOGLE_CLIENT_ID")
	clientSecret := getEnv("GOOGLE_CLIENT_SECRET")
	webLoginRedirectURL := getEnv("WEB_LOGIN_REDIRECT_URL")
	apiLoginRedirectURL := getEnv("API_LOGIN_REDIRECT_URL")
	apiDriveRedirectURL := getEnv("API_DRIVE_REDIRECT_URL")
	webDriveRedirectURL := getEnv("WEB_DRIVE_REDIRECT_URL")
	pgConnStr := getEnv("PG_CONN_STR")
	pgSecret := getEnv("PG_SECRET")
	minioEndpoint := getEnv("MINIO_ENDPOINT")
	minioAccessKey := getEnv("MINIO_ACCESS_KEY")
	minioSecretKey := getEnv("MINIO_SECRET_KEY")
	minioBucket := getEnv("MINIO_BUCKET")
	jobFetcherURL := getEnv("JOB_FETCHER_URL")
	jobFetcherToken := getEnv("JOB_FETCHER_TOKEN")
	embedBaseURL := getEnv("OPENAI_BASE_URL")
	embedAPIKey := getEnv("OPENAI_API_KEY")
	rootFolderName := os.Getenv("ROOT_FOLDER_NAME")
	if rootFolderName == "" { // default
		rootFolderName = "JobMatch Applications"
	}
	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = ":8080"
	}

	secureCookies = os.Getenv("COOKIE_SECURE") == "1"
	ctx := context.Background()

	webLoginOAuth, err := NewGoogleOAuth(ctx, clientID, clientSecret, webLoginRedirectURL)
	if err != nil {
		logger.Fatal("failed to init google oauth (web)", zap.Error(err))
	}
	apiLoginOAuth, err := NewGoogleOAuth(ctx, clientID, clientSecret, apiLoginRedirectURL)
	if err != nil {
		logger.Fatal("failed to init google oauth (api)", zap.Error(err))
	}
	driveOAuth, err := NewGoogleOAuth(ctx, clientID, clientSecret, apiDriveRedirectURL)
	if err != nil {
		logger.Fatal("failed to init google oauth (drive api)", zap.Error(err))
	}
	driveWebOAuth, err := NewGoogleOAuth(ctx, clientID, clientSecret, webDriveRedirectURL)
	if err != nil {
		logger.Fatal("failed to init google oauth (drive web)", zap.Error(err))
	}

	storage, err := NewStorage(ctx, pgConnStr, pgSecret, minioEndpoint, minioAccessKey, minioSecretKey, minioBucket, false)
	if err != nil {
		logger.Fatal("failed to init storage", zap.Error(err))
	}
	defer storage.Close()

	jobFetcher := NewJobFetcher(jobFetcherURL, jobFetcherToken)
	embedder := NewEmbeder(embedBaseURL, embedAPIKey)

	webService := NewService(webLoginOAuth, driveWebOAuth, storage, jobFetcher, embedder, rootFolderName, logger)
	apiService := NewService(apiLoginOAuth, driveOAuth, storage, jobFetcher, embedder, rootFolderName, logger)

	// parse templates (include all fragments)
	tmpl, err := template.ParseFiles(
		filepath.Join("templates", "base.html"),
		filepath.Join("templates", "home.html"),
		filepath.Join("templates", "jobs.html"),
		filepath.Join("templates", "job_details.html"),
		filepath.Join("templates", "note_edit.html"),
		filepath.Join("templates", "note_fragment.html"),
		filepath.Join("templates", "drive_authorize.html"),
		filepath.Join("templates", "resumes.html"),
		filepath.Join("templates", "settings.html"),
		filepath.Join("templates", "partials_error.html"),
		filepath.Join("templates", "partials_success.html"),
	)
	if err != nil {
		logger.Fatal("template parse error", zap.Error(err))
	}

	mux := http.NewServeMux()
	rootHandler := mux

	// static assets
	mux.HandleFunc("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("assets", "style.css"))
	})

	// home page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// attempt to get user via idToken cookie (optional for home)
		uid, _, _ := getIDTokenSubject(r, webLoginOAuth, logger)
		// create or reuse CSRF token (prevent rotation desync across tabs)
		var csrfToken string
		if existing, _ := r.Cookie("csrf"); existing != nil && existing.Value != "" {
			csrfToken = existing.Value
		} else {
			if tok, err := generateCSRFToken(); err == nil {
				csrfToken = tok
				setCSRFCookie(w, csrfToken)
			}
		}
		data := struct {
			Authenticated bool
			Year          int
			Error         string
			CSRF          string
		}{Authenticated: uid != "", Year: time.Now().Year(), CSRF: csrfToken}
		if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// login initiate (redirect user)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		authURL, st, err := webService.Login(r.Context())
		if err != nil {
			http.Error(w, err.Error(), st)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	// login callback sets idToken cookie then redirect home
	mux.HandleFunc("/login/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		idToken, st, err := webService.LoginCallback(r.Context(), state, code)
		if err != nil {
			http.Error(w, err.Error(), st)
			return
		}
		secure := os.Getenv("COOKIE_SECURE") == "1"
		http.SetCookie(w, &http.Cookie{Name: "idToken", Value: idToken, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// logout
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if !validateCSRF(r) {
				http.Error(w, "bad csrf", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "idToken", Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1})
			w.Header().Set("HX-Redirect", "/")
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// jobs fragment (htmx)
	mux.HandleFunc("/jobs", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		status := r.URL.Query().Get("status")
		jobs, st2, err := webService.GetJobs(r.Context(), uid, 0, status)
		if err != nil {
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		data := struct{ Jobs any }{Jobs: jobs}
		if err := tmpl.ExecuteTemplate(w, "jobs", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// job details fragment
	mux.HandleFunc("/job/details", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		jobID := r.URL.Query().Get("id")
		if jobID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing id")
			return
		}
		content, st2, err := webService.GetJobDetails(r.Context(), uid, jobID)
		if err != nil {
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		data := struct{ JobID, Content string }{JobID: jobID, Content: content}
		if err := tmpl.ExecuteTemplate(w, "job_details", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// close details fragment
	mux.HandleFunc("/job/details/close", func(w http.ResponseWriter, r *http.Request) {
		// simply remove panel
		w.WriteHeader(http.StatusOK)
	})

	// edit note fragment
	mux.HandleFunc("/job/note/edit", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		jobID := r.URL.Query().Get("jobID")
		if jobID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing jobID")
			return
		}
		job, st2, err := webService.GetJob(r.Context(), uid, jobID)
		if err != nil {
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		data := struct{ JobID, Current string }{JobID: jobID, Current: ""}
		if job.note.Valid {
			data.Current = job.note.String
		}
		if err := tmpl.ExecuteTemplate(w, "note_edit", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// cancel note edit
	mux.HandleFunc("/job/note/cancel", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		jobID := r.URL.Query().Get("jobID")
		if jobID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing jobID")
			return
		}
		job, st2, err := webService.GetJob(r.Context(), uid, jobID)
		if err != nil {
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		noteText := "No notes yet"
		if job.note.Valid {
			noteText = job.note.String
		}
		data := struct{ JobID, Note string }{JobID: jobID, Note: noteText}
		if err := tmpl.ExecuteTemplate(w, "note_fragment", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// save note (htmx)
	mux.HandleFunc("/job/note/save", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if r.Method != http.MethodPost {
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		if err := r.ParseForm(); err != nil {
			fragmentError(w, tmpl, http.StatusBadRequest, "bad form")
			return
		}
		jobID := r.Form.Get("jobID")
		note := r.Form.Get("note")
		if jobID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing jobID")
			return
		}
		if st2, err := webService.UpdateJobNote(r.Context(), uid, jobID, note); err != nil {
			logger.Error("update job note failed", zap.Error(err), zap.String("jobID", jobID), zap.String("uid", uid))
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		logger.Info("job note updated", zap.String("jobID", jobID), zap.String("uid", uid))
		if note == "" {
			note = "No notes yet"
		}
		data := struct{ JobID, Note string }{JobID: jobID, Note: note}
		if err := tmpl.ExecuteTemplate(w, "note_fragment", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// update job status (htmx)
	mux.HandleFunc("/job/status", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if r.Method != http.MethodPost {
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		if err := r.ParseForm(); err != nil {
			fragmentError(w, tmpl, http.StatusBadRequest, "bad form")
			return
		}
		jobID := r.Form.Get("jobID")
		status := r.Form.Get("status")
		if jobID == "" || status == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing jobID/status")
			return
		}
		if st2, err := webService.UpdateJobStatus(r.Context(), uid, jobID, status); err != nil {
			logger.Error("update job status failed", zap.Error(err), zap.String("jobID", jobID), zap.String("uid", uid), zap.String("status", status))
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		logger.Info("job status updated", zap.String("jobID", jobID), zap.String("uid", uid), zap.String("status", status))
		job, st3, err := webService.GetJob(r.Context(), uid, jobID)
		if err != nil {
			fragmentError(w, tmpl, st3, err.Error())
			return
		}
		if err := tmpl.ExecuteTemplate(w, "job_card", job); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
	}))

	// resumes fragment
	mux.HandleFunc("/resumes", func(w http.ResponseWriter, r *http.Request) {
		uid, _, _ := getIDTokenSubject(r, webLoginOAuth, logger) // optional
		var resumes any
		if uid != "" {
			res, _, err := webService.GetResumes(r.Context(), uid, 0)
			if err != nil {
				fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
				return
			}
			resumes = res
		}
		data := struct {
			Authenticated bool
			Resumes       any
		}{Authenticated: uid != "", Resumes: resumes}
		if err := tmpl.ExecuteTemplate(w, "resumes", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// upload resume (htmx target)
	mux.HandleFunc("/resumes/upload", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if r.Method != http.MethodPost {
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		if err := r.ParseForm(); err != nil {
			fragmentError(w, tmpl, http.StatusBadRequest, "bad form")
			return
		}
		fileID := r.Form.Get("fileID")
		if fileID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing fileID")
			return
		}
		if _, err := webService.UploadResume(r.Context(), uid, fileID); err != nil {
			logger.Error("resume upload failed", zap.Error(err), zap.String("fileID", fileID), zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		logger.Info("resume uploaded", zap.String("fileID", fileID), zap.String("uid", uid))
		if err := tmpl.ExecuteTemplate(w, "success_fragment", struct{ Message string }{Message: "Resume uploaded."}); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// settings fragment (CSRF required even on GET)
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		uid, _, _ := getIDTokenSubject(r, webLoginOAuth, logger) // optional
		var searchURL string
		if uid != "" {
			url, _, err := webService.GetSearchURL(r.Context(), uid)
			if err == nil {
				searchURL = url
			}
		}
		var driveEnabled bool
		if uid != "" {
			enabled, _, err := webService.HasDriveEnabled(r.Context(), uid)
			if err == nil {
				driveEnabled = enabled
			}
		}
		data := struct {
			Authenticated bool
			SearchURL     string
			DriveEnabled  bool
		}{Authenticated: uid != "", SearchURL: searchURL, DriveEnabled: driveEnabled}
		if err := tmpl.ExecuteTemplate(w, "settings", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// settings save search URL
	mux.HandleFunc("/settings/search", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if r.Method != http.MethodPost {
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		if err := r.ParseForm(); err != nil {
			fragmentError(w, tmpl, http.StatusBadRequest, "bad form")
			return
		}
		searchURL := r.Form.Get("searchURL")
		if searchURL == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing searchURL")
			return
		}
		if st2, err := webService.SetSearchURL(r.Context(), uid, searchURL); err != nil {
			logger.Error("save search URL failed", zap.Error(err), zap.String("uid", uid))
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		logger.Info("search URL saved", zap.String("uid", uid))
		if err := tmpl.ExecuteTemplate(w, "success_fragment", struct{ Message string }{Message: "Search URL saved."}); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// settings enable drive (returns authorize link via template, require CSRF)
	mux.HandleFunc("/settings/drive", requireAuth(logger, webLoginOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		enabled, st2, err := webService.HasDriveEnabled(r.Context(), uid)
		if err != nil {
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		if enabled {
			if err := tmpl.ExecuteTemplate(w, "success_fragment", struct{ Message string }{Message: "Drive already enabled."}); err != nil {
				fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			}
			return
		}
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		authURL, st2, err := webService.EnableDrive(r.Context(), uid)
		if err != nil {
			logger.Error("enable drive failed", zap.Error(err), zap.String("uid", uid))
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		logger.Info("drive enable initiated", zap.String("uid", uid))
		data := struct{ AuthURL string }{AuthURL: authURL}
		if err := tmpl.ExecuteTemplate(w, "drive_authorize", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// drive enable callback (web flow) sets up tokens then redirects to settings
	mux.HandleFunc("/drive/enable/callback", func(w http.ResponseWriter, r *http.Request) {
		uid, st, err := getIDTokenSubject(r, webLoginOAuth, logger)
		if err != nil {
			http.Error(w, err.Error(), st)
			return
		}
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		st2, err := webService.EnableDriveCallback(r.Context(), uid, state, code)
		if err != nil {
			http.Error(w, err.Error(), st2)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		authURL, st, err := apiService.Login(r.Context())
		writeJSON(w, st, map[string]string{"authUrl": authURL}, err)
	})
	mux.HandleFunc("/api/login/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		idToken, st, err := apiService.LoginCallback(r.Context(), state, code)
		writeJSON(w, st, map[string]string{"idToken": idToken}, err)
	})
	mux.HandleFunc("/api/token/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		newToken, st, err := apiService.RefreshToken(r.Context(), uid)
		writeJSON(w, st, map[string]string{"idToken": newToken}, err)
	})
	mux.HandleFunc("/api/drive/enable", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		authURL, st, err := apiService.EnableDrive(r.Context(), uid)
		writeJSON(w, st, map[string]string{"authUrl": authURL}, err)
	})
	mux.HandleFunc("/api/drive/enable/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		st, err := apiService.EnableDriveCallback(r.Context(), uid, state, code)
		writeJSON(w, st, map[string]string{"status": "drive_enabled"}, err)
	})
	mux.HandleFunc("/api/search-url", func(w http.ResponseWriter, r *http.Request) {
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		switch r.Method {
		case http.MethodGet:
			urlStr, st, err := apiService.GetSearchURL(r.Context(), uid)
			writeJSON(w, st, map[string]string{"searchURL": urlStr}, err)
		case http.MethodPost:
			var body struct {
				SearchURL string `json:"searchURL"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.SearchURL == "" {
				writeJSON(w, http.StatusBadRequest, nil, errMissing("searchURL"))
				return
			}
			st, err := apiService.SetSearchURL(r.Context(), uid, body.SearchURL)
			writeJSON(w, st, map[string]string{"status": "updated"}, err)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/resumes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		resumes, st, err := apiService.GetResumes(r.Context(), uid, offset)
		writeJSON(w, st, map[string]any{"resumes": resumes}, err)
	})
	mux.HandleFunc("/api/resume/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		var body struct {
			FileID string `json:"fileID"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.FileID == "" {
			writeJSON(w, http.StatusBadRequest, nil, errMissing("fileID"))
			return
		}
		st, err := apiService.UploadResume(r.Context(), uid, body.FileID)
		writeJSON(w, st, map[string]string{"status": "uploaded"}, err)
	})
	mux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		status := r.URL.Query().Get("status")
		jobs, st, err := apiService.GetJobs(r.Context(), uid, offset, status)
		writeJSON(w, st, map[string]any{"jobs": jobs}, err)
	})
	mux.HandleFunc("/api/job/note", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		var body struct{ JobID, Note string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.JobID == "" {
			writeJSON(w, http.StatusBadRequest, nil, errMissing("jobID"))
			return
		}
		st, err := apiService.UpdateJobNote(r.Context(), uid, body.JobID, body.Note)
		writeJSON(w, st, map[string]string{"status": "updated"}, err)
	})
	mux.HandleFunc("/api/job/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		var body struct{ JobID, Status string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.JobID == "" || body.Status == "" {
			writeJSON(w, http.StatusBadRequest, nil, errMissing("jobID/status"))
			return
		}
		st, err := apiService.UpdateJobStatus(r.Context(), uid, body.JobID, body.Status)
		writeJSON(w, st, map[string]string{"status": "updated"}, err)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// lightweight dependency checks (storage ping?) kept minimal for speed
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/api/job/details", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiLoginOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		jobID := r.URL.Query().Get("jobID")
		if jobID == "" {
			writeJSON(w, http.StatusBadRequest, nil, errMissing("jobID"))
			return
		}
		content, st, err := apiService.GetJobDetails(r.Context(), uid, jobID)
		writeJSON(w, st, map[string]string{"content": content}, err)
	})

	server := &http.Server{Addr: serverAddr, Handler: rootHandler}
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		logger.Info("starting server", zap.String("addr", serverAddr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()
	<-shutdownCh
	logger.Info("shutdown signal received")
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctxShutdown); err != nil {
		logger.Error("graceful shutdown failed", zap.Error(err))
	}
	logger.Info("server stopped")
}
