package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
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
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(apiResponse{Status: status, Error: err.Error()})
		return
	}
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
	w.WriteHeader(status)
	_ = tmpl.ExecuteTemplate(w, "error_fragment", struct{ Message string }{Message: msg})
}

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Load environment configuration (fail fast on required values)
	getEnv := func(key string) string {
		val := os.Getenv(key)
		if val == "" {
			log.Fatalf("missing env var: %s", key)
		}
		return val
	}

	clientID := getEnv("GOOGLE_CLIENT_ID")
	clientSecret := getEnv("GOOGLE_CLIENT_SECRET")
	redirectURL := getEnv("GOOGLE_REDIRECT_URL")
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

	ctx := context.Background()

	googleOAuth, err := NewGoogleOAuth(ctx, clientID, clientSecret, redirectURL)
	if err != nil {
		log.Fatalf("failed to init google oauth: %v", err)
	}

	storage, err := NewStorage(ctx, pgConnStr, pgSecret, minioEndpoint, minioAccessKey, minioSecretKey, minioBucket, false)
	if err != nil {
		log.Fatalf("failed to init storage: %v", err)
	}
	defer storage.Close()

	jobFetcher := NewJobFetcher(jobFetcherURL, jobFetcherToken)
	embedder := NewEmbeder(embedBaseURL, embedAPIKey)

	service := NewService(googleOAuth, storage, jobFetcher, embedder, rootFolderName, logger)

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
	)
	if err != nil {
		log.Fatalf("template parse error: %v", err)
	}

	mux := http.NewServeMux()

	// Simple CORS middleware for frontend dev
	cors := func(next http.Handler) http.Handler {
		allowedOrigin := os.Getenv("FRONTEND_ORIGIN")
		if allowedOrigin == "" { // dev default
			allowedOrigin = "http://localhost:5173"
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	rootHandler := cors(mux)

	// static assets
	mux.HandleFunc("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("assets", "style.css"))
	})

	// home page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// check id token cookie
		idTokCookie, _ := r.Cookie("idToken")
		var userID string
		if idTokCookie != nil {
			if tok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value); err == nil {
				userID = tok.Subject
			}
		}
		// create CSRF token for UI (not for API)
		csrfToken, err := generateCSRFToken()
		if err == nil {
			setCSRFCookie(w, csrfToken)
		}
		data := struct {
			Authenticated bool
			Year          int
			Error         string
			CSRF          string
		}{Authenticated: userID != "", Year: time.Now().Year(), CSRF: csrfToken}
		if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// login initiate (redirect user)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		authURL, _, err := service.Login(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	// login callback sets idToken cookie then redirect home
	mux.HandleFunc("/login/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		idToken, _, err := service.LoginCallback(r.Context(), state, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "idToken", Value: idToken, Path: "/", HttpOnly: true, Secure: false, SameSite: http.SameSiteLaxMode})
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
	mux.HandleFunc("/jobs", func(w http.ResponseWriter, r *http.Request) {
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		status := r.URL.Query().Get("status")
		jobs, _, err := service.GetJobs(r.Context(), idTok.Subject, 0, status)
		if err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		data := struct{ Jobs any }{Jobs: jobs}
		if err := tmpl.ExecuteTemplate(w, "jobs", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// job details fragment
	mux.HandleFunc("/job/details", func(w http.ResponseWriter, r *http.Request) {
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		jobID := r.URL.Query().Get("id")
		if jobID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing id")
			return
		}
		content, _, err := service.GetJobDetails(r.Context(), idTok.Subject, jobID)
		if err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		data := struct{ JobID, Content string }{JobID: jobID, Content: content}
		if err := tmpl.ExecuteTemplate(w, "job_details", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// close details fragment
	mux.HandleFunc("/job/details/close", func(w http.ResponseWriter, r *http.Request) {
		// simply remove panel
		w.WriteHeader(http.StatusOK)
	})

	// edit note fragment
	mux.HandleFunc("/job/note/edit", func(w http.ResponseWriter, r *http.Request) {
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		jobID := r.URL.Query().Get("jobID")
		if jobID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing jobID")
			return
		}
		job, err := storage.SelectJob(r.Context(), idTok.Subject, jobID)
		if err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		data := struct{ JobID, Current string }{JobID: jobID, Current: ""}
		if job.note.Valid {
			data.Current = job.note.String
		}
		if err := tmpl.ExecuteTemplate(w, "note_edit", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// cancel note edit returns original note display via template
	mux.HandleFunc("/job/note/cancel", func(w http.ResponseWriter, r *http.Request) {
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		jobID := r.URL.Query().Get("jobID")
		if jobID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing jobID")
			return
		}
		job, err := storage.SelectJob(r.Context(), idTok.Subject, jobID)
		if err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
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
	})

	// save note (htmx)
	mux.HandleFunc("/job/note/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
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
		if _, err := service.UpdateJobNote(r.Context(), idTok.Subject, jobID, note); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		if note == "" {
			note = "No notes yet"
		}
		data := struct{ JobID, Note string }{JobID: jobID, Note: note}
		if err := tmpl.ExecuteTemplate(w, "note_fragment", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// update job status (htmx)
	mux.HandleFunc("/job/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
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
		if _, err := service.UpdateJobStatus(r.Context(), idTok.Subject, jobID, status); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		// re-fetch job for updated fields
		job, err := storage.SelectJob(r.Context(), idTok.Subject, jobID)
		if err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		// reuse single card template
		if err := tmpl.ExecuteTemplate(w, "job_card", job); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
	})

	// resumes fragment
	mux.HandleFunc("/resumes", func(w http.ResponseWriter, r *http.Request) {
		idTokCookie, _ := r.Cookie("idToken")
		var uid string
		if idTokCookie != nil {
			if tok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value); err == nil {
				uid = tok.Subject
			}
		}
		var resumes any
		if uid != "" {
			res, _, err := service.GetResumes(r.Context(), uid, 0)
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

	// upload resume fragment target
	mux.HandleFunc("/resumes/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		if err := r.ParseForm(); err != nil {
			fragmentError(w, tmpl, http.StatusBadRequest, "bad form")
			return
		}
		fileID := r.Form.Get("fileID")
		if fileID == "" {
			fragmentError(w, tmpl, http.StatusBadRequest, "missing fileID")
			return
		}
		if _, err := service.UploadResume(r.Context(), idTok.Subject, fileID); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		w.Write([]byte("Uploaded."))
	})

	// settings fragment (require CSRF token for access as requested)
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		if !validateCSRF(r) { // enforce even on GET htmx request
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		idTokCookie, _ := r.Cookie("idToken")
		var uid, searchURL string
		if idTokCookie != nil {
			if tok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value); err == nil {
				uid = tok.Subject
			}
		}
		if uid != "" {
			url, _, err := service.GetSearchURL(r.Context(), uid)
			if err == nil {
				searchURL = url
			}
		}
		data := struct {
			Authenticated bool
			SearchURL     string
		}{Authenticated: uid != "", SearchURL: searchURL}
		if err := tmpl.ExecuteTemplate(w, "settings", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// settings save search URL
	mux.HandleFunc("/settings/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validateCSRF(r) {
			http.Error(w, "bad csrf", http.StatusForbidden)
			return
		}
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		searchURL := r.Form.Get("searchURL")
		if searchURL == "" {
			http.Error(w, "missing searchURL", http.StatusBadRequest)
			return
		}
		if _, err := service.SetSearchURL(r.Context(), idTok.Subject, searchURL); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Saved."))
	})

	// settings enable drive (returns authorize link via template, require CSRF)
	mux.HandleFunc("/settings/drive", func(w http.ResponseWriter, r *http.Request) {
		if !validateCSRF(r) {
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		idTokCookie, _ := r.Cookie("idToken")
		if idTokCookie == nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		idTok, err := googleOAuth.VerifyIDToken(r.Context(), idTokCookie.Value)
		if err != nil {
			fragmentError(w, tmpl, http.StatusUnauthorized, "unauthorized")
			return
		}
		authURL, _, err := service.EnableDrive(r.Context(), idTok.Subject)
		if err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		data := struct{ AuthURL string }{AuthURL: authURL}
		if err := tmpl.ExecuteTemplate(w, "drive_authorize", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// JSON API endpoints
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		authURL, st, err := service.Login(r.Context())
		writeJSON(w, st, map[string]string{"authUrl": authURL}, err)
	})
	mux.HandleFunc("/api/login/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		idToken, st, err := service.LoginCallback(r.Context(), state, code)
		writeJSON(w, st, map[string]string{"idToken": idToken}, err)
	})
	mux.HandleFunc("/api/token/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		newToken, st, err := service.RefreshToken(r.Context(), uid)
		writeJSON(w, st, map[string]string{"idToken": newToken}, err)
	})
	mux.HandleFunc("/api/drive/enable", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		authURL, st, err := service.EnableDrive(r.Context(), uid)
		writeJSON(w, st, map[string]string{"authUrl": authURL}, err)
	})
	mux.HandleFunc("/api/drive/enable/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		st, err := service.EnableDriveCallback(r.Context(), uid, state, code)
		writeJSON(w, st, map[string]string{"status": "drive_enabled"}, err)
	})
	mux.HandleFunc("/api/search-url", func(w http.ResponseWriter, r *http.Request) {
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		switch r.Method {
		case http.MethodGet:
			urlStr, st, err := service.GetSearchURL(r.Context(), uid)
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
			st, err := service.SetSearchURL(r.Context(), uid, body.SearchURL)
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
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		resumes, st, err := service.GetResumes(r.Context(), uid, offset)
		writeJSON(w, st, map[string]any{"resumes": resumes}, err)
	})
	mux.HandleFunc("/api/resume/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, googleOAuth)
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
		st, err := service.UploadResume(r.Context(), uid, body.FileID)
		writeJSON(w, st, map[string]string{"status": "uploaded"}, err)
	})
	mux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		status := r.URL.Query().Get("status")
		jobs, st, err := service.GetJobs(r.Context(), uid, offset, status)
		writeJSON(w, st, map[string]any{"jobs": jobs}, err)
	})
	mux.HandleFunc("/api/job/note", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		var body struct {
			JobID string `json:"jobID"`
			Note  string `json:"note"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.JobID == "" {
			writeJSON(w, http.StatusBadRequest, nil, errMissing("jobID"))
			return
		}
		st, err := service.UpdateJobNote(r.Context(), uid, body.JobID, body.Note)
		writeJSON(w, st, map[string]string{"status": "updated"}, err)
	})
	mux.HandleFunc("/api/job/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		var body struct {
			JobID  string `json:"jobID"`
			Status string `json:"status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.JobID == "" || body.Status == "" {
			writeJSON(w, http.StatusBadRequest, nil, errMissing("jobID/status"))
			return
		}
		st, err := service.UpdateJobStatus(r.Context(), uid, body.JobID, body.Status)
		writeJSON(w, st, map[string]string{"status": "updated"}, err)
	})
	mux.HandleFunc("/api/job/details", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, googleOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		jobID := r.URL.Query().Get("jobID")
		if jobID == "" {
			writeJSON(w, http.StatusBadRequest, nil, errMissing("jobID"))
			return
		}
		content, st, err := service.GetJobDetails(r.Context(), uid, jobID)
		writeJSON(w, st, map[string]string{"content": content}, err)
	})

	server := &http.Server{Addr: serverAddr, Handler: rootHandler}
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Printf("starting server on %s", serverAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()
	<-shutdownCh
	log.Println("shutdown signal received")
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctxShutdown); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Println("server stopped")
}

// dynamic errors
func errMissing(field string) error { return &argError{msg: "missing " + field} }

type argError struct{ msg string }

func (e *argError) Error() string { return e.msg }
