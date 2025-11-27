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
	webRedirectURL := getEnv("WEB_REDIRECT_URL")
	apiRedirectURL := getEnv("API_REDIRECT_URL")
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

	webOAuth, err := NewGoogleOAuth(ctx, clientID, clientSecret, webRedirectURL)
	if err != nil {
		logger.Fatal("failed to init google oauth (web)", zap.Error(err))
	}
	apiOAuth, err := NewGoogleOAuth(ctx, clientID, clientSecret, apiRedirectURL)
	if err != nil {
		logger.Fatal("failed to init google oauth (api)", zap.Error(err))
	}

	storage, err := NewStorage(ctx, pgConnStr, pgSecret, minioEndpoint, minioAccessKey, minioSecretKey, minioBucket, false)
	if err != nil {
		logger.Fatal("failed to init storage", zap.Error(err))
	}
	defer storage.Close()

	jobFetcher := NewJobFetcher(jobFetcherURL, jobFetcherToken, logger)
	embedder := NewEmbeder(embedBaseURL, embedAPIKey)

	webService := NewService(webOAuth, storage, jobFetcher, embedder, rootFolderName, logger)
	defer webService.Shutdown()
	apiService := NewService(apiOAuth, storage, jobFetcher, embedder, rootFolderName, logger)
	defer apiService.Shutdown()

	// parse templates (include all fragments)
	tmpl, err := template.ParseFiles(
		filepath.Join("templates", "base.html"),
		filepath.Join("templates", "home.html"),
		filepath.Join("templates", "jobs.html"),
		filepath.Join("templates", "job_details.html"),
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
		uid, _, _ := getIDTokenSubject(r, webOAuth, logger)
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

	// jobs fragment (htmx) - always pending, expand to JobData for swipe UI
	mux.HandleFunc("/jobs", requireAuth(logger, webOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		// ignore status filter; always show pending
		jobsMeta, st2, err := webService.GetJobs(r.Context(), uid, 0, JobStatusPending)
		if err != nil {
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		// build []JobData from metadata
		var jobDatas []JobData
		for _, jm := range jobsMeta {
			content, st3, err2 := webService.GetJobDetails(r.Context(), uid, jm.ID)
			if err2 != nil {
				logger.Warn("job content fetch failed", zap.Error(err2), zap.String("jobID", jm.ID))
				if st3 >= 500 { // server error: abort
					fragmentError(w, tmpl, st3, err2.Error())
					return
				}
				continue
			}
			var jd JobData
			if err := json.Unmarshal([]byte(content), &jd); err != nil {
				logger.Warn("job content unmarshal failed", zap.Error(err), zap.String("jobID", jm.ID))
				continue
			}
			jobDatas = append(jobDatas, jd)
		}
		data := struct{ Jobs any }{Jobs: jobDatas}
		if err := tmpl.ExecuteTemplate(w, "jobs", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// job details fragment
	mux.HandleFunc("/job/details", requireAuth(logger, webOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		jobID := r.URL.Query().Get("id")
		if jobID == "" {
			logger.Info("missing job id in details request", zap.String("uid", uid))
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
	// update job status (htmx)
	mux.HandleFunc("/job/status", requireAuth(logger, webOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if r.Method != http.MethodPost {
			logger.Info("invalid method on job status update", zap.String("method", r.Method), zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			logger.Info("invalid CSRF on job status update", zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		if err := r.ParseForm(); err != nil {
			logger.Info("bad form on job status update", zap.String("uid", uid), zap.Error(err))
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
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		logger.Info("job status updated", zap.String("jobID", jobID), zap.String("uid", uid), zap.String("status", status))
		// respond with success fragment (client will remove/swipe card)
		if err := tmpl.ExecuteTemplate(w, "success_fragment", struct{ Message string }{Message: "Status updated."}); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
	}))

	// resumes fragment
	mux.HandleFunc("/resumes", func(w http.ResponseWriter, r *http.Request) {
		uid, _, _ := getIDTokenSubject(r, webOAuth, logger) // optional
		var resumes []ResumeMetaData
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
			Resumes       []ResumeMetaData
		}{Authenticated: uid != "", Resumes: resumes}
		if err := tmpl.ExecuteTemplate(w, "resumes", data); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	})

	// upload resume (htmx target)
	mux.HandleFunc("/resumes/upload", requireAuth(logger, webOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if r.Method != http.MethodPost {
			logger.Info("invalid method on resume upload", zap.String("method", r.Method), zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			logger.Info("invalid CSRF on resume upload", zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		if err := r.ParseForm(); err != nil {
			logger.Info("bad form on resume upload", zap.String("uid", uid), zap.Error(err))
			fragmentError(w, tmpl, http.StatusBadRequest, "bad form")
			return
		}
		fileID := r.Form.Get("fileID")
		if fileID == "" {
			logger.Info("missing fileID on resume upload", zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusBadRequest, "missing fileID")
			return
		}
		if _, err := webService.UploadResume(r.Context(), uid, fileID); err != nil {
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
			return
		}
		logger.Info("resume uploaded", zap.String("fileID", fileID), zap.String("uid", uid))
		if err := tmpl.ExecuteTemplate(w, "success_fragment", struct{ Message string }{Message: "Resume uploaded."}); err != nil {
			logger.Error("resume upload success fragment error", zap.String("uid", uid), zap.Error(err))
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))

	// delete resume (htmx target)
	mux.HandleFunc("/resumes/delete", requireAuth(logger, webOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if r.Method != http.MethodPost {
			logger.Info("invalid method on resume delete", zap.String("method", r.Method), zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			logger.Info("invalid CSRF on resume delete", zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		if err := r.ParseForm(); err != nil {
			logger.Info("bad form on resume delete", zap.String("uid", uid), zap.Error(err))
			fragmentError(w, tmpl, http.StatusBadRequest, "bad form")
			return
		}
		resumeID := r.Form.Get("resumeID")
		if resumeID == "" {
			logger.Info("missing resumeID on resume delete", zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusBadRequest, "missing resumeID")
			return
		}
		if st2, err := webService.DeleteResume(r.Context(), uid, resumeID); err != nil {
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		logger.Info("resume deleted", zap.String("resumeID", resumeID), zap.String("uid", uid))
		// return empty 200 OK; hx-swap outerHTML on target will remove element
		w.WriteHeader(http.StatusOK)
	}))

	// settings fragment (CSRF required even on GET)
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		if !validateCSRF(r) {
			logger.Info("invalid CSRF on settings fetch")
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		uid, st, err := getIDTokenSubject(r, webOAuth, logger)
		if err != nil && st != http.StatusUnauthorized {
			fragmentError(w, tmpl, st, err.Error())
			return
		}
		var searchURL string
		if uid != "" {
			url, _, err := webService.GetSearchURL(r.Context(), uid)
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
	mux.HandleFunc("/settings/search", requireAuth(logger, webOAuth, tmpl, func(w http.ResponseWriter, r *http.Request, uid string) {
		if r.Method != http.MethodPost {
			logger.Info("invalid method on search URL save", zap.String("method", r.Method))
			fragmentError(w, tmpl, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !validateCSRF(r) {
			logger.Info("invalid CSRF on search URL save", zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusForbidden, "bad csrf")
			return
		}
		refreshCSRFCookie(w, r)
		if err := r.ParseForm(); err != nil {
			logger.Info("bad form on search URL save", zap.String("uid", uid), zap.Error(err))
			fragmentError(w, tmpl, http.StatusBadRequest, "bad form")
			return
		}
		searchURL := r.Form.Get("searchURL")
		if searchURL == "" {
			logger.Info("missing search URL on save", zap.String("uid", uid))
			fragmentError(w, tmpl, http.StatusBadRequest, "missing searchURL")
			return
		}
		if st2, err := webService.SetSearchURL(r.Context(), uid, searchURL); err != nil {
			fragmentError(w, tmpl, st2, err.Error())
			return
		}
		logger.Info("search URL saved", zap.String("uid", uid))
		if err := tmpl.ExecuteTemplate(w, "success_fragment", struct{ Message string }{Message: "Search URL saved."}); err != nil {
			logger.Error("search URL save success fragment error", zap.String("uid", uid), zap.Error(err))
			fragmentError(w, tmpl, http.StatusInternalServerError, err.Error())
		}
	}))
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			logger.Info("invalid method on api login", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		authURL, st, err := apiService.Login(r.Context())
		writeJSON(w, st, map[string]string{"authUrl": authURL}, err)
	})
	mux.HandleFunc("/api/login/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			logger.Info("invalid method on api login callback", zap.String("method", r.Method))
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
			logger.Info("invalid method on api token refresh", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		newToken, _, _, st, err := apiService.RefreshToken(r.Context(), uid)
		writeJSON(w, st, map[string]string{"idToken": newToken}, err)
	})
	mux.HandleFunc("/api/search-url", func(w http.ResponseWriter, r *http.Request) {
		uid, verr := verifyAndGetUserID(r, apiOAuth)
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
			logger.Info("invalid method on api search URL", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/resumes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			logger.Info("invalid method on api get resumes", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		resumes, st, err := apiService.GetResumes(r.Context(), uid, offset)
		writeJSON(w, st, map[string]any{"resumes": resumes}, err)
	})
	mux.HandleFunc("/api/resume", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			uid, verr := verifyAndGetUserID(r, apiOAuth)
			if verr != nil {
				writeJSON(w, http.StatusUnauthorized, nil, verr)
				return
			}
			var body struct {
				FileID string `json:"fileID"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.FileID == "" {
				logger.Info("missing fileID on api resume upload", zap.String("uid", uid))
				writeJSON(w, http.StatusBadRequest, nil, errMissing("fileID"))
				return
			}
			st, err := apiService.UploadResume(r.Context(), uid, body.FileID)
			writeJSON(w, st, map[string]string{"status": "uploaded"}, err)
		case http.MethodDelete:
			uid, verr := verifyAndGetUserID(r, apiOAuth)
			if verr != nil {
				writeJSON(w, http.StatusUnauthorized, nil, verr)
				return
			}
			resumeID := r.URL.Query().Get("resumeID")
			if resumeID == "" {
				logger.Info("missing resumeID on api resume delete", zap.String("uid", uid))
				writeJSON(w, http.StatusBadRequest, nil, errMissing("resumeID"))
				return
			}
			st, err := apiService.DeleteResume(r.Context(), uid, resumeID)
			writeJSON(w, st, map[string]string{"status": "deleted"}, err)
		default:
			logger.Info("invalid method on api resume", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			logger.Info("invalid method on api get jobs", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiOAuth)
		if verr != nil {
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil {
			logger.Info("invalid offset on api get jobs", zap.String("offset", r.URL.Query().Get("offset")), zap.String("uid", uid))
			writeJSON(w, http.StatusBadRequest, map[string]string{"offset": r.URL.Query().Get("offset")}, errMissing("offset"))
			return
		}
		// always pending for API
		jobs, st, err := apiService.GetJobs(r.Context(), uid, offset, JobStatusPending)
		writeJSON(w, st, map[string]any{"jobs": jobs}, err)
	})
	mux.HandleFunc("/api/job/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			logger.Info("invalid method on api job status update", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiOAuth)
		if verr != nil {
			logger.Info("unauthorized api job status update attempt")
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
			logger.Info("invalid method on health check", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// lightweight dependency checks (storage ping?) kept minimal for speed
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/api/job/details", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			logger.Info("invalid method on api job details", zap.String("method", r.Method))
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		uid, verr := verifyAndGetUserID(r, apiOAuth)
		if verr != nil {
			logger.Info("unauthorized api job details attempt")
			writeJSON(w, http.StatusUnauthorized, nil, verr)
			return
		}
		jobID := r.URL.Query().Get("jobID")
		if jobID == "" {
			logger.Info("missing jobID on api job details", zap.String("uid", uid))
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
		logger.Fatal("server shutdown failed", zap.Error(err))
	}
	logger.Info("server stopped")
}
