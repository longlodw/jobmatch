package main

import (
	"context"
	"database/sql"
	"io"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	JobStatusPending       = "PENDING"
	JobStatusInterested    = "INTERESTED"
	JobStatusNotInterested = "NOT_INTERESTED"
	JobStatusApplied       = "APPLIED"
	JobStatusInterviewing  = "INTERVIEWING"
	JobStatusOffered       = "OFFERED"
	JobStatusRejected      = "REJECTED"
)

type IStorage interface {
	InsertUser(ctx context.Context, id, refreshToken string) error
	UpdateUserToken(ctx context.Context, id, refreshToken string) error
	UpdateUserDriveTokens(ctx context.Context, id string, accessToken, refreshToken sql.NullString, tokenExpiry sql.NullTime) error
	UpdateUserSearchURL(ctx context.Context, id string, searchURL sql.NullString) error
	UpdateUserLastSearched(ctx context.Context, id string) error
	SelectUserToken(ctx context.Context, id string) (refreshToken string, err error)
	SelectUserDriveTokens(ctx context.Context, id string) (driveAccessToken, driveRefreshToken sql.NullString, tokenExpiry sql.NullTime, err error)
	HasDriveEnabled(ctx context.Context, id string) (bool, error)
	SelectUserSearchURL(ctx context.Context, id string) (searchURL sql.NullString, err error)
	SelectUserLastSearched(ctx context.Context, id string) (lastSearched sql.NullTime, err error)

	InsertResume(ctx context.Context, id, userID string) error
	UpdateResumeTimestamp(ctx context.Context, id, userID string) error
	SelectResumesByUser(ctx context.Context, userID string, offset int) (resumes []struct {
		id          string
		lastUpdated sql.NullTime
	}, err error)
	SelectResumesByEmbedding(ctx context.Context, userID string, embedding []float32, topK int) (resumes []struct {
		id         string
		similarity float32
	}, err error)
	InsertResumeEmbedding(ctx context.Context, resumeID string, embedding []float32) error
	DeleteResumeEmbedding(ctx context.Context, resumeID string) error

	InsertJob(ctx context.Context, id, userID, resumeID, jobContent string) error
	UpdateJobStatus(ctx context.Context, id, userID, status string) error
	UpdateJobNote(ctx context.Context, id, userID string, note sql.NullString) error
	UpdateJobGoogleDriveID(ctx context.Context, id, userID string, driveID sql.NullString) error
	SelectJobsByUser(ctx context.Context, userID string, offset int) (jobs []struct {
		id          string
		status      string
		note        sql.NullString
		lastUpdated sql.NullTime
	}, err error)
	SelectJobByStatus(ctx context.Context, userID, status string, offset int) (jobs []struct {
		id          string
		status      string
		note        sql.NullString
		lastUpdated sql.NullTime
	}, err error)
	SelectJob(ctx context.Context, userID, jobID string) (job struct {
		id          string
		status      string
		note        sql.NullString
		lastUpdated sql.NullTime
	}, err error)

	GetJobContent(ctx context.Context, id string) (jobContent string, err error)
	StoreCode(ctx context.Context, state, codeVerifier string) error
	GetCode(ctx context.Context, state string) (codeVerifier string, isValid bool, err error)
	DeleteCode(ctx context.Context, state string) error

	Close() error
}

type Storage struct {
	db          *sql.DB
	minioClient *minio.Client
	bucketName  string
	pgSecret    string
}

func NewStorage(ctx context.Context, dbConnStr, pgSecret, minioEndpoint, minioAccessKey, minioSecretKey, bucketName string, secure bool) (*Storage, error) {
	db, err := sql.Open("pgx", dbConnStr)
	if err != nil {
		return nil, err
	}

	minioClient, err := minio.New(minioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(minioAccessKey, minioSecretKey, ""),
		Secure: secure,
	})
	if err != nil {
		return nil, err
	}

	// create bucket if not exists
	exists, err := minioClient.BucketExists(ctx, bucketName)
	if err != nil {
		return nil, err
	}
	if !exists {
		err = minioClient.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
		if err != nil {
			return nil, err
		}
	}

	// create tables if not exists
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			refresh_token BYTEA NOT NULL,
			drive_access_token BYTEA DEFAULT NULL,
			drive_refresh_token BYTEA DEFAULT NULL,
			drive_token_expiry TIMESTAMPTZ DEFAULT NULL,
			search_url TEXT DEFAULT NULL,
			last_searched TIMESTAMPTZ DEFAULT NULL
		);
		CREATE TABLE IF NOT EXISTS resumes (
			id TEXT,
			user_id TEXT,
			last_updated TIMESTAMPTZ DEFAULT NOW(),
			PRIMARY KEY (id, user_id)
		);
		CREATE INDEX IF NOT EXISTS id_to_resumes ON resumes (id);
		CREATE INDEX IF NOT EXISTS user_id_to_resumes ON resumes (user_id);
		CREATE TABLE IF NOT EXISTS jobs (
			id TEXT,
			user_id TEXT,
			resume_id TEXT,
			status TEXT,
			note TEXT DEFAULT NULL,
			application_drive_id TEXT DEFAULT NULL,
			last_updated TIMESTAMPTZ DEFAULT NOW(),
			PRIMARY KEY (id, user_id)
		);
		CREATE INDEX IF NOT EXISTS id_to_jobs ON jobs (id);
		CREATE INDEX IF NOT EXISTS user_id_to_jobs ON jobs (user_id);
		CREATE INDEX IF NOT EXISTS status_to_jobs ON jobs (status);
		CREATE EXTENSION IF NOT EXISTS pgcrypto;
		CREATE EXTENSION IF NOT EXISTS vector;
		CREATE TABLE IF NOT EXISTS resume_embeddings (
			resume_id TEXT,
			embedding VECTOR(3072)
		);
		CREATE INDEX IF NOT EXISTS resume_id_to_embeddings ON resume_embeddings (resume_id);
	`)
	if err != nil {
		return nil, err
	}

	return &Storage{
		db:          db,
		minioClient: minioClient,
		bucketName:  bucketName,
		pgSecret:    pgSecret,
	}, nil
}

func (s *Storage) InsertUser(ctx context.Context, id, refreshToken string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, refresh_token) VALUES ($1, pgp_sym_encrypt($2, $3))
		ON CONFLICT (id) DO UPDATE SET refresh_token = pgp_sym_encrypt($2, $3);
	`, id, refreshToken, s.pgSecret)
	return err
}

func (s *Storage) UpdateUserToken(ctx context.Context, id, refreshToken string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET refresh_token = pgp_sym_encrypt($2, $3)
		WHERE id = $1;
	`, id, refreshToken, s.pgSecret)
	return err
}

func (s *Storage) UpdateUserDriveTokens(ctx context.Context, id string, accessToken, refreshToken sql.NullString, tokenExpiry sql.NullTime) error {
	var accessVal any
	if accessToken.Valid {
		accessVal = accessToken.String
	} else {
		accessVal = nil
	}
	var refreshVal any
	if refreshToken.Valid {
		refreshVal = refreshToken.String
	} else {
		refreshVal = nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET drive_access_token = CASE WHEN $2 IS NULL THEN NULL ELSE pgp_sym_encrypt($2, $5) END,
			drive_refresh_token = CASE WHEN $3 IS NULL THEN NULL ELSE pgp_sym_encrypt($3, $5) END,
			drive_token_expiry = $4
		WHERE id = $1;
	`, id, accessVal, refreshVal, tokenExpiry, s.pgSecret)
	return err
}

func (s *Storage) UpdateUserSearchURL(ctx context.Context, id string, searchURL sql.NullString) error {
	var searchVal any
	if searchURL.Valid {
		searchVal = searchURL.String
	} else {
		searchVal = nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET search_url = $2
		WHERE id = $1;
	`, id, searchVal)
	return err
}

func (s *Storage) UpdateUserLastSearched(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET last_searched = NOW()
		WHERE id = $1;
	`, id)
	return err
}

func (s *Storage) SelectUserToken(ctx context.Context, id string) (refreshToken string, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT pgp_sym_decrypt(refresh_token, $2)
		FROM users
		WHERE id = $1;
	`, id, s.pgSecret).Scan(&refreshToken)
	return
}

func (s *Storage) SelectUserDriveTokens(ctx context.Context, id string) (driveAccessToken, driveRefreshToken sql.NullString, tokenExpiry sql.NullTime, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT
			CASE WHEN drive_access_token IS NULL THEN NULL ELSE pgp_sym_decrypt(drive_access_token, $2) END,
			CASE WHEN drive_refresh_token IS NULL THEN NULL ELSE pgp_sym_decrypt(drive_refresh_token, $2) END,
			drive_token_expiry
		FROM users
		WHERE id = $1;
	`, id, s.pgSecret).Scan(&driveAccessToken, &driveRefreshToken, &tokenExpiry)
	return
}

func (s *Storage) SelectUserSearchURL(ctx context.Context, id string) (searchURL sql.NullString, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT search_url
		FROM users
		WHERE id = $1;
	`, id).Scan(&searchURL)
	return
}

func (s *Storage) SelectUserLastSearched(ctx context.Context, id string) (lastSearched sql.NullTime, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT last_searched
		FROM users
		WHERE id = $1;
	`, id).Scan(&lastSearched)
	return
}

func (s *Storage) InsertResume(ctx context.Context, id, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO resumes (id, user_id)
		VALUES ($1, $2)
		ON CONFLICT (id, user_id) DO NOTHING;
	`, id, userID)
	return err
}

func (s *Storage) UpdateResumeTimestamp(ctx context.Context, id, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE resumes
		SET last_updated = NOW()
		WHERE id = $1 AND user_id = $2;
	`, id, userID)
	return err
}

func (s *Storage) SelectResumesByUser(ctx context.Context, userID string, offset int) (resumes []struct {
	id          string
	lastUpdated sql.NullTime
}, err error) {
	var rows *sql.Rows
	if offset < 0 {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, last_updated
			FROM resumes
			WHERE user_id = $1;
		`, userID)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, last_updated
			FROM resumes
			WHERE user_id = $1
			LIMIT 20 OFFSET $2;
		`, userID, offset)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var lastUpdated sql.NullTime
		if err := rows.Scan(&id, &lastUpdated); err != nil {
			return nil, err
		}
		resumes = append(resumes, struct {
			id          string
			lastUpdated sql.NullTime
		}{
			id:          id,
			lastUpdated: lastUpdated,
		})
	}
	return resumes, rows.Err()
}

func (s *Storage) SelectResumesByEmbedding(ctx context.Context, userID string, embedding []float32, topK int) (resumes []struct {
	id         string
	similarity float32
}, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id AS id, avg(1 - (re.embedding <=> $2)) AS similarity
		FROM resumes r
		JOIN resume_embeddings re ON r.id = re.resume_id
		WHERE r.user_id = $3 AND (re.embedding <=> $2) < 0.3
		GROUP BY r.id
		ORDER BY similarity DESC
		LIMIT $4;
	`, embedding, userID, topK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var similarity float32
		if err := rows.Scan(&id, &similarity); err != nil {
			return nil, err
		}
		resumes = append(resumes, struct {
			id         string
			similarity float32
		}{
			id:         id,
			similarity: similarity,
		})
	}
	return resumes, rows.Err()
}

func (s *Storage) InsertResumeEmbedding(ctx context.Context, resumeID string, embedding []float32) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO resume_embeddings (resume_id, embedding)
		VALUES ($1, $2)
		ON CONFLICT (resume_id) DO UPDATE SET embedding = EXCLUDED.embedding;
	`, resumeID, embedding)
	return err
}

func (s *Storage) DeleteResumeEmbedding(ctx context.Context, resumeID string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM resume_embeddings
		WHERE resume_id = $1;
	`, resumeID)
	return err
}

func (s *Storage) InsertJob(ctx context.Context, id, userID, resumeID, jobContent string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO jobs (id, user_id, resume_id, status)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id, user_id) DO UPDATE SET resume_id = EXCLUDED.resume_id;
	`, id, userID, resumeID, JobStatusPending)
	if err != nil {
		return err
	}
	_, err = s.minioClient.PutObject(ctx, s.bucketName, "jobs/"+id+".json",
		strings.NewReader(jobContent), int64(len(jobContent)), minio.PutObjectOptions{ContentType: "application/json"})
	return err
}

func (s *Storage) UpdateJobStatus(ctx context.Context, id, userID, status string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE jobs
		SET status = $3, last_updated = NOW()
		WHERE id = $1 AND user_id = $2;
	`, id, userID, status)
	return err
}

func (s *Storage) UpdateJobNote(ctx context.Context, id, userID string, note sql.NullString) error {
	var noteVal any
	if note.Valid {
		noteVal = note.String
	} else {
		noteVal = nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE jobs
		SET note = $3, last_updated = NOW()
		WHERE id = $1 AND user_id = $2;
	`, id, userID, noteVal)
	return err
}

func (s *Storage) UpdateJobGoogleDriveID(ctx context.Context, id, userID string, driveID sql.NullString) error {
	var driveVal any
	if driveID.Valid {
		driveVal = driveID.String
	} else {
		driveVal = nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE jobs
		SET application_drive_id = $3, last_updated = NOW()
		WHERE id = $1 AND user_id = $2;
	`, id, userID, driveVal)
	return err
}

func (s *Storage) SelectJobsByUser(ctx context.Context, userID string, offset int) (jobs []struct {
	id          string
	status      string
	note        sql.NullString
	lastUpdated sql.NullTime
}, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, status, note, last_updated
		FROM jobs
		WHERE user_id = $1
		LIMIT 20 OFFSET $2;
	`, userID, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status string
		var note sql.NullString
		var lastUpdated sql.NullTime
		if err := rows.Scan(&id, &status, &note, &lastUpdated); err != nil {
			return nil, err
		}
		jobs = append(jobs, struct {
			id          string
			status      string
			note        sql.NullString
			lastUpdated sql.NullTime
		}{
			id:          id,
			status:      status,
			note:        note,
			lastUpdated: lastUpdated,
		})
	}
	return jobs, rows.Err()
}

func (s *Storage) SelectJobByStatus(ctx context.Context, userID, status string, offset int) (jobs []struct {
	id          string
	status      string
	note        sql.NullString
	lastUpdated sql.NullTime
}, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, status, note, last_updated
		FROM jobs
		WHERE user_id = $1 AND status = $2
		LIMIT 20 OFFSET $3;
	`, userID, status, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, st string
		var note sql.NullString
		var lastUpdated sql.NullTime
		if err := rows.Scan(&id, &st, &note, &lastUpdated); err != nil {
			return nil, err
		}
		jobs = append(jobs, struct {
			id          string
			status      string
			note        sql.NullString
			lastUpdated sql.NullTime
		}{
			id:          id,
			status:      st,
			note:        note,
			lastUpdated: lastUpdated,
		})
	}
	return jobs, rows.Err()
}

func (s *Storage) SelectJob(ctx context.Context, userID, jobID string) (job struct {
	id          string
	status      string
	note        sql.NullString
	lastUpdated sql.NullTime
}, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT id, status, note, last_updated
		FROM jobs
		WHERE user_id = $1 AND id = $2;
	`, userID, jobID).Scan(&job.id, &job.status, &job.note, &job.lastUpdated)
	return
}

func (s *Storage) GetJobContent(ctx context.Context, id string) (jobContent string, err error) {
	obj, err := s.minioClient.GetObject(ctx, s.bucketName, "jobs/"+id+".json", minio.GetObjectOptions{})
	if err != nil {
		return "", err
	}
	defer obj.Close()
	result, err := io.ReadAll(obj)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func (s *Storage) StoreCode(ctx context.Context, state, codeVerifier string) error {
	_, err := s.minioClient.PutObject(ctx, s.bucketName, "codes/"+state+".txt",
		strings.NewReader(codeVerifier), int64(len(codeVerifier)), minio.PutObjectOptions{ContentType: "text/plain", UserMetadata: map[string]string{
			"created_at": time.Now().Format(time.RFC3339),
		}})
	return err
}

func (s *Storage) GetCode(ctx context.Context, state string) (codeVerifier string, isValid bool, err error) {
	info, err := s.minioClient.StatObject(ctx, s.bucketName, "codes/"+state+".txt", minio.StatObjectOptions{})
	if err != nil {
		return "", false, err
	}
	lastModified := info.LastModified
	if time.Since(lastModified) > 10*time.Minute {
		return "", false, nil
	}
	obj, err := s.minioClient.GetObject(ctx, s.bucketName, "codes/"+state+".txt", minio.GetObjectOptions{})
	if err != nil {
		return "", false, err
	}
	defer obj.Close()
	result, err := io.ReadAll(obj)
	if err != nil {
		return "", false, err
	}
	return string(result), true, nil
}

func (s *Storage) DeleteCode(ctx context.Context, state string) error {
	return s.minioClient.RemoveObject(ctx, s.bucketName, "codes/"+state+".txt", minio.RemoveObjectOptions{})
}

func (s *Storage) HasDriveEnabled(ctx context.Context, id string) (bool, error) {
	var accessToken sql.NullString
	var refreshToken sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT CASE WHEN drive_access_token IS NULL THEN NULL ELSE pgp_sym_decrypt(drive_access_token, $2) END,
		       CASE WHEN drive_refresh_token IS NULL THEN NULL ELSE pgp_sym_decrypt(drive_refresh_token, $2) END
		FROM users WHERE id = $1;
	`, id, s.pgSecret).Scan(&accessToken, &refreshToken)
	if err != nil {
		return false, err
	}
	return accessToken.Valid && refreshToken.Valid, nil
}

func (s *Storage) Close() error { return s.db.Close() }
