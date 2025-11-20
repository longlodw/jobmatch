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
	UpdateUserDriveTokens(ctx context.Context, id, accessToken, refreshToken string, tokenExpiry sql.NullTime) error
	UpdateUserSearchURL(ctx context.Context, id, searchURL string) error
	UpdateUserLastSearched(ctx context.Context, id string) error
	SelectUserToken(ctx context.Context, id string) (refreshToken string, err error)
	SelectUserDriveTokens(ctx context.Context, id string) (driveAccessToken, driveRefreshToken string, tokenExpiry sql.NullTime, err error)
	SelectUserSearchURL(ctx context.Context, id string) (searchURL string, err error)
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
	UpdateJobNote(ctx context.Context, id, userID, note string) error
	UpdateJobGoogleDriveID(ctx context.Context, id, userID, driveID string) error
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

	GetJobContent(ctx context.Context, id string) (jobContent string, err error)
	StoreCode(ctx context.Context, codeVerifier, codeChallenge string) error
	GetCode(ctx context.Context, codeChallenge string) (codeVerifier string, err error)
	DeleteCode(ctx context.Context, codeChallenge string) error
	StoreState(ctx context.Context, state string) error
	GetState(ctx context.Context, state string) (isValid bool, err error)
	DeleteState(ctx context.Context, state string) error

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
			id TEXT KEY,
			user_id TEXT FOREIGN KEY REFERENCES users(id),
			last_updated TIMESTAMPTZ DEFAULT NOW(),
			PRIMARY KEY (id, user_id)
		);
		CREATE INDEX IF NOT EXISTS id_to_resumes ON resumes (id);
		CREATE INDEX IF NOT EXISTS user_id_to_resumes ON resumes (user_id);
		CREATE TABLE IF NOT EXISTS jobs (
			id TEXT,
			user_id TEXT FOREIGN KEY REFERENCES users(id),
			resume_id TEXT FOREIGN KEY REFERENCES resumes(id),
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
			resume_id TEXT FOREIGN KEY REFERENCES resumes(id),
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
		ON CONFLICT (id) SET refresh_token = pgp_sym_encrypt($2, $3);
	`, id, refreshToken, s.pgSecret)
	return err
}

func (s *Storage) UpdateUserToken(ctx context.Context, id, refreshToken string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET refresh_token = pgp_sym_encrypt($2, $4),
		WHERE id = $1;
	`, id, refreshToken, s.pgSecret)
	return err
}

func (s *Storage) UpdateUserDriveTokens(ctx context.Context, id, accessToken, refreshToken string, tokenExpiry sql.NullTime) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET drive_access_token = pgp_sym_encrypt($2, $5),
			drive_refresh_token = pgp_sym_encrypt($3, $5),
			token_expiry = $4
		WHERE id = $1;
	`, id, accessToken, refreshToken, tokenExpiry, s.pgSecret)
	return err
}

func (s *Storage) UpdateUserSearchURL(ctx context.Context, id, searchURL string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET search_url = $2,
		WHERE id = $1;
	`, id, searchURL)
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

func (s *Storage) SelectUserDriveTokens(ctx context.Context, id string) (driveAccessToken, driveRefreshToken string, tokenExpiry sql.NullTime, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT pgp_sym_decrypt(drive_access_token, $2), pgp_sym_decrypt(drive_refresh_token, $2), token_expiry
		FROM users
		WHERE id = $1;
	`, id, s.pgSecret).Scan(&driveAccessToken, &driveRefreshToken, &tokenExpiry)
	return
}

func (s *Storage) SelectUserSearchURL(ctx context.Context, id string) (searchURL string, err error) {
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
		ON CONFLICT (id, user_id) SET resume_id = EXCLUDED.resume_id;
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

func (s *Storage) UpdateJobNote(ctx context.Context, id, userID, note string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE jobs
		SET note = $3, last_updated = NOW()
		WHERE id = $1 AND user_id = $2;
	`, id, userID, note)
	return err
}

func (s *Storage) UpdateJobGoogleDriveID(ctx context.Context, id, userID, driveID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE jobs
		SET application_drive_id = $3, last_updated = NOW()
		WHERE id = $1 AND user_id = $2;
	`, id, userID, driveID)
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
		WHERE user_id = $1;
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
		SELECT id, note, last_updated
		FROM jobs
		WHERE user_id = $1 AND status = $2
		LIMIT 20 OFFSET $3;
	`, userID, status, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var note sql.NullString
		var lastUpdated sql.NullTime
		if err := rows.Scan(&id, &note, &lastUpdated); err != nil {
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

func (s *Storage) StoreCode(ctx context.Context, codeVerifier, codeChallenge string) error {
	_, err := s.minioClient.PutObject(ctx, s.bucketName, "codes/"+codeChallenge+".txt",
		strings.NewReader(codeVerifier), int64(len(codeVerifier)), minio.PutObjectOptions{ContentType: "text/plain", UserMetadata: map[string]string{
			"created_at": time.Now().Format(time.RFC3339),
		}})
	return err
}

func (s *Storage) GetCode(ctx context.Context, codeChallenge string) (codeVerifier string, err error) {
	obj, err := s.minioClient.GetObject(ctx, s.bucketName, "codes/"+codeChallenge+".txt", minio.GetObjectOptions{})
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

func (s *Storage) DeleteCode(ctx context.Context, codeChallenge string) error {
	return s.minioClient.RemoveObject(ctx, s.bucketName, "codes/"+codeChallenge+".txt", minio.RemoveObjectOptions{})
}

func (s *Storage) StoreState(ctx context.Context, state string) error {
	expiration := time.Now().Add(1 * time.Minute).Format(time.RFC3339)
	_, err := s.minioClient.PutObject(ctx, s.bucketName, "states/"+state+".txt",
		strings.NewReader(expiration), int64(len(expiration)), minio.PutObjectOptions{ContentType: "text/plain"})
	return err
}

func (s *Storage) GetState(ctx context.Context, state string) (isValid bool, err error) {
	obj, err := s.minioClient.GetObject(ctx, s.bucketName, "states/"+state+".txt", minio.GetObjectOptions{})
	if err != nil {
		return false, err
	}
	defer obj.Close()
	result, err := io.ReadAll(obj)
	if err != nil {
		return false, err
	}
	expiration, err := time.Parse(time.RFC3339, string(result))
	if err != nil {
		return false, err
	}
	return time.Now().Before(expiration), nil
}

func (s *Storage) DeleteState(ctx context.Context, state string) error {
	return s.minioClient.RemoveObject(ctx, s.bucketName, "states/"+state+".txt", minio.RemoveObjectOptions{})
}

func (s *Storage) Close() error {
	return s.db.Close()
}
