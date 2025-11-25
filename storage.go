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
	"github.com/pgvector/pgvector-go"
)

const (
	JobStatusPending       = "PENDING"
	JobStatusInterested    = "INTERESTED"
	JobStatusNotInterested = "NOT_INTERESTED"
)

type JobMetadata struct {
	ID         string
	UserID     string
	ResumeID   string
	Status     string
	LastUpdate time.Time
}

type ResumeMetadata struct {
	ID          string
	LastUpdated time.Time
}

type EmbeddingScore struct {
	ID         string
	Similarity float32
}

type IStorage interface {
	InsertUser(ctx context.Context, id, refreshToken, accessToken string, tokenExpiry time.Time) error
	UpdateUserSearchURL(ctx context.Context, id string, searchURL string) error
	UpdateUserLastSearched(ctx context.Context, id string) error
	SelectUserTokens(ctx context.Context, id string) (refreshToken, accessToken string, tokenExpiry time.Time, err error)
	SelectUserSearchURL(ctx context.Context, id string) (searchURL sql.NullString, err error)
	SelectUserLastSearched(ctx context.Context, id string) (lastSearched sql.NullTime, err error)

	InsertResume(ctx context.Context, id, userID string, embeddings [][]float32) error
	UpdateResumeTimestamp(ctx context.Context, id, userID string) error
	SelectResumesByUser(ctx context.Context, userID string, offset int) (resumes []ResumeMetadata, err error)
	SelectResumesByEmbedding(ctx context.Context, userID string, embedding []float32, topK int) (resumes []EmbeddingScore, err error)

	InsertJob(ctx context.Context, id, userID, resumeID, jobContent string) error
	UpdateJobStatus(ctx context.Context, id, userID, status string) error
	SelectJobByStatus(ctx context.Context, userID, status string) (jobs []JobMetadata, err error)

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
			access_token BYTEA NOT NULL,
			token_expiry TIMESTAMPTZ NOT NULL,
			search_url TEXT DEFAULT NULL,
			last_searched TIMESTAMPTZ DEFAULT NULL
		);
		CREATE TABLE IF NOT EXISTS resumes (
			id TEXT NOT NULL,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (id, user_id)
		);
		CREATE INDEX IF NOT EXISTS user_id_to_resumes ON resumes (user_id);
		CREATE TABLE IF NOT EXISTS jobs (
			id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			resume_id TEXT NOT NULL,
			status TEXT NOT NULL,
			last_updated TIMESTAMPTZ DEFAULT NOW(),
			PRIMARY KEY (id, user_id),
			FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS user_id_status_to_jobs ON jobs (user_id, status);
		CREATE EXTENSION IF NOT EXISTS pgcrypto;
		CREATE EXTENSION IF NOT EXISTS vector;
		CREATE TABLE IF NOT EXISTS resume_embeddings (
			resume_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			embedding VECTOR(1536) NOT NULL,
			FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE CASCADE
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

func (s *Storage) InsertUser(ctx context.Context, id, refreshToken, accessToken string, tokenExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, refresh_token, access_token, token_expiry)
		VALUES ($1, pgp_sym_encrypt($2, $4), pgp_sym_encrypt($3, $4), $5)
		ON CONFLICT (id) DO UPDATE SET
			refresh_token = EXCLUDED.refresh_token,
			access_token = EXCLUDED.access_token,
			token_expiry = EXCLUDED.token_expiry;
	`, id, refreshToken, accessToken, s.pgSecret, tokenExpiry)
	return err
}

func (s *Storage) UpdateUserSearchURL(ctx context.Context, id string, searchURL string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET search_url = $2
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

func (s *Storage) SelectUserTokens(ctx context.Context, id string) (refreshToken, accessToken string, tokenExpiry time.Time, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT
			pgp_sym_decrypt(refresh_token, $2),
			pgp_sym_decrypt(access_token, $2),
			token_expiry
		FROM users
		WHERE id = $1;
	`, id, s.pgSecret).Scan(&refreshToken, &accessToken, &tokenExpiry)
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

func (s *Storage) InsertResume(ctx context.Context, id, userID string, embedding [][]float32) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO resumes (id, user_id, last_updated)
		VALUES ($1, $2, NOW())
		ON CONFLICT (id, user_id) DO UPDATE SET last_updated = NOW();
	`, id, userID)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.ExecContext(ctx, `
		DELETE FROM resume_embeddings
		WHERE resume_id = $1;
	`, id)
	if err != nil {
		tx.Rollback()
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO resume_embeddings (resume_id, user_id, embedding)
		VALUES ($1, $2, $3);
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, emb := range embedding {
		_, err = stmt.ExecContext(ctx, id, userID, pgvector.NewVector(emb))
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Storage) UpdateResumeTimestamp(ctx context.Context, id, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE resumes
		SET last_updated = NOW()
		WHERE id = $1 AND user_id = $2;
	`, id, userID)
	return err
}

func (s *Storage) SelectResumesByUser(ctx context.Context, userID string, offset int) (resumes []ResumeMetadata, err error) {
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
		var lastUpdated time.Time
		if err := rows.Scan(&id, &lastUpdated); err != nil {
			return nil, err
		}
		resumes = append(resumes, ResumeMetadata{
			ID:          id,
			LastUpdated: lastUpdated,
		})
	}
	return resumes, rows.Err()
}

func (s *Storage) SelectResumesByEmbedding(ctx context.Context, userID string, embedding []float32, topK int) (resumes []EmbeddingScore, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id AS id, avg(1 - (re.embedding <=> $2)) AS similarity
		FROM resumes r
		JOIN resume_embeddings re ON r.id = re.resume_id
		WHERE r.user_id = $3 AND (re.embedding <=> $2) < 0.3
		GROUP BY r.id
		ORDER BY similarity DESC
		LIMIT $4;
	`, pgvector.NewVector(embedding), userID, topK)
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
		resumes = append(resumes, EmbeddingScore{
			ID:         id,
			Similarity: similarity,
		})
	}
	return resumes, rows.Err()
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

func (s *Storage) SelectJobByStatus(ctx context.Context, userID, status string) (jobs []JobMetadata, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, status, last_updated
		FROM jobs
		WHERE user_id = $1 AND status = $2
		LIMIT 20;
	`, userID, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, st string
		var lastUpdated time.Time
		if err := rows.Scan(&id, &st, &lastUpdated); err != nil {
			return nil, err
		}
		jobs = append(jobs, JobMetadata{
			ID:         id,
			UserID:     userID,
			Status:     st,
			LastUpdate: lastUpdated,
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

func (s *Storage) Close() error {
	return s.db.Close()
}
