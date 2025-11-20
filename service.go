package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"sync"
	"time"

	"github.com/longlodw/lazyiterate"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type Service struct {
	googleOAuth    IOAuth
	storage        IStorage
	jobFetcher     IJobFetcher
	embedder       IEmbedder
	rootFolderName string
	logger         *zap.Logger
}

func NewService(googleOAuth IOAuth, storage IStorage, jobFetcher IJobFetcher, embedder IEmbedder, rootFolderName string, logger *zap.Logger) *Service {
	return &Service{
		googleOAuth:    googleOAuth,
		storage:        storage,
		jobFetcher:     jobFetcher,
		embedder:       embedder,
		rootFolderName: rootFolderName,
		logger:         logger,
	}
}

func (s *Service) Login(ctx context.Context) (authUrl string, httpStatus int, err error) {
	s.logger.Info("initiating login")
	scopes := []string{"openid"}
	authUrl, state, codeVerifier, codeChallenge, err := s.googleOAuth.Initiate(scopes)
	if err != nil {
		s.logger.Error("failed to initiate login", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	err = s.storage.StoreState(ctx, state)
	if err != nil {
		s.logger.Error("failed to store state", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	err = s.storage.StoreCode(ctx, codeVerifier, codeChallenge)
	if err != nil {
		s.logger.Error("failed to store code", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	s.logger.Info("login initiated", zap.String("authUrl", authUrl))
	return authUrl, http.StatusOK, nil
}

func (s *Service) LoginCallback(ctx context.Context, state, code string) (idToken string, httpStatus int, err error) {
	s.logger.Info("handling login callback", zap.String("state", state), zap.String("code", code))
	codeVerifier, err := s.storage.GetCode(ctx, code)
	if err != nil {
		s.logger.Error("failed to get code verifier", zap.Error(err))
		return "", http.StatusBadRequest, err
	}
	token, err := s.googleOAuth.Exchange(ctx, code, codeVerifier)
	if err != nil {
		s.logger.Error("failed to exchange code for token", zap.Error(err))
		return "", http.StatusBadRequest, err
	}
	idToken, err = ExtractIDToken(token)
	if err != nil {
		s.logger.Error("failed to extract ID token", zap.Error(err))
		return "", http.StatusBadRequest, err
	}
	verifiedIDToken, err := s.googleOAuth.VerifyIDToken(ctx, idToken)
	if err != nil {
		s.logger.Error("failed to verify ID token", zap.Error(err))
		return "", http.StatusBadRequest, err
	}
	refreshToken := token.RefreshToken
	err = s.storage.InsertUser(ctx, verifiedIDToken.Subject, refreshToken)
	if err != nil {
		s.logger.Error("failed to insert user", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	s.logger.Info("login callback handled successfully", zap.String("userID", verifiedIDToken.Subject))
	return idToken, http.StatusOK, nil
}

func (s *Service) RefreshToken(ctx context.Context, userID string) (newIDToken string, httpStatus int, err error) {
	s.logger.Info("refreshing token", zap.String("userID", userID))
	refreshToken, err := s.storage.SelectUserToken(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get refresh token", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	newToken, err := s.googleOAuth.Refresh(ctx, refreshToken)
	if err != nil {
		s.logger.Error("failed to refresh token", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	newIDToken = newToken.Extra("id_token").(string)
	s.logger.Info("token refreshed successfully", zap.String("userID", userID))
	return newIDToken, http.StatusOK, nil
}

func (s *Service) EnableDrive(ctx context.Context, userID string) (authUrl string, httpStatus int, err error) {
	s.logger.Info("initiating Google Drive enable", zap.String("userID", userID))
	scopes := []string{"https://www.googleapis.com/auth/drive.file"}
	authUrl, state, codeVerifier, codeChallenge, err := s.googleOAuth.Initiate(scopes)
	if err != nil {
		s.logger.Error("failed to initiate Google Drive enable", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	err = s.storage.StoreState(ctx, state)
	if err != nil {
		s.logger.Error("failed to store state", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	err = s.storage.StoreCode(ctx, codeVerifier, codeChallenge)
	if err != nil {
		s.logger.Error("failed to store code", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	s.logger.Info("Google Drive enable initiated", zap.String("authUrl", authUrl))
	return authUrl, http.StatusOK, nil
}

func (s *Service) EnableDriveCallback(ctx context.Context, userID, state, code string) (int, error) {
	s.logger.Info("handling Google Drive enable callback", zap.String("userID", userID), zap.String("state", state), zap.String("code", code))
	codeVerifier, err := s.storage.GetCode(ctx, code)
	if err != nil {
		s.logger.Error("failed to get code verifier", zap.Error(err))
		return http.StatusBadRequest, err
	}
	token, err := s.googleOAuth.Exchange(ctx, code, codeVerifier)
	if err != nil {
		s.logger.Error("failed to exchange code for token", zap.Error(err))
		return http.StatusBadRequest, err
	}
	accessToken := token.AccessToken
	refreshToken := token.RefreshToken
	accessTokenExpiry := token.Expiry
	sqlNullAccessTokenExpiry := sql.NullTime{Time: accessTokenExpiry, Valid: true}
	err = s.storage.UpdateUserDriveTokens(ctx, userID, accessToken, refreshToken, sqlNullAccessTokenExpiry)
	if err != nil {
		s.logger.Error("failed to update user drive tokens", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	s.logger.Info("Google Drive enabled successfully", zap.String("userID", userID))
	return http.StatusOK, nil
}

func (s *Service) SetSearchURL(ctx context.Context, userID, searchURL string) (int, error) {
	s.logger.Info("setting search URL", zap.String("userID", userID), zap.String("searchURL", searchURL))
	err := s.storage.UpdateUserSearchURL(ctx, userID, searchURL)
	if err != nil {
		s.logger.Error("failed to set search URL", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	s.logger.Info("search URL set successfully", zap.String("userID", userID))
	return http.StatusOK, nil
}

func (s *Service) GetSearchURL(ctx context.Context, userID string) (string, int, error) {
	s.logger.Info("getting search URL", zap.String("userID", userID))
	searchUrl, err := s.storage.SelectUserSearchURL(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get search URL", zap.Error(err))
		return searchUrl, http.StatusInternalServerError, err
	}
	s.logger.Info("search URL retrieved successfully", zap.String("userID", userID), zap.String("searchURL", searchUrl))
	return searchUrl, http.StatusOK, nil
}

func (s *Service) GetResumes(ctx context.Context, userID string, offset int) ([]struct {
	id          string
	lastUpdated sql.NullTime
}, int, error) {
	s.logger.Info("getting resumes", zap.String("userID", userID))
	resume, err := s.storage.SelectResumesByUser(ctx, userID, offset)
	if err != nil {
		s.logger.Error("failed to get resumes", zap.Error(err))
		return nil, http.StatusInternalServerError, err
	}
	s.logger.Info("resumes retrieved successfully", zap.String("userID", userID), zap.Int("count", len(resume)))
	return resume, http.StatusOK, nil
}

func (s *Service) UploadResume(ctx context.Context, userID, fileID string) (int, error) {
	s.logger.Info("uploading resume", zap.String("userID", userID), zap.String("fileID", fileID))
	drive, httpStatus, err := s.driveForUser(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get drive for user", zap.Error(err))
		return httpStatus, err
	}
	content, err := drive.ExportDocsAsText(ctx, fileID)
	if err != nil {
		s.logger.Error("failed to export resume content", zap.Error(err))
		return http.StatusBadRequest, err
	}
	chunks, err := ChunkText(content, 2000)
	if err != nil {
		s.logger.Error("failed to chunk resume content", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	embeddingResumes, err := s.embedder.GetEmbedding(ctx, chunks)
	if err != nil {
		s.logger.Error("failed to get resume embeddings", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	wg := sync.WaitGroup{}
	arrErr := make([]error, len(embeddingResumes))
	for k, embeddingResume := range embeddingResumes {
		wg.Add(1)
		go func(i int, embeddingResume []float32) {
			defer wg.Done()
			arrErr[i] = s.storage.InsertResumeEmbedding(ctx, userID, embeddingResume)
		}(k, embeddingResume)
	}
	wg.Wait()
	err = errors.Join(arrErr...)
	if err != nil {
		s.logger.Error("failed to insert resume embeddings", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	if err := s.storage.InsertResume(ctx, fileID, userID); err != nil {
		s.logger.Error("failed to insert resume", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	s.logger.Info("resume uploaded successfully", zap.String("userID", userID), zap.String("fileID", fileID))
	return http.StatusOK, nil
}

func (s *Service) GetJobs(ctx context.Context, userID string, offset int, status string) ([]struct {
	id          string
	status      string
	note        sql.NullString
	lastUpdated sql.NullTime
}, int, error) {
	s.logger.Info("getting jobs", zap.String("userID", userID), zap.Int("offset", offset), zap.String("status", status))
	drive, httpStatus, err := s.driveForUser(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get drive for user", zap.Error(err))
		return nil, httpStatus, err
	}
	if st, err := s.fetchJobsIfNeeded(ctx, drive, userID); err != nil {
		s.logger.Error("failed to fetch jobs", zap.Error(err))
		return nil, st, err
	}
	if status == "" {
		s.logger.Info("retrieving all jobs", zap.String("userID", userID), zap.Int("offset", offset))
		jobs, err := s.storage.SelectJobsByUser(ctx, userID, offset)
		if err != nil {
			s.logger.Error("failed to get jobs", zap.Error(err))
			return nil, http.StatusInternalServerError, err
		}
		s.logger.Info("jobs retrieved successfully", zap.String("userID", userID), zap.Int("count", len(jobs)))
		return jobs, http.StatusOK, nil
	}
	jobs, err := s.storage.SelectJobByStatus(ctx, userID, status, offset)
	if err != nil {
		s.logger.Error("failed to get jobs by status", zap.Error(err))
		return nil, http.StatusInternalServerError, err
	}
	s.logger.Info("jobs by status retrieved successfully", zap.String("userID", userID), zap.String("status", status), zap.Int("count", len(jobs)))
	return jobs, http.StatusOK, nil
}

func (s *Service) UpdateJobNote(ctx context.Context, userID, jobID, note string) (int, error) {
	s.logger.Info("updating job note", zap.String("userID", userID), zap.String("jobID", jobID))
	if err := s.storage.UpdateJobNote(ctx, userID, jobID, note); err != nil {
		s.logger.Error("failed to update job note", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	s.logger.Info("job note updated successfully", zap.String("userID", userID), zap.String("jobID", jobID))
	return http.StatusOK, nil
}

func (s *Service) UpdateJobStatus(ctx context.Context, userID, jobID, status string) (int, error) {
	s.logger.Info("updating job status", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("status", status))
	switch status {
	case JobStatusInterested:
		drive, httpStatus, err := s.driveForUser(ctx, userID)
		if err != nil {
			s.logger.Error("failed to get drive for user", zap.Error(err))
			return httpStatus, err
		}
		rootFolderID, err := drive.CreateFolderIfNotExists(ctx, s.rootFolderName, "")
		if err != nil {
			s.logger.Error("failed to create or get root folder", zap.Error(err))
			return http.StatusInternalServerError, err
		}
		jobFolderID, err := drive.CreateFolderIfNotExists(ctx, jobID, rootFolderID)
		if err != nil {
			s.logger.Error("failed to create or get job folder", zap.Error(err))
			return http.StatusInternalServerError, err
		}
		_, err = drive.CopyFile(ctx, jobID, jobFolderID)
		if err != nil {
			s.logger.Error("failed to copy job file to job folder", zap.Error(err))
			return http.StatusInternalServerError, err
		}
		if err := s.storage.UpdateJobGoogleDriveID(ctx, userID, jobID, jobFolderID); err != nil {
			s.logger.Error("failed to update job Google Drive ID", zap.Error(err))
			return http.StatusInternalServerError, err
		}
		if err := s.storage.UpdateJobStatus(ctx, userID, jobID, JobStatusInterested); err != nil {
			s.logger.Error("failed to update job status to interested", zap.Error(err))
			return http.StatusInternalServerError, err
		}
		s.logger.Info("job status updated to interested successfully", zap.String("userID", userID), zap.String("jobID", jobID))
		return http.StatusOK, nil
	case JobStatusPending, JobStatusNotInterested, JobStatusApplied, JobStatusInterviewing, JobStatusOffered, JobStatusRejected:
		if err := s.storage.UpdateJobStatus(ctx, userID, jobID, status); err != nil {
			s.logger.Error("failed to update job status", zap.Error(err))
			return http.StatusInternalServerError, err
		}
		s.logger.Info("job status updated successfully", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("status", status))
		return http.StatusOK, nil
	default:
		s.logger.Error("invalid job status", zap.String("status", status))
		return http.StatusBadRequest, errors.New("invalid job status")
	}
}

func (s *Service) GetJobDetails(ctx context.Context, userID, jobID string) (string, int, error) {
	s.logger.Info("getting job details", zap.String("userID", userID), zap.String("jobID", jobID))
	jobContent, err := s.storage.GetJobContent(ctx, jobID)
	if err != nil {
		s.logger.Error("failed to get job content", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	s.logger.Info("job details retrieved successfully", zap.String("userID", userID), zap.String("jobID", jobID))
	return jobContent, http.StatusOK, nil
}

func (s *Service) fetchJobsIfNeeded(ctx context.Context, drive IDrive, userID string) (int, error) {
	s.logger.Info("checking if job fetch is needed", zap.String("userID", userID))
	lastSearched, err := s.storage.SelectUserLastSearched(ctx, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.logger.Error("failed to get user's last searched time", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	if lastSearched.Valid && lastSearched.Time.After(time.Now().Add(-24*time.Hour)) {
		s.logger.Info("job fetch not needed, last searched within 24 hours", zap.String("userID", userID))
		return http.StatusOK, nil
	}
	searchUrl, err := s.storage.SelectUserSearchURL(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get user's search URL", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	if searchUrl == "" {
		s.logger.Info("job fetch not needed, no search URL set", zap.String("userID", userID))
		return http.StatusOK, nil
	}
	jobIdData, err := s.jobFetcher.Fetch(ctx, searchUrl)
	if err != nil {
		s.logger.Error("failed to fetch jobs", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	wg := sync.WaitGroup{}
	resumes, err := s.storage.SelectResumesByUser(ctx, userID, -1)
	if err != nil {
		s.logger.Error("failed to get resumes for user", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	// Update resumes if modified in Google Drive
	arrErr := make([]error, len(resumes))
	for k, resume := range resumes {
		wg.Add(1)
		go func(i int, resume struct {
			id          string
			lastUpdated sql.NullTime
		}) {
			defer wg.Done()
			lastModified, err := drive.LastModifiedTime(ctx, resume.id)
			if err != nil {
				arrErr[i] = err
				return
			}
			if !resume.lastUpdated.Valid || lastModified.After(resume.lastUpdated.Time) {
				if _, err := s.UploadResume(ctx, userID, resume.id); err != nil {
					arrErr[i] = err
					return
				}
			}
		}(k, resume)
	}

	arrErr = make([]error, len(jobIdData))
	for k, jobIdDatum := range jobIdData {
		wg.Add(1)
		go func(i int, jobIdDatum IdMarshaledJob) {
			defer wg.Done()
			jobString := string(json.RawMessage(jobIdDatum.RawMessage))
			chunks, err := ChunkText(jobString, 2000)
			if err != nil {
				arrErr[i] = err
				return
			}
			embeddingJobs, err := s.embedder.GetEmbedding(ctx, chunks)
			if err != nil {
				arrErr[i] = err
				return
			}
			idCounts := make(map[string]float32)
			for _, embeddingJob := range embeddingJobs {
				resumes, err := s.storage.SelectResumesByEmbedding(ctx, userID, embeddingJob, 1)
				if err != nil {
					arrErr[i] = err
					return
				}
				if len(resumes) == 0 {
					// A similar job already exists, skip inserting
					continue
				}
				resumeId := resumes[0].id
				idCounts[resumeId] += resumes[0].similarity
			}
			mostCommonId := lazyiterate.Reduce2(maps.All(idCounts), func(a, k string, v float32) string {
				if a == "" || v > idCounts[a] {
					return k
				}
				return a
			}, "")
			if mostCommonId == "" {
				// No similar resume found, skip inserting
				return
			}
			err = s.storage.InsertJob(ctx, jobIdDatum.Id, userID, mostCommonId, jobString)
			if err != nil {
				arrErr[i] = err
				return
			}
		}(k, jobIdDatum)
	}
	wg.Wait()
	err = errors.Join(arrErr...)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := s.storage.UpdateUserLastSearched(ctx, userID); err != nil {
		s.logger.Error("failed to update user's last searched time", zap.Error(err))
		return http.StatusInternalServerError, err
	}
	s.logger.Info("job fetch completed successfully", zap.String("userID", userID))
	return http.StatusOK, nil
}

func sqlNullTime(t time.Time) sql.NullTime { return sql.NullTime{Time: t, Valid: true} }

func (s *Service) driveForUser(ctx context.Context, userID string) (IDrive, int, error) {
	access, refresh, expiry, err := s.storage.SelectUserDriveTokens(ctx, userID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	// if expiry invalid or expired and we have refresh token, refresh
	if (expiry.Valid && time.Now().After(expiry.Time)) && refresh != "" {
		newTok, err := s.googleOAuth.Refresh(ctx, refresh)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		access = newTok.AccessToken
		// update storage with new access token & expiry
		_ = s.storage.UpdateUserDriveTokens(ctx, userID, access, refresh, sqlNullTime(newTok.Expiry))
	}
	// Build oauth2.Token for drive client
	oauthTok := &oauth2.Token{AccessToken: access, RefreshToken: refresh, Expiry: expiry.Time}
	drive, err := NewGoogleDrive(ctx, oauthTok)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return drive, http.StatusOK, nil
}
