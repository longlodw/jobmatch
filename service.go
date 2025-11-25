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

type JobData struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	CompanyName string `json:"companyName"`
	Description string `json:"description"`
	Link        string `json:"link"`
	PostedAt    string `json:"postedAt"`
}

type Service struct {
	oAuth          IOAuth
	storage        IStorage
	jobFetcher     IJobFetcher
	embedder       IEmbedder
	rootFolderName string
	logger         *zap.Logger
}

func NewService(oAuth IOAuth, storage IStorage, jobFetcher IJobFetcher, embedder IEmbedder, rootFolderName string, logger *zap.Logger) *Service {
	return &Service{
		oAuth:          oAuth,
		storage:        storage,
		jobFetcher:     jobFetcher,
		embedder:       embedder,
		rootFolderName: rootFolderName,
		logger:         logger,
	}
}

func (s *Service) Login(ctx context.Context) (authUrl string, httpStatus int, err error) {
	s.logger.Info("initiating login")
	// scopes with openid and google drive read any file and edit files
	scopes := []string{"openid", "https://www.googleapis.com/auth/drive.readonly", "https://www.googleapis.com/auth/drive.file"}
	authUrl, state, codeVerifier, err := s.oAuth.Initiate(scopes)
	if err != nil {
		s.logger.Error("failed to initiate login", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	err = s.storage.StoreCode(ctx, state, codeVerifier)
	if err != nil {
		s.logger.Error("failed to store code", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	s.logger.Info("login initiated", zap.String("authUrl", authUrl))
	return authUrl, http.StatusOK, nil
}

func (s *Service) LoginCallback(ctx context.Context, state, code string) (idToken string, httpStatus int, err error) {
	s.logger.Info("handling login callback", zap.String("state", state), zap.String("code", code))
	codeVerifier, isValid, err := s.storage.GetCode(ctx, state)
	if err != nil {
		s.logger.Error("failed to get code verifier", zap.Error(err))
		return "", http.StatusBadRequest, err
	}
	if !isValid {
		s.logger.Error("invalid state parameter")
		return "", http.StatusBadRequest, errors.New("invalid state parameter")
	}
	token, err := s.oAuth.Exchange(ctx, code, codeVerifier)
	if err != nil {
		s.logger.Error("failed to exchange code for token", zap.Error(err))
		return "", http.StatusBadRequest, err
	}
	idToken, err = ExtractIDToken(token)
	if err != nil {
		s.logger.Error("failed to extract ID token", zap.Error(err))
		return "", http.StatusBadRequest, err
	}
	verifiedIDToken, err := s.oAuth.VerifyIDToken(ctx, idToken)
	if err != nil {
		s.logger.Error("failed to verify ID token", zap.Error(err))
		return "", http.StatusBadRequest, err
	}
	refreshToken := token.RefreshToken
	accessToken := token.AccessToken
	expiry := token.Expiry
	err = s.storage.InsertUser(ctx, verifiedIDToken.Subject, refreshToken, accessToken, expiry)
	if err != nil {
		s.logger.Error("failed to insert user", zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	s.logger.Info("login callback handled successfully", zap.String("userID", verifiedIDToken.Subject))
	return idToken, http.StatusOK, nil
}

func (s *Service) RefreshToken(ctx context.Context, userID string) (idToken, refreshToken, accessToken string, httpStatus int, err error) {
	s.logger.Info("refreshing token", zap.String("userID", userID))
	refreshToken, _, _, err = s.storage.SelectUserTokens(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get refresh token", zap.String("userID", userID), zap.Error(err))
		return "", "", "", http.StatusInternalServerError, err
	}
	newToken, err := s.oAuth.Refresh(ctx, refreshToken)
	if err != nil {
		s.logger.Error("failed to refresh token", zap.String("userID", userID), zap.Error(err))
		return "", "", "", http.StatusInternalServerError, err
	}
	idToken = newToken.Extra("id_token").(string)
	accessToken = newToken.AccessToken
	refreshToken = newToken.RefreshToken
	err = s.storage.InsertUser(ctx, userID, refreshToken, accessToken, newToken.Expiry)
	if err != nil {
		s.logger.Error("failed to update user tokens", zap.String("userID", userID), zap.Error(err))
		return "", "", "", http.StatusInternalServerError, err
	}
	newIDToken, err := ExtractIDToken(newToken)
	if err != nil {
		s.logger.Error("failed to extract new ID token", zap.String("userID", userID), zap.Error(err))
		return "", "", "", http.StatusInternalServerError, err
	}
	s.logger.Info("token refreshed successfully", zap.String("userID", userID))
	return newIDToken, refreshToken, accessToken, http.StatusOK, nil
}

func (s *Service) SetSearchURL(ctx context.Context, userID, searchURL string) (int, error) {
	s.logger.Info("setting search URL", zap.String("userID", userID), zap.String("searchURL", searchURL))
	err := s.storage.UpdateUserSearchURL(ctx, userID, searchURL)
	if err != nil {
		s.logger.Error("failed to set search URL", zap.String("userID", userID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	s.logger.Info("search URL set successfully", zap.String("userID", userID))
	return http.StatusOK, nil
}

func (s *Service) GetSearchURL(ctx context.Context, userID string) (string, int, error) {
	s.logger.Info("getting search URL", zap.String("userID", userID))
	searchUrl, err := s.storage.SelectUserSearchURL(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get search URL", zap.String("userID", userID), zap.Error(err))
		return searchUrl.String, http.StatusInternalServerError, err
	}
	s.logger.Info("search URL retrieved successfully", zap.String("userID", userID), zap.String("searchURL", searchUrl.String))
	return searchUrl.String, http.StatusOK, nil
}

func (s *Service) GetResumes(ctx context.Context, userID string, offset int) ([]ResumeMetadata, int, error) {
	s.logger.Info("getting resumes", zap.String("userID", userID))
	resume, err := s.storage.SelectResumesByUser(ctx, userID, offset)
	if err != nil {
		s.logger.Error("failed to get resumes", zap.String("userID", userID), zap.Error(err))
		return nil, http.StatusInternalServerError, err
	}
	s.logger.Info("resumes retrieved successfully", zap.String("userID", userID), zap.Int("count", len(resume)))
	return resume, http.StatusOK, nil
}

func (s *Service) UploadResume(ctx context.Context, userID, fileID string) (int, error) {
	s.logger.Info("uploading resume", zap.String("userID", userID), zap.String("fileID", fileID))
	drive, httpStatus, err := s.driveForUser(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get drive for user", zap.String("userID", userID), zap.Error(err))
		return httpStatus, err
	}
	content, err := drive.ExportDocsAsText(ctx, fileID)
	if err != nil {
		s.logger.Error("failed to export resume content", zap.String("userID", userID), zap.String("fileID", fileID), zap.Error(err))
		return http.StatusBadRequest, err
	}
	chunks, err := ChunkText(content, 2000)
	if err != nil {
		s.logger.Error("failed to chunk resume content", zap.String("userID", userID), zap.String("fileID", fileID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	embeddingResumes, err := s.embedder.GetEmbedding(ctx, chunks)
	if err != nil {
		s.logger.Error("failed to get resume embeddings", zap.String("userID", userID), zap.String("fileID", fileID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	if err := s.storage.InsertResume(ctx, fileID, userID, embeddingResumes); err != nil {
		s.logger.Error("failed to insert resume", zap.String("userID", userID), zap.String("fileID", fileID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	s.logger.Info("resume uploaded successfully", zap.String("userID", userID), zap.String("fileID", fileID))
	return http.StatusOK, nil
}

func (s *Service) GetJobs(ctx context.Context, userID string, offset int, status string) ([]JobMetadata, int, error) {
	s.logger.Info("getting jobs", zap.String("userID", userID), zap.Int("offset", offset), zap.String("status", status))
	drive, httpStatus, err := s.driveForUser(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get drive for user", zap.String("userID", userID), zap.Error(err))
		return nil, httpStatus, err
	}
	if st, err := s.fetchJobsIfNeeded(ctx, drive, userID); err != nil {
		s.logger.Error("failed to fetch jobs", zap.String("userID", userID), zap.Error(err))
		return nil, st, err
	}
	jobs, err := s.storage.SelectJobByStatus(ctx, userID, status)
	if err != nil {
		s.logger.Error("failed to get jobs by status", zap.String("userID", userID), zap.String("status", status), zap.Error(err))
		return nil, http.StatusInternalServerError, err
	}
	s.logger.Info("jobs by status retrieved successfully", zap.String("userID", userID), zap.String("status", status), zap.Int("count", len(jobs)))
	return jobs, http.StatusOK, nil
}

func (s *Service) UpdateJobStatus(ctx context.Context, userID, jobID, status string) (int, error) {
	s.logger.Info("updating job status", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("status", status))
	switch status {
	case JobStatusInterested:
		drive, httpStatus, err := s.driveForUser(ctx, userID)
		if err != nil {
			s.logger.Error("failed to get drive for user", zap.String("userID", userID), zap.Error(err))
			return httpStatus, err
		}
		rootFolderID, err := drive.CreateFolderIfNotExists(ctx, s.rootFolderName, "")
		if err != nil {
			s.logger.Error("failed to create or get root folder", zap.String("userID", userID), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		jobFolderID, err := drive.CreateFolderIfNotExists(ctx, jobID, rootFolderID)
		if err != nil {
			s.logger.Error("failed to create or get job folder", zap.String("userID", userID), zap.String("rootFolderID", rootFolderID), zap.String("jobID", jobID), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		_, err = drive.CopyFile(ctx, jobID, jobFolderID)
		if err != nil {
			s.logger.Error("failed to copy job file to job folder", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("jobFolderID", jobFolderID), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		sheetId, err := drive.CreateSheetIfNotExists(ctx, "Job Details", rootFolderID)
		if err != nil {
			s.logger.Error("failed to create or get job details sheet", zap.String("userID", userID), zap.String("rootFolderID", rootFolderID), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		jobContent, err := s.storage.GetJobContent(ctx, jobID)
		if err != nil {
			s.logger.Error("failed to get job content", zap.String("userID", userID), zap.String("jobID", jobID), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		jobFolderLink := drive.GetFileLink(jobFolderID)
		var jobContentObj JobData
		if err := json.Unmarshal([]byte(jobContent), &jobContentObj); err != nil {
			s.logger.Error("failed to unmarshal job content", zap.String("userID", userID), zap.String("jobID", jobID), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		rowToInsert := [][]any{{jobContentObj.Title, jobContentObj.CompanyName, jobContentObj.Description, jobContentObj.Link, jobContentObj.PostedAt, jobFolderLink}}
		if err := drive.InsertRows(ctx, sheetId, rowToInsert); err != nil {
			s.logger.Error("failed to insert job details into sheet", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("sheetId", sheetId), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		if err := s.storage.UpdateJobStatus(ctx, userID, jobID, JobStatusInterested); err != nil {
			s.logger.Error("failed to update job status", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("status", status), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		s.logger.Info("job status updated to interested successfully", zap.String("userID", userID), zap.String("jobID", jobID))
		return http.StatusOK, nil
	case JobStatusNotInterested:
		if err := s.storage.UpdateJobStatus(ctx, userID, jobID, status); err != nil {
			s.logger.Error("failed to update job status", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("status", status), zap.Error(err))
			return http.StatusInternalServerError, err
		}
		s.logger.Info("job status updated successfully", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("status", status))
		return http.StatusOK, nil
	default:
		s.logger.Error("invalid job status", zap.String("userID", userID), zap.String("jobID", jobID), zap.String("status", status))
		return http.StatusBadRequest, errors.New("invalid job status")
	}
}

func (s *Service) GetJobDetails(ctx context.Context, userID, jobID string) (string, int, error) {
	s.logger.Info("getting job details", zap.String("userID", userID), zap.String("jobID", jobID))
	jobContent, err := s.storage.GetJobContent(ctx, jobID)
	if err != nil {
		s.logger.Error("failed to get job content", zap.String("userID", userID), zap.String("jobID", jobID), zap.Error(err))
		return "", http.StatusInternalServerError, err
	}
	s.logger.Info("job details retrieved successfully", zap.String("userID", userID), zap.String("jobID", jobID))
	return jobContent, http.StatusOK, nil
}

func (s *Service) fetchJobsIfNeeded(ctx context.Context, drive IDrive, userID string) (int, error) {
	s.logger.Info("checking if job fetch is needed", zap.String("userID", userID))
	lastSearched, err := s.storage.SelectUserLastSearched(ctx, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.logger.Error("failed to get user's last searched time", zap.String("userID", userID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	if lastSearched.Valid && lastSearched.Time.After(time.Now().Add(-24*time.Hour)) {
		s.logger.Info("job fetch not needed, last searched within 24 hours", zap.String("userID", userID))
		return http.StatusOK, nil
	}
	searchUrl, err := s.storage.SelectUserSearchURL(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get user's search URL", zap.String("userID", userID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	if !searchUrl.Valid || searchUrl.String == "" {
		s.logger.Info("job fetch not needed, no search URL set", zap.String("userID", userID))
		return http.StatusOK, nil
	}
	jobIdData, err := s.jobFetcher.Fetch(ctx, searchUrl.String)
	if err != nil {
		s.logger.Error("failed to fetch jobs from search URL", zap.String("userID", userID), zap.String("searchURL", searchUrl.String), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	wg := sync.WaitGroup{}
	resumes, err := s.storage.SelectResumesByUser(ctx, userID, -1)
	if err != nil {
		s.logger.Error("failed to get resumes for user", zap.String("userID", userID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	// Update resumes if modified in Google Drive
	arrErr := make([]error, len(resumes))
	for k, resume := range resumes {
		wg.Add(1)
		go func(i int, resume ResumeMetadata) {
			defer wg.Done()
			lastModified, err := drive.LastModifiedTime(ctx, resume.ID)
			if err != nil {
				arrErr[i] = err
				return
			}
			if lastModified.After(resume.LastUpdated) {
				if _, err := s.UploadResume(ctx, userID, resume.ID); err != nil {
					arrErr[i] = err
					return
				}
				// update timestamp after successful re-upload
				_ = s.storage.UpdateResumeTimestamp(ctx, resume.ID, userID)
			}
		}(k, resume)
	}
	wg.Wait()
	err = errors.Join(arrErr...)
	if err != nil {
		s.logger.Error("failed to update resumes", zap.String("userID", userID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	// Process fetched jobs

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
				resumeId := resumes[0].ID
				idCounts[resumeId] += resumes[0].Similarity
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
		s.logger.Error("failed to process fetched jobs", zap.String("userID", userID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	if err := s.storage.UpdateUserLastSearched(ctx, userID); err != nil {
		s.logger.Error("failed to update user's last searched time", zap.String("userID", userID), zap.Error(err))
		return http.StatusInternalServerError, err
	}
	s.logger.Info("job fetch completed successfully", zap.String("userID", userID))
	return http.StatusOK, nil
}

func (s *Service) driveForUser(ctx context.Context, userID string) (IDrive, int, error) {
	access, refresh, expiry, err := s.storage.SelectUserTokens(ctx, userID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	// if expiry invalid or expired and we have refresh token, refresh
	if time.Now().After(expiry) {
		var httpStatus int
		_, refresh, access, httpStatus, err = s.RefreshToken(ctx, userID)
		if err != nil {
			return nil, httpStatus, err
		}
	}
	// Build oauth2.Token for drive client
	oauthTok := &oauth2.Token{AccessToken: access, RefreshToken: refresh, Expiry: expiry, TokenType: "Bearer"}
	drive, err := NewGoogleDrive(ctx, s.oAuth, oauthTok)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return drive, http.StatusOK, nil
}
