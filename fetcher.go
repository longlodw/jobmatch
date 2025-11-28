package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

type IJobFetcher interface {
	InitiateFetch(ctx context.Context, searchUrl string) (runID, datasetID string, err error)
	FinalizeFetch(ctx context.Context, runID, datasetID string) ([]json.RawMessage, bool, error)
}

type JobFetcher struct {
	urlBaseStr string
	token      string
	logger     *zap.Logger
}

func NewJobFetcher(urlStr, token string, logger *zap.Logger) *JobFetcher {
	return &JobFetcher{
		urlBaseStr: urlStr,
		token:      token,
		logger:     logger,
	}
}

func (jf *JobFetcher) InitiateFetch(ctx context.Context, searchUrl string) (runID, datasetID string, err error) {
	bodyObj := map[string]any{
		"count":        100,
		"urls":         []string{searchUrl},
		"scrapeSkills": true,
	}
	bodyJson, err := json.Marshal(bodyObj)
	if err != nil {
		jf.logger.Error("Failed to marshal fetch body", zap.String("searchUrl", searchUrl), zap.Error(err))
		return "", "", err
	}
	bodyReader := strings.NewReader(string(bodyJson))
	fullUrl := jf.urlBaseStr + "/acts/curious_coder~linkedin-jobs-scraper/runs"
	resp, err := fetchUrl(ctx, "POST", fullUrl, jf.token, bodyReader)
	if err != nil {
		jf.logger.Error("Failed to fetch jobs", zap.String("searchUrl", searchUrl), zap.Error(err))
		return "", "", err
	}
	defer resp.Body.Close()
	var fetchResp InitiateFetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&fetchResp); err != nil {
		jf.logger.Error("Failed to decode fetch response", zap.String("searchUrl", searchUrl), zap.Error(err))
		return "", "", err
	}
	return fetchResp.Data.ID, fetchResp.Data.DefaultDatasetID, nil
}

func (jf *JobFetcher) FinalizeFetch(ctx context.Context, runID, datasetID string) ([]json.RawMessage, bool, error) {
	runUrl := jf.urlBaseStr + "/actor-runs/" + runID
	resp, err := fetchUrl(ctx, "GET", runUrl, jf.token, nil)
	if err != nil {
		jf.logger.Error("Failed to check run status", zap.String("runID", runID), zap.String("datasetID", datasetID), zap.Error(err))
		return nil, false, err
	}
	var statusResp InitiateFetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		jf.logger.Error("Failed to decode run status response", zap.String("runID", runID), zap.String("datasetID", datasetID), zap.Error(err))
		return nil, false, err
	}
	defer resp.Body.Close()
	jf.logger.Info("Run status", zap.String("runID", runID), zap.String("datasetID", datasetID), zap.String("status", statusResp.Data.Status))
	if statusResp.Data.Status == "RUNNING" || statusResp.Data.Status == "READY" {
		return nil, false, nil
	}
	if statusResp.Data.Status == "FAILED" || statusResp.Data.Status == "ABORTED" || statusResp.Data.Status == "TIMED_OUT" {
		jf.logger.Error("Run failed", zap.String("runID", runID), zap.String("datasetID", datasetID), zap.String("status", statusResp.Data.Status))
		return nil, true, nil
	}
	// Fetch the results
	fUrl := jf.urlBaseStr + "/datasets/" + datasetID + "/items"
	resp2, err := fetchUrl(ctx, "GET", fUrl, jf.token, nil)
	if err != nil {
		jf.logger.Error("Failed to finalize fetch", zap.String("runID", runID), zap.String("datasetID", datasetID), zap.Error(err))
		return nil, false, err
	}
	defer resp2.Body.Close()
	var results []json.RawMessage
	if err := json.NewDecoder(resp2.Body).Decode(&results); err != nil {
		jf.logger.Error("Failed to decode finalize fetch response", zap.String("runID", runID), zap.String("datasetID", datasetID), zap.Error(err))
		return nil, false, err
	}
	return results, true, nil
}

func fetchUrl(ctx context.Context, method, urlStr, token string, body io.Reader) (*http.Response, error) {
	client := &http.Client{}
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}
	req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return client.Do(req)
}

type InitiateFetchResponseInner struct {
	ID               string `json:"id"`
	DefaultDatasetID string `json:"defaultDatasetId"`
	Status           string `json:"status"`
}

type InitiateFetchResponse struct {
	Data InitiateFetchResponseInner `json:"data"`
}
