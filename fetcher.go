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
	Fetch(ctx context.Context, searchUrl string) ([]IdMarshaledJob, error)
}

type IdMarshaledJob struct {
	json.RawMessage
	Id string `json:"id"`
}

type JobFetcher struct {
	urlStr string
	token  string
	logger *zap.Logger
}

func NewJobFetcher(urlStr, token string, logger *zap.Logger) *JobFetcher {
	return &JobFetcher{
		urlStr: urlStr,
		token:  token,
		logger: logger,
	}
}

func (jf *JobFetcher) Fetch(ctx context.Context, searchUrl string) ([]IdMarshaledJob, error) {
	bodyObj := map[string]any{
		"count":        100,
		"urls":         []string{searchUrl},
		"scrapeSkills": true,
	}
	bodyJson, err := json.Marshal(bodyObj)
	if err != nil {
		jf.logger.Error("Failed to marshal fetch body", zap.String("searchUrl", searchUrl), zap.Error(err))
		return nil, err
	}
	bodyReader := strings.NewReader(string(bodyJson))
	resp, err := fetchUrl(ctx, jf.urlStr, jf.token, bodyReader)
	if err != nil {
		jf.logger.Error("Failed to fetch jobs", zap.String("searchUrl", searchUrl), zap.Error(err))
		return nil, err
	}
	defer resp.Body.Close()
	var jobs []IdMarshaledJob
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&jobs)
	if err != nil {
		jf.logger.Error("Failed to decode jobs response", zap.String("searchUrl", searchUrl), zap.Error(err))
		return nil, err
	}
	return jobs, nil
}

func fetchUrl(ctx context.Context, urlStr, token string, body io.Reader) (*http.Response, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		return nil, err
	}
	req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return client.Do(req)
}
