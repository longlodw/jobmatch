package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
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
}

func NewJobFetcher(urlStr, token string) *JobFetcher {
	return &JobFetcher{
		urlStr: urlStr,
		token:  token,
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
		return nil, err
	}
	bodyReader := strings.NewReader(string(bodyJson))
	resp, err := fetchUrl(ctx, jf.urlStr, jf.token, bodyReader)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var jobs []IdMarshaledJob
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&jobs)
	if err != nil {
		return nil, err
	}
	return jobs, nil
}

func fetchUrl(ctx context.Context, urlStr, token string, body io.Reader) (*http.Response, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	query := parsedURL.Query()
	query.Set("token", token)
	parsedURL.RawQuery = query.Encode()
	newUrl := parsedURL.String()
	client := &http.Client{}
	req, err := http.NewRequest("POST", newUrl, body)
	if err != nil {
		return nil, err
	}
	req.WithContext(ctx)
	return client.Do(req)
}
