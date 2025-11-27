package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pkoukk/tiktoken-go"
	openai "github.com/sashabaranov/go-openai"
	"golang.org/x/sync/semaphore"
)

type IEmbedder interface {
	GetEmbedding(ctx context.Context, texts []string) ([][]float32, error)
}

type Embedder struct {
	client         *openai.Client
	sema           *semaphore.Weighted
	lastFailedTime time.Time
}

func NewEmbeder(baseUrl, apiKey string) *Embedder {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = baseUrl
	client := openai.NewClientWithConfig(config)
	return &Embedder{
		client: client,
		sema:   semaphore.NewWeighted(4), // limit to 4 concurrent requests
	}
}

func (e *Embedder) GetEmbedding(ctx context.Context, texts []string) ([][]float32, error) {
	if time.Since(e.lastFailedTime) < time.Minute {
		return nil, errors.New("embedder is in cooldown due to recent failure")
	}
	req := openai.EmbeddingRequest{
		Input: texts,
		Model: "all-MiniLM-L6-v2",
	}
	status := e.sema.Acquire(ctx, 1)
	if status != nil {
		e.lastFailedTime = time.Now()
		return nil, status
	}
	defer e.sema.Release(1)
	resp, err := e.client.CreateEmbeddings(ctx, req)
	if err != nil {
		e.lastFailedTime = time.Now()
		return nil, err
	}
	if len(resp.Data) == 0 {
		e.lastFailedTime = time.Now()
		return nil, nil
	}
	embeddings := make([][]float32, len(resp.Data))
	for i, data := range resp.Data {
		embeddings[i] = data.Embedding
	}
	return embeddings, nil
}

// ChunkText splits text into slices of ~chunkSize tokens
func ChunkText(text string, chunkSize int) ([]string, error) {
	enc, err := tiktoken.GetEncoding("cl100k_base")
	if err != nil {
		return nil, err
	}

	tokens := enc.Encode(text, nil, nil)
	var chunks [][]int
	increment := max(40, chunkSize/10) // overlap of 10% or at least 100 tokens

	for start := 0; start < len(tokens); start += increment {
		end := min(start+chunkSize, len(tokens))
		chunks = append(chunks, tokens[start:end])
	}
	textChunks := make([]string, len(chunks))
	wg := sync.WaitGroup{}
	for k, chunk := range chunks {
		wg.Add(1)
		go func(i int, c []int) {
			defer wg.Done()
			textChunk := enc.Decode(c)
			textChunks[i] = textChunk
		}(k, chunk)
	}
	wg.Wait()
	return textChunks, nil
}
