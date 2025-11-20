package main

import (
	"context"
	"sync"

	"github.com/pkoukk/tiktoken-go"
	openai "github.com/sashabaranov/go-openai"
)

type IEmbedder interface {
	GetEmbedding(ctx context.Context, texts []string) ([][]float32, error)
}

type Embedder struct {
	client *openai.Client
}

func NewEmbeder(baseUrl, apiKey string) *Embedder {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = baseUrl
	client := openai.NewClientWithConfig(config)
	return &Embedder{client: client}
}

func (e *Embedder) GetEmbedding(ctx context.Context, texts []string) ([][]float32, error) {
	req := openai.EmbeddingRequest{
		Input: texts,
		Model: "gemini-embedding-001",
	}
	resp, err := e.client.CreateEmbeddings(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
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
	increment := max(100, chunkSize/10) // overlap of 10% or at least 100 tokens

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
