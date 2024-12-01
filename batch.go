package openai

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const batchesSuffix = "/batches"

// BatchEndpoint is all the endpoints that can be used in a batch.
type BatchEndpoint string

const (
	BatchEndpointChatCompletions BatchEndpoint = "/v1/chat/completions"
	BatchEndpointCompletions     BatchEndpoint = "/v1/completions"
	BatchEndpointEmbeddings      BatchEndpoint = "/v1/embeddings"
)

// BatchStatus corresponds to all possible batch states.
type BatchStatus string

const (
	BatchStatusValidating BatchStatus = "validating"
	BatchStatusFailed     BatchStatus = "failed"
	BatchStatusInProgress BatchStatus = "in_progress"
	BatchStatusFinalizing BatchStatus = "finalizing"
	BatchStatusCompleted  BatchStatus = "completed"
	BatchStatusExpired    BatchStatus = "expired"
	BatchStatusCancelling BatchStatus = "cancelling"
	BatchStatusCancelled  BatchStatus = "cancelled"
)

// Batch represents a Batch API descriptor.
type Batch struct {
	ID               string             `json:"id"`
	Object           string             `json:"object"`
	InputFileID      string             `json:"input_file_id"`
	CompletionWindow string             `json:"completion_window"`
	Endpoint         BatchEndpoint      `json:"endpoint"`
	Status           BatchStatus        `json:"status"`
	Errors           *BatchErrors       `json:"errors,omitempty"`
	OutputFileID     string             `json:"output_file_id,omitempty"`
	ErrorFileID      string             `json:"error_file_id,omitempty"`
	CreatedAt        int64              `json:"created_at"`
	InProgressAt     int64              `json:"in_progress_at,omitempty"`
	ExpiresAt        int64              `json:"expires_at,omitempty"`
	FinalizingAt     int64              `json:"finalizing_at,omitempty"`
	CompletedAt      int64              `json:"completed_at,omitempty"`
	FailedAt         int64              `json:"failed_at,omitempty"`
	ExpiredAt        int64              `json:"expired_at,omitempty"`
	CancellingAt     int64              `json:"cancelling_at,omitempty"`
	CancelledAt      int64              `json:"cancelled_at,omitempty"`
	RequestCounts    BatchRequestCounts `json:"request_counts,omitempty"`
	Metadata         map[string]any     `json:"metadata"`
}

func (b Batch) Value() (driver.Value, error)        { return json.Marshal(b) }
func (b BatchInput) Value() (driver.Value, error)   { return json.Marshal(b) }
func (b BatchOutput) Value() (driver.Value, error)  { return json.Marshal(b) }
func (b *Batch) Scan(value interface{}) error       { return scanJSON(value, &b) }
func (b *BatchInput) Scan(value interface{}) error  { return scanJSON(value, &b) }
func (b *BatchOutput) Scan(value interface{}) error { return scanJSON(value, &b) }

func scanJSON(value interface{}, target any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, target)
}

// BatchErrors is a group of errors.
type BatchErrors struct {
	Object string       `json:"object,omitempty"`
	Data   []BatchError `json:"data"`
}

// BatchError represents an error that occurred during batching.
type BatchError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Param   string `json:"param,omitempty"`
	Line    int    `json:"line,omitempty"`
}

// BatchRequestCounts provides statistics about the batch.
type BatchRequestCounts struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// CreateBatchRequest is the request to create a batch.
type CreateBatchRequest struct {
	InputFileID      string         `json:"input_file_id"`
	Endpoint         BatchEndpoint  `json:"endpoint"`
	CompletionWindow string         `json:"completion_window"`
	Metadata         map[string]any `json:"metadata"`
}

type BatchResponse struct {
	httpHeader
	Batch
}

// CreateBatch creates a batch.
func (c *Client) CreateBatch(
	ctx context.Context,
	request CreateBatchRequest,
) (response BatchResponse, err error) {
	if request.CompletionWindow == "" {
		request.CompletionWindow = "24h"
	}

	req, err := c.newRequest(ctx, http.MethodPost, c.fullURL(batchesSuffix), withBody(request))
	if err != nil {
		return
	}

	err = c.sendRequest(req, &response)
	return
}

// CreateFileBatch uploads a batch file.
func (c *Client) CreateFileBatch(ctx context.Context, inputs []BatchInput) (File, error) {
	var b bytes.Buffer
	w := json.NewEncoder(&b)
	for _, input := range inputs {
		err := w.Encode(input)
		if err != nil {
			return File{}, err
		}
	}
	return c.CreateFileBytes(ctx, FileBytesRequest{
		Name:    "batch.jsonl",
		Bytes:   b.Bytes(),
		Purpose: PurposeBatch,
	})
}

// RetrieveBatch retrieves a batch.
func (c *Client) RetrieveBatch(
	ctx context.Context,
	batchID string,
) (response BatchResponse, err error) {
	urlSuffix := fmt.Sprintf("%s/%s", batchesSuffix, batchID)
	req, err := c.newRequest(ctx, http.MethodGet, c.fullURL(urlSuffix))
	if err != nil {
		return
	}
	err = c.sendRequest(req, &response)
	return
}

// CancelBatch cancels a batch.
func (c *Client) CancelBatch(
	ctx context.Context,
	batchID string,
) (response BatchResponse, err error) {
	urlSuffix := fmt.Sprintf("%s/%s/cancel", batchesSuffix, batchID)
	req, err := c.newRequest(ctx, http.MethodPost, c.fullURL(urlSuffix))
	if err != nil {
		return
	}
	err = c.sendRequest(req, &response)
	return
}

// ListBatchResponse is a paginated batch list.
type ListBatchResponse struct {
	httpHeader
	Object  string  `json:"object"`
	Data    []Batch `json:"data"`
	FirstID string  `json:"first_id"`
	LastID  string  `json:"last_id"`
	HasMore bool    `json:"has_more"`
}

// ListBatch returns batches in the account.
func (c *Client) ListBatch(ctx context.Context, after *string, limit *int) (response ListBatchResponse, err error) {
	urlValues := url.Values{}
	if limit != nil {
		urlValues.Add("limit", fmt.Sprintf("%d", *limit))
	}
	if after != nil {
		urlValues.Add("after", *after)
	}
	encodedValues := ""
	if len(urlValues) > 0 {
		encodedValues = "?" + urlValues.Encode()
	}

	urlSuffix := fmt.Sprintf("%s%s", batchesSuffix, encodedValues)
	req, err := c.newRequest(ctx, http.MethodGet, c.fullURL(urlSuffix))
	if err != nil {
		return
	}

	err = c.sendRequest(req, &response)
	return
}

// GetBatchContent returns the contents of a batch output file.
func (c *Client) GetBatchContent(ctx context.Context, fileID string) ([]BatchOutput, error) {
	f, err := c.GetFileContent(ctx, fileID)
	if err != nil {
		return nil, err
	}
	r := json.NewDecoder(f)

	var outputs []BatchOutput
	for {
		var output BatchOutput

		switch err := r.Decode(&output); err {
		case nil:
			outputs = append(outputs, output)
		case io.EOF:
			return outputs, nil
		default:
			return nil, err
		}
	}
}

// BatchInput is the individual batch task (request).
type BatchInput struct {
	// CustomID is set by the client.
	CustomID       string                 `json:"custom_id"`
	Method         string                 `json:"method"`
	URL            BatchEndpoint          `json:"url"`
	MaxTokens      int                    `json:"max_tokens,omitempty"`
	Completion     *CompletionRequest     `json:"-"`
	ChatCompletion *ChatCompletionRequest `json:"-"`
	Embedding      *EmbeddingRequest      `json:"-"`
}

func (r BatchInput) MarshalJSON() (b []byte, err error) {
	if r.CustomID == "" {
		return nil, errors.New("custom_id is required")
	}
	var req = struct {
		CustomID  string          `json:"custom_id"`
		Method    string          `json:"method"`
		URL       BatchEndpoint   `json:"url"`
		MaxTokens int             `json:"max_tokens,omitempty"`
		Body      json.RawMessage `json:"body"`
	}{
		CustomID:  r.CustomID,
		Method:    "POST",
		MaxTokens: r.MaxTokens,
	}
	switch {
	case r.Completion != nil:
		req.Body, err = json.Marshal(r.Completion)
		req.URL = BatchEndpointCompletions
	case r.ChatCompletion != nil:
		req.Body, err = json.Marshal(r.ChatCompletion)
		req.URL = BatchEndpointChatCompletions
	case r.Embedding != nil:
		req.Body, err = json.Marshal(r.Embedding)
		req.URL = BatchEndpointEmbeddings
	default:
		return nil, errors.New("no fitting body")
	}
	if err != nil {
		return nil, fmt.Errorf("batch body: %w", err)
	}
	return json.Marshal(req)
}

func (r *BatchInput) UnmarshalJSON(data []byte) error {
	var req struct {
		CustomID  string          `json:"custom_id"`
		Method    string          `json:"method"`
		URL       BatchEndpoint   `json:"url"`
		MaxTokens int             `json:"max_tokens,omitempty"`
		Request   json.RawMessage `json:"body"`
	}
	err := json.Unmarshal(data, &req)
	if err != nil {
		return fmt.Errorf("batch content: %w", err)
	}
	*r = BatchInput{
		CustomID:  req.CustomID,
		Method:    req.Method,
		URL:       req.URL,
		MaxTokens: req.MaxTokens,
	}
	switch req.URL {
	case BatchEndpointCompletions:
		err = json.Unmarshal(req.Request, &r.Completion)
	case BatchEndpointChatCompletions:
		err = json.Unmarshal(req.Request, &r.ChatCompletion)
	case BatchEndpointEmbeddings:
		err = json.Unmarshal(req.Request, &r.Embedding)
	default:
		err = errors.New("unsupported batch url")
	}
	return err
}

func (r *BatchInput) Model() string {
	switch {
	case r.Completion != nil:
		return r.Completion.Model
	case r.ChatCompletion != nil:
		return r.ChatCompletion.Model
	case r.Embedding != nil:
		return r.Embedding.Model
	}
	return ""
}

// BatchOutput is the individual batch task (response).
type BatchOutput struct {
	// ID is set by the API.
	ID             string                  `json:"id"`
	CustomID       string                  `json:"custom_id"`
	Completion     *CompletionResponse     `json:"-"`
	ChatCompletion *ChatCompletionResponse `json:"-"`
	Embedding      *EmbeddingResponse      `json:"-"`
	Error          *APIError               `json:"error,omitempty"`

	response json.RawMessage `json:"-"`
}

func (r BatchOutput) MarshalJSON() (b []byte, err error) {
	if r.CustomID == "" {
		return nil, errors.New("custom_id is required")
	}
	var resp = struct {
		ID       string          `json:"id"`
		CustomID string          `json:"custom_id"`
		Error    *APIError       `json:"error,omitempty"`
		Response json.RawMessage `json:"response"`
	}{
		ID:       r.ID,
		CustomID: r.CustomID,
		Error:    r.Error,
		Response: r.response,
	}
	if r.response != nil || r.Error != nil {
		return json.Marshal(resp)
	}

	var blind = struct {
		StatusCode int    `json:"status_code"`
		RequestID  string `json:"request_id"`
		Body       any    `json:"body"`
	}{200, "", nil}
	switch {
	case r.Completion != nil:
		blind.Body = r.Completion
	case r.ChatCompletion != nil:
		blind.Body = r.ChatCompletion
	case r.Embedding != nil:
		blind.Body = r.Embedding
	default:
		return nil, errors.New("no response fitting")
	}
	resp.Response, err = json.Marshal(blind)
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (r *BatchOutput) UnmarshalJSON(data []byte) error {
	var resp struct {
		ID       string          `json:"id"`
		CustomID string          `json:"custom_id"`
		Error    *APIError       `json:"error,omitempty"`
		Response json.RawMessage `json:"response"`
	}
	err := json.Unmarshal(data, &resp)
	if err != nil {
		return err
	}
	*r = BatchOutput{
		ID:       resp.ID,
		CustomID: resp.CustomID,
		Error:    resp.Error,
		response: resp.Response,
	}

	var blind struct {
		Body struct {
			Object string `json:"object"`
		} `json:"body"`
	}
	err = json.Unmarshal(r.response, &blind)
	if err != nil {
		return err
	}
	switch blind.Body.Object {
	case "completion":
		var blind struct {
			Body *CompletionResponse `json:"body"`
		}
		err = json.Unmarshal(r.response, &blind)
		r.Completion = blind.Body
	case "chat.completion":
		var blind struct {
			Body *ChatCompletionResponse `json:"body"`
		}
		err = json.Unmarshal(r.response, &blind)
		r.ChatCompletion = blind.Body
	case "embedding":
		var blind struct {
			Body *EmbeddingResponse `json:"body"`
		}
		err = json.Unmarshal(r.response, &blind)
		r.Embedding = blind.Body
	default:
		err = errors.New("no response fitting")
	}
	return err
}
