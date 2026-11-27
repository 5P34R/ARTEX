package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/norma/llm"
)

const planToken = "synthetic-access-token"

// planServer fakes POST /responses. respond writes the reply for each request
// after the shared request checks; requests records how many arrived.
func planServer(t *testing.T, respond func(w http.ResponseWriter, body map[string]json.RawMessage)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/responses" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+planToken {
			t.Errorf("authorization = %q", got)
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if string(body["stream"]) != "true" || string(body["store"]) != "false" {
			t.Errorf("stream=%s store=%s, want true/false", body["stream"], body["store"])
		}
		for _, f := range []string{"max_output_tokens", "temperature", "metadata", "previous_response_id"} {
			if _, ok := body[f]; ok {
				t.Errorf("rejected field %q was sent", f)
			}
		}
		respond(w, body)
	}))
	t.Cleanup(srv.Close)
	prev := chatgptPlanEndpoint
	chatgptPlanEndpoint = srv.URL + "/v1"
	t.Cleanup(func() { chatgptPlanEndpoint = prev })
	return srv, &requests
}

func planProvider(t *testing.T) llm.Provider {
	t.Helper()
	cfg := ConfigFrom("chatgpt-plan", "gpt-plan-test", "https://ignored.example", "ignored-key", "")
	cfg.Retry.ConnectAttempts = -1 // one attempt: the tests count requests
	f := TokenSourceFunc(func(context.Context) (string, error) { return planToken, nil })
	cfg.TokenSource = &f
	p, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeSSE(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		var v struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal([]byte(e), &v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", v.Type, e)
	}
}

const completedEvent = `{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello from the plan"}]}],"usage":{"input_tokens":3,"output_tokens":4}}}`

func planRequest() llm.CompletionRequest {
	temp := 0.2
	return llm.CompletionRequest{
		System:      []string{"be brief"},
		Messages:    []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "hi"}}}},
		MaxTokens:   256,
		Temperature: &temp,
	}
}

func TestChatGPTPlanConfig(t *testing.T) {
	cfg := ConfigFrom("chatgpt-plan", "m", "https://evil.example/v1", "sk-should-be-dropped", "")
	if cfg.Format != FormatChatGPTPlan || cfg.BaseURL != ChatGPTPlanBaseURL || cfg.APIKey != "" || cfg.NeedsAPIKey() || cfg.Provider() != "chatgpt-plan" {
		t.Fatalf("config: %+v", cfg)
	}
	if _, err := cfg.NewProvider(); err == nil {
		t.Fatal("a chatgpt-plan provider without a token source must not build")
	}
}

func TestChatGPTPlanStreamAuthenticatesAndAdaptsBody(t *testing.T) {
	planServer(t, func(w http.ResponseWriter, body map[string]json.RawMessage) {
		if string(body["instructions"]) != `"be brief"` {
			t.Errorf("instructions = %s", body["instructions"])
		}
		writeSSE(w,
			`{"type":"response.created","response":{"status":"in_progress"}}`,
			`{"type":"response.output_text.delta","delta":"hello "}`,
			`{"type":"response.output_text.delta","delta":"from the plan"}`,
			completedEvent)
	})
	var text strings.Builder
	for ev, err := range planProvider(t).Stream(context.Background(), planRequest()) {
		if err != nil {
			t.Fatal(err)
		}
		if ev.Type == llm.SETextDelta {
			text.WriteString(ev.Text)
		}
	}
	if text.String() != "hello from the plan" {
		t.Fatalf("text = %q", text.String())
	}
}

// Provider.Complete sends stream:false; plan inference only streams, so the
// transport streams and hands Norma the final response object as JSON.
func TestChatGPTPlanCompleteBridgesTheStream(t *testing.T) {
	planServer(t, func(w http.ResponseWriter, _ map[string]json.RawMessage) {
		writeSSE(w, `{"type":"response.output_text.delta","delta":"hello from the plan"}`, completedEvent)
	})
	msg, _, usage, err := planProvider(t).Complete(context.Background(), planRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Content) != 1 || msg.Content[0].Text != "hello from the plan" || usage.OutputTokens != 4 {
		t.Fatalf("message=%+v usage=%+v", msg, usage)
	}
}

func TestChatGPTPlanUsageLimitIsANoFailoverRefusal(t *testing.T) {
	_, requests := planServer(t, func(w http.ResponseWriter, _ map[string]json.RawMessage) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"limit reached"}}`))
	})
	_, _, _, err := planProvider(t).Complete(context.Background(), planRequest())
	if err == nil || !llmpool.IsNoFailover(err) || llmpool.StatusOf(err) != 403 {
		t.Fatalf("err = %v, want a 403 carrying the no-failover marker", err)
	}
	if !strings.Contains(err.Error(), "usage limit") || !strings.Contains(err.Error(), "chatgpt.com/settings/usage") {
		t.Fatalf("error does not explain the limit: %v", err)
	}
	if IsQuotaExhaustedMessage(err.Error()) {
		t.Fatal("a plan limit must not look like exhausted API credit (that path fails over)")
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("requests = %d, want exactly 1 (a 403 is not retried)", n)
	}
}

func TestChatGPTPlanErrorMapping(t *testing.T) {
	cases := []struct {
		status     int
		body       string
		wantStatus int
		marked     bool
	}{
		{401, `{"detail":"token rejected"}`, 403, true},
		{403, `{"detail":"region not supported"}`, 403, true},
		{403, `{"error":{"code":"subscription_sharing_user_not_eligible","message":"x"}}`, 403, true},
		{503, `{"error":{"code":"subscription_sharing_usage_unavailable","message":"later"}}`, 503, true},
		{400, `{"error":{"code":"model_not_found","message":"no such model"}}`, 400, false},
		{500, `{"error":{"message":"boom"}}`, 500, false},
	}
	for _, c := range cases {
		planServer(t, func(w http.ResponseWriter, _ map[string]json.RawMessage) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		})
		_, _, _, err := planProvider(t).Complete(context.Background(), planRequest())
		if err == nil {
			t.Fatalf("%d %s: no error", c.status, c.body)
		}
		if got := llmpool.StatusOf(err); got != c.wantStatus || llmpool.IsNoFailover(err) != c.marked {
			t.Fatalf("%d %s: status=%d marked=%v err=%v", c.status, c.body, got, llmpool.IsNoFailover(err), err)
		}
	}
}

// OpenAI reports response.failed with the error under response.error; Norma
// reads a top-level error, so without the transport the failure would read
// "stream error". Plan codes also carry the marker.
func TestChatGPTPlanStreamFailureIsExplained(t *testing.T) {
	planServer(t, func(w http.ResponseWriter, _ map[string]json.RawMessage) {
		writeSSE(w,
			`{"type":"response.created","response":{"status":"in_progress"}}`,
			`{"type":"response.failed","response":{"status":"failed","error":{"code":"subscription_sharing_usage_limit_exceeded","message":"limit"}}}`)
	})
	var got error
	for _, err := range planProvider(t).Stream(context.Background(), planRequest()) {
		if err != nil {
			got = err
		}
	}
	if got == nil || !llmpool.IsNoFailover(got) || !strings.Contains(got.Error(), "usage limit") {
		t.Fatalf("err = %v", got)
	}
}

func TestChatGPTPlanTruncatedStreamIsAnError(t *testing.T) {
	planServer(t, func(w http.ResponseWriter, _ map[string]json.RawMessage) {
		writeSSE(w, `{"type":"response.output_text.delta","delta":"partial"}`) // no terminal event
	})
	var got error
	for _, err := range planProvider(t).Stream(context.Background(), planRequest()) {
		if err != nil {
			got = err
		}
	}
	if got == nil || !strings.Contains(got.Error(), "ended before response.completed") {
		t.Fatalf("stream err = %v", got)
	}
	_, _, _, err := planProvider(t).Complete(context.Background(), planRequest())
	if err == nil || !strings.Contains(err.Error(), "ended before response.completed") {
		t.Fatalf("complete err = %v", err)
	}
}

func TestChatGPTPlanTokenSourceFailureIsNoFailover(t *testing.T) {
	_, requests := planServer(t, func(http.ResponseWriter, map[string]json.RawMessage) {})
	cfg := ConfigFrom("chatgpt-plan", "m", "", "", "")
	cfg.Retry.ConnectAttempts = -1
	f := TokenSourceFunc(func(context.Context) (string, error) { return "", errors.New("refresh token expired: sign in again") })
	cfg.TokenSource = &f
	p, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = p.Complete(context.Background(), planRequest())
	if err == nil || !llmpool.IsNoFailover(err) || !strings.Contains(err.Error(), "sign in again") {
		t.Fatalf("err = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("a request was sent without a token")
	}
}
