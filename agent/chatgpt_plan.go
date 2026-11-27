package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/norma/llm"
)

// FormatChatGPTPlan marks a profile that runs on the operator's ChatGPT plan
// through "Sign in with ChatGPT" OAuth instead of an API key. On the wire it is
// the OpenAI Responses API (llm.FormatOpenAIResponses) at ChatGPTPlanBaseURL;
// chatgptPlanTransport supplies the OAuth access token and adapts each request
// to what plan-billed inference accepts.
const FormatChatGPTPlan llm.Format = "chatgpt-plan"

// ChatGPTPlanBaseURL is the only endpoint plan-billed inference is documented
// for (POST /responses, GET /models).
const ChatGPTPlanBaseURL = "https://api.openai.com/v1"

// chatgptPlanEndpoint is the base URL NewProvider uses; tests point it at a fake.
var chatgptPlanEndpoint = ChatGPTPlanBaseURL

// chatgptPlanPlaceholderKey stands in for the API key the SDK requires; the
// transport replaces the Authorization header on every request, so this value
// never leaves the process.
const chatgptPlanPlaceholderKey = "chatgpt-plan-oauth"

// TokenSource returns a currently valid OAuth access token, refreshing it when
// needed. Errors are surfaced to the caller as no-failover errors.
// Implementations must be comparable (Config values are compared with ==), e.g.
// a small struct holding a pointer and an account id.
type TokenSource interface {
	AccessToken(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a function to TokenSource (tests; not comparable, so
// never use it in a Config that gets compared).
type TokenSourceFunc func(ctx context.Context) (string, error)

func (f *TokenSourceFunc) AccessToken(ctx context.Context) (string, error) { return (*f)(ctx) }

// chatgptPlanOmitFields are request fields plan-billed inference rejects
// (OpenAI "Models and inference": omit these fields). Norma's Responses adapter
// can send max_output_tokens and temperature; the rest are listed defensively.
var chatgptPlanOmitFields = []string{
	"background", "conversation", "max_output_tokens", "max_tool_calls", "metadata",
	"moderation", "multi_agent", "prompt", "prompt_cache_retention", "safety_identifier",
	"temperature", "top_logprobs", "top_p", "truncation", "user", "previous_response_id",
}

// chatgptPlanTransport authenticates requests with the OAuth access token and
// adapts them to plan-billed inference:
//
//   - the request body drops the rejected fields and always asks for a stream
//     (store:false is already Norma's default);
//   - a request that asked for stream:false (Provider.Complete: compaction,
//     summaries, task LLM calls) is streamed and answered with a synthetic JSON
//     response built from response.completed, which is the body Norma's
//     non-streaming parser expects;
//   - plan refusals become errors that carry llmpool.NoFailoverMarker, so no
//     failover path silently moves the work to another billing route;
//   - in a stream, response.failed is lifted into the top-level error Norma
//     reads, and a stream that ends before a terminal event becomes an error.
type chatgptPlanTransport struct {
	base   http.RoundTripper
	tokens TokenSource
}

func (t *chatgptPlanTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.tokens == nil {
		return nil, fmt.Errorf("%s ChatGPT plan profile has no signed-in account", llmpool.NoFailoverMarker)
	}
	token, err := t.tokens.AccessToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("%s ChatGPT sign-in: %w", llmpool.NoFailoverMarker, err)
	}
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+token)

	wantStream := true
	if req.Method == http.MethodPost && req.Body != nil && strings.HasSuffix(req.URL.Path, "/responses") {
		raw, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		body, stream, err := adaptChatGPTPlanBody(raw)
		if err != nil {
			return nil, err
		}
		wantStream = stream
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		out.Header.Set("Accept", "text/event-stream")
	}

	resp, err := t.base.RoundTrip(out)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode >= 400 {
		return mapChatGPTPlanHTTPError(resp), nil
	}
	if out.Header.Get("Accept") != "text/event-stream" {
		return resp, nil // e.g. GET /models
	}
	if !wantStream {
		return bridgeChatGPTPlanStream(resp), nil
	}
	resp.Body = newChatGPTPlanSSEFilter(resp.Body)
	return resp, nil
}

// adaptChatGPTPlanBody removes the fields plan inference rejects and forces
// stream:true. It reports whether the caller itself asked for a stream.
func adaptChatGPTPlanBody(raw []byte) ([]byte, bool, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false, fmt.Errorf("chatgpt plan: request body is not a JSON object: %w", err)
	}
	stream := string(bytes.TrimSpace(m["stream"])) == "true"
	for _, f := range chatgptPlanOmitFields {
		delete(m, f)
	}
	m["stream"] = json.RawMessage("true")
	m["store"] = json.RawMessage("false")
	b, err := json.Marshal(m)
	return b, stream, err
}

// chatgptPlanErrorInfo describes one documented plan error code.
type chatgptPlanErrorInfo struct {
	status  int // status the caller sees (403 = durable refusal, 503 = transient)
	message string
}

// chatgptPlanErrors maps OpenAI's plan error codes (Errors and recovery) to the
// status ARTEX should act on and an operator-facing explanation. 403 is never
// retried on the same provider; 503 is, a few times, before surfacing.
var chatgptPlanErrors = map[string]chatgptPlanErrorInfo{
	"subscription_sharing_usage_limit_exceeded":   {403, "ChatGPT plan usage limit reached for ARTEX; it resumes when the limit resets (check https://chatgpt.com/settings/usage)"},
	"subscription_sharing_user_not_eligible":      {403, "this ChatGPT account is not eligible to use its plan in other apps"},
	"subscription_sharing_invalid_user":           {403, "the ChatGPT sign-in is no longer valid: sign in again in System > LLM"},
	"subscription_sharing_route_not_supported":    {403, "this request is not supported for ChatGPT plan usage"},
	"subscription_sharing_unsupported_capability": {403, "the request uses a capability ChatGPT plan usage does not support"},
	"chatpass_v2_scope_not_authorized":            {403, "plan usage was not granted to ARTEX: sign in again and allow plan usage"},
	"chatpass_v2_invalid_authorization_context":   {403, "the ChatGPT sign-in does not authorize plan usage: sign in again"},
	"subscription_sharing_usage_unavailable":      {503, "ChatGPT plan usage is temporarily unavailable"},
	"subscription_sharing_user_unavailable":       {503, "the ChatGPT account is temporarily unavailable"},
}

// chatgptPlanError extracts the documented error code/param/message from an
// error body: {"error":{"code","param","message"}}, a response object carrying
// "error", or a direct-admission {"detail":"..."}.
func chatgptPlanError(body []byte) (code, param, message string) {
	var v struct {
		Error *struct {
			Code    string `json:"code"`
			Param   string `json:"param"`
			Message string `json:"message"`
		} `json:"error"`
		Response *struct {
			Error *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		} `json:"response"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &v) != nil {
		return "", "", ""
	}
	switch {
	case v.Error != nil:
		return v.Error.Code, v.Error.Param, v.Error.Message
	case v.Response != nil && v.Response.Error != nil:
		return v.Response.Error.Code, "", v.Response.Error.Message
	default:
		return "", "", v.Detail
	}
}

// chatgptPlanErrorText builds the marked, operator-facing error text.
func chatgptPlanErrorText(code, param, message string) (int, string) {
	info, known := chatgptPlanErrors[code]
	if !known {
		info = chatgptPlanErrorInfo{403, "ChatGPT plan request refused"}
	}
	text := llmpool.NoFailoverMarker + " " + info.message
	if code != "" {
		text += " (" + code
		if param != "" {
			text += ", param " + param
		}
		text += ")"
	}
	if message != "" {
		text += ": " + truncateRunes(message, 300)
	}
	return info.status, text
}

// mapChatGPTPlanHTTPError rewrites a plan refusal into a response whose status
// and body the rest of ARTEX acts on correctly. Errors that are not plan
// refusals (a bad model name, an ordinary 5xx) pass through unchanged and keep
// the normal retry and failover policy.
func mapChatGPTPlanHTTPError(resp *http.Response) *http.Response {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	code, param, message := chatgptPlanError(raw)
	planCode := strings.HasPrefix(code, "subscription_sharing_") || strings.HasPrefix(code, "chatpass_")
	var status int
	var text string
	switch {
	case planCode:
		status, text = chatgptPlanErrorText(code, param, message)
	case resp.StatusCode == http.StatusUnauthorized:
		status, text = chatgptPlanErrorText("subscription_sharing_invalid_user", "", message)
	case resp.StatusCode == http.StatusForbidden:
		// Direct admission refusals (policy or region) arrive as {"detail":...}.
		status, text = http.StatusForbidden, llmpool.NoFailoverMarker+" ChatGPT plan request refused by policy or region: "+truncateRunes(message, 300)
	default:
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		return resp
	}
	return syntheticJSONResponse(resp, status, chatgptPlanErrorBody(text, code))
}

func chatgptPlanErrorBody(text, code string) []byte {
	b, _ := json.Marshal(map[string]any{"error": map[string]string{"message": text, "code": code}})
	return b
}

func syntheticJSONResponse(orig *http.Response, status int, body []byte) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         orig.Proto,
		ProtoMajor:    orig.ProtoMajor,
		ProtoMinor:    orig.ProtoMinor,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       orig.Request,
	}
}

// sseEvent is one Server-Sent Event: its event name and joined data lines.
type sseEvent struct {
	name string
	data string
}

// sseReader reads Responses SSE events one at a time.
type sseReader struct{ r *bufio.Reader }

func newSSEReader(r io.Reader) *sseReader { return &sseReader{bufio.NewReaderSize(r, 64<<10)} }

func (s *sseReader) next() (sseEvent, error) {
	var ev sseEvent
	var data []string
	for {
		line, err := s.r.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(trimmed, "event:"):
			ev.name = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
		case strings.HasPrefix(trimmed, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(trimmed, "data:"), " "))
		case trimmed == "" && (ev.name != "" || len(data) > 0):
			ev.data = strings.Join(data, "\n")
			return ev, nil
		}
		if err != nil {
			if err == io.EOF && (ev.name != "" || len(data) > 0) {
				ev.data = strings.Join(data, "\n")
				return ev, nil
			}
			return sseEvent{}, err
		}
	}
}

// eventType returns the event name, falling back to the JSON "type" field.
func (e sseEvent) eventType() string {
	if e.name != "" {
		return e.name
	}
	var v struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal([]byte(e.data), &v)
	return v.Type
}

func isTerminalEvent(kind string) bool {
	switch kind {
	case "response.completed", "response.incomplete", "response.failed", "error":
		return true
	}
	return false
}

// failedEventError turns a response.failed / error event into the marked error
// text when it carries a plan code, else the provider's own message.
func failedEventError(data string) string {
	code, param, message := chatgptPlanError([]byte(data))
	if strings.HasPrefix(code, "subscription_sharing_") || strings.HasPrefix(code, "chatpass_") {
		_, text := chatgptPlanErrorText(code, param, message)
		return text
	}
	if message == "" {
		message = "the response failed"
	}
	if code != "" {
		message += " (" + code + ")"
	}
	return message
}

// newChatGPTPlanSSEFilter passes a Responses stream through unchanged except
// for its terminal failure: response.failed (whose error Norma looks for at the
// top level, not under response.error) is re-emitted as an "error" event with
// the explanation, and a stream that ends with no terminal event gets one, so
// it is reported as a failure rather than a short answer.
func newChatGPTPlanSSEFilter(body io.ReadCloser) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		defer body.Close()
		r := newSSEReader(body)
		terminal := false
		for {
			ev, err := r.next()
			if err != nil {
				if !terminal {
					msg := "the ChatGPT plan stream ended before response.completed"
					if err != io.EOF {
						msg += ": " + err.Error()
					}
					writeSSEError(pw, msg)
				}
				_ = pw.Close()
				return
			}
			kind := ev.eventType()
			if kind == "response.failed" || kind == "error" {
				terminal = true
				writeSSEError(pw, failedEventError(ev.data))
				continue
			}
			terminal = terminal || isTerminalEvent(kind)
			var buf strings.Builder
			if ev.name != "" {
				buf.WriteString("event: " + ev.name + "\n")
			}
			for _, line := range strings.Split(ev.data, "\n") {
				buf.WriteString("data: " + line + "\n")
			}
			buf.WriteString("\n")
			if _, err := io.WriteString(pw, buf.String()); err != nil {
				return // reader closed (caller stopped consuming)
			}
		}
	}()
	return pr
}

func writeSSEError(w io.Writer, message string) {
	b, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"message": message}})
	_, _ = io.WriteString(w, "event: error\ndata: "+string(b)+"\n\n")
}

// bridgeChatGPTPlanStream answers a non-streaming request from a stream: it
// reads to the terminal event and returns the final response object as a JSON
// body (status 200), or the failure as a marked error response.
func bridgeChatGPTPlanStream(resp *http.Response) *http.Response {
	defer resp.Body.Close()
	r := newSSEReader(resp.Body)
	for {
		ev, err := r.next()
		if err != nil {
			msg := "the ChatGPT plan stream ended before response.completed"
			if !errors.Is(err, io.EOF) {
				msg += ": " + err.Error()
			}
			return syntheticJSONResponse(resp, http.StatusBadGateway, chatgptPlanErrorBody(msg, ""))
		}
		switch ev.eventType() {
		case "response.completed", "response.incomplete":
			var v struct {
				Response json.RawMessage `json:"response"`
			}
			if json.Unmarshal([]byte(ev.data), &v) != nil || len(v.Response) == 0 {
				return syntheticJSONResponse(resp, http.StatusBadGateway, chatgptPlanErrorBody("malformed response.completed event", ""))
			}
			return syntheticJSONResponse(resp, http.StatusOK, v.Response)
		case "response.failed", "error":
			text := failedEventError(ev.data)
			status := http.StatusBadGateway
			if strings.Contains(text, llmpool.NoFailoverMarker) {
				code, _, _ := chatgptPlanError([]byte(ev.data))
				status, _ = chatgptPlanErrorText(code, "", "")
			}
			return syntheticJSONResponse(resp, status, chatgptPlanErrorBody(text, ""))
		}
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
