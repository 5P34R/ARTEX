package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
)

// fakeOpenAIAuth is a minimal auth.openai.com: discovery, JWKS, token
// (authorization_code and refresh_token grants) and revocation.
type fakeOpenAIAuth struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	issued   string
	subject  string
	scope    string
	refreshN atomic.Int32
	revoked  atomic.Int32
	failNext atomic.Value // refresh error code to return once ("" = none)

	mu       sync.Mutex
	nonce    string
	verifier string
}

func newFakeOpenAIAuth(t *testing.T) *fakeOpenAIAuth {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOpenAIAuth{t: t, key: key, issued: "oaiapp_test123", subject: fmt.Sprintf("user-%d", time.Now().UnixNano()),
		scope: "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"}
	f.failNext.Store("")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": chatgptIssuer, "jwks_uri": f.srv.URL + "/jwks", "revocation_endpoint": f.srv.URL + "/revoke"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "k1", "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("token_type_hint") != "refresh_token" || r.Form.Get("client_id") != f.issued {
			t.Errorf("revoke form: %v", r.Form)
		}
		f.revoked.Add(1)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOpenAIAuth) idToken(nonce string) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": chatgptIssuer, "aud": f.issued, "sub": f.subject, "email": "operator@example.com",
		"nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fakeOpenAIAuth) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("resource") != chatgptResource || r.Form.Get("client_id") != f.issued {
		f.t.Errorf("token form: resource=%q client_id=%q", r.Form.Get("resource"), r.Form.Get("client_id"))
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		f.mu.Lock()
		verifier, nonce := f.verifier, f.nonce
		f.mu.Unlock()
		if r.Form.Get("code") != "the-code" || r.Form.Get("code_verifier") != verifier || !strings.HasSuffix(r.Form.Get("redirect_uri"), chatgptCallbackPath) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-1", "refresh_token": "refresh-1", "id_token": f.idToken(nonce), "expires_in": 3600, "scope": f.scope, "token_type": "Bearer"})
	case "refresh_token":
		if code, _ := f.failNext.Load().(string); code != "" {
			f.failNext.Store("")
			w.WriteHeader(400)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
			return
		}
		n := f.refreshN.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("access-r%d", n), "refresh_token": fmt.Sprintf("refresh-r%d", n), "expires_in": 3600, "scope": f.scope})
	default:
		w.WriteHeader(400)
	}
}

// signin drives startSignin + completeSignin the way the browser would.
func (f *fakeOpenAIAuth) signin(t *testing.T, o *chatgptOAuth, tamper func(q url.Values)) (*db.ChatGPTAccount, url.Values, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/llm/chatgpt/signin", nil)
	authURL, redirectURI, err := o.startSignin(req, chatgptSigninRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if redirectURI != "http://127.0.0.1:8787/auth/callback" {
		t.Fatalf("redirect_uri = %s", redirectURI)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	o.mu.Lock()
	p := o.pending[q.Get("state")]
	o.mu.Unlock()
	f.mu.Lock()
	f.nonce, f.verifier = q.Get("nonce"), p.verifier
	f.mu.Unlock()
	cb := url.Values{"code": {"the-code"}, "state": {q.Get("state")}, "scope": {f.scope}, "client_id": {f.issued}}
	if tamper != nil {
		tamper(cb)
	}
	a, err := o.completeSignin(context.Background(), cb)
	return a, q, err
}

func newTestChatGPTOAuth(t *testing.T, f *fakeOpenAIAuth) (*chatgptOAuth, *db.DB) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { d.Close() })
	if err := d.InitSecrets(t.TempDir()); err != nil { // key comes from ARTEX_SECRET_KEY (testmain)
		t.Fatal(err)
	}
	_, _ = d.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, db.SettingChatGPTClientID, db.SettingChatGPTHostID)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM chatgpt_accounts WHERE subject=$1`, f.subject)
		_, _ = d.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, db.SettingChatGPTClientID, db.SettingChatGPTHostID)
	})
	o := newChatGPTOAuth(func() *db.DB { return d })
	o.endpoints = chatgptEndpoints{Authorize: f.srv.URL + "/authorize", Token: f.srv.URL + "/token", Discovery: f.srv.URL + "/.well-known/openid-configuration"}
	return o, d
}

func TestChatGPTSigninRegistersRefreshesAndSignsOut(t *testing.T) {
	f := newFakeOpenAIAuth(t)
	o, d := newTestChatGPTOAuth(t, f)

	a, q, err := f.signin(t, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	// First sign-in registers dynamically.
	if q.Get("client_id") != chatgptDynamicClientID || q.Get("agent_name_hint") != "ARTEX" || q.Get("code_challenge_method") != "S256" ||
		q.Get("resource") != chatgptResource || !strings.HasPrefix(q.Get("ext_agent_host_id"), "urn:uuid:") || !strings.Contains(q.Get("scope"), chatgptScopePlanUse) {
		t.Fatalf("authorize query: %v", q)
	}
	if issued, _, _ := d.GetSetting(db.SettingChatGPTClientID); issued != f.issued {
		t.Fatalf("issued client id not kept: %q", issued)
	}
	if a.Status != db.ChatGPTStatusActive || a.Email != "operator@example.com" || a.ClientID != f.issued {
		t.Fatalf("account: %+v", a)
	}

	// A second sign-in reuses the issued client ID, without agent_name_hint, same host id.
	_, q2, err := f.signin(t, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if q2.Get("client_id") != f.issued || q2.Has("agent_name_hint") || q2.Get("ext_agent_host_id") != q.Get("ext_agent_host_id") {
		t.Fatalf("returning authorize query: %v", q2)
	}

	ts := chatgptTokenSource{o: o, accountID: a.ID}
	if tok, err := ts.AccessToken(context.Background()); err != nil || tok != "access-1" {
		t.Fatalf("fresh token: %q %v", tok, err)
	}
	// Near expiry: concurrent callers refresh exactly once and get the rotated token.
	o.now = func() time.Time { return time.Now().Add(58 * time.Minute) }
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, err := ts.AccessToken(context.Background()); err != nil || tok != "access-r1" {
				t.Errorf("refreshed token: %q %v", tok, err)
			}
		}()
	}
	wg.Wait()
	if n := f.refreshN.Load(); n != 1 {
		t.Fatalf("refreshes = %d, want 1", n)
	}
	got, _ := d.ChatGPTAccountByID(a.ID)
	if got.RefreshToken != "refresh-r1" {
		t.Fatalf("rotated refresh token not stored: %q", got.RefreshToken)
	}

	revoked, err := o.signOut(context.Background(), a.ID)
	if err != nil || !revoked || f.revoked.Load() != 1 {
		t.Fatalf("sign-out: revoked=%v err=%v", revoked, err)
	}
	if _, err := ts.AccessToken(context.Background()); !errors.Is(err, errChatGPTSignin) {
		t.Fatalf("after sign-out: %v", err)
	}
}

func TestChatGPTTerminalRefreshRequiresSignin(t *testing.T) {
	f := newFakeOpenAIAuth(t)
	o, d := newTestChatGPTOAuth(t, f)
	a, _, err := f.signin(t, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	o.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	f.failNext.Store("refresh_token_reused")
	if _, err := (chatgptTokenSource{o: o, accountID: a.ID}).AccessToken(context.Background()); !errors.Is(err, errChatGPTSignin) {
		t.Fatalf("terminal refresh: %v", err)
	}
	got, _ := d.ChatGPTAccountByID(a.ID)
	if got.Status != db.ChatGPTStatusNeedsSignin || got.RefreshToken != "" || got.ClientID != f.issued {
		t.Fatalf("after terminal refresh: %+v", got)
	}
}

func TestChatGPTCallbackRejections(t *testing.T) {
	f := newFakeOpenAIAuth(t)
	o, _ := newTestChatGPTOAuth(t, f)
	cases := map[string]func(q url.Values){
		"declined":           func(q url.Values) { q.Set("error", "access_denied") },
		"unknown state":      func(q url.Values) { q.Set("state", "forged") },
		"no issued client":   func(q url.Values) { q.Del("client_id") },
		"placeholder client": func(q url.Values) { q.Set("client_id", chatgptDynamicClientID) },
		"wrong code":         func(q url.Values) { q.Set("code", "stolen") },
	}
	for name, tamper := range cases {
		_, _ = o.pg().Exec(`DELETE FROM settings WHERE key=$1`, db.SettingChatGPTClientID)
		if _, _, err := f.signin(t, o, tamper); err == nil {
			t.Fatalf("%s: sign-in accepted", name)
		}
	}
	// Plan usage not granted: the sign-in is kept, plan use disabled.
	f.scope = "openid profile email offline_access"
	a, _, err := f.signin(t, o, nil)
	if err != nil || a.Status != db.ChatGPTStatusPlanDisabled {
		t.Fatalf("no plan scope: %+v %v", a, err)
	}
	// A state is single use.
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/x", nil)
	authURL, _, _ := o.startSignin(req, chatgptSigninRequest{})
	u, _ := url.Parse(authURL)
	st := u.Query().Get("state")
	_, _ = o.completeSignin(context.Background(), url.Values{"state": {st}, "error": {"access_denied"}})
	if _, err := o.completeSignin(context.Background(), url.Values{"state": {st}, "code": {"the-code"}, "client_id": {f.issued}}); err == nil {
		t.Fatal("a state was accepted twice")
	}
}

func TestChatGPTRedirectURI(t *testing.T) {
	for host, want := range map[string]string{
		"127.0.0.1:9000":    "http://127.0.0.1:9000/auth/callback",
		"localhost:8787":    "http://127.0.0.1:8787/auth/callback",
		"[::1]:8800":        "http://127.0.0.1:8800/auth/callback",
		"artex.example:443": "http://127.0.0.1:8787/auth/callback",
	} {
		r := httptest.NewRequest(http.MethodPost, "http://"+host+"/", nil)
		if got := chatgptRedirectURI(r); got != want {
			t.Fatalf("%s: %s, want %s", host, got, want)
		}
	}
}
