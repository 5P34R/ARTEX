package server

// "Sign in with ChatGPT" for chatgpt-plan model profiles: the open-source
// token-sharing flow documented at
// https://developers.openai.com/siwc/token-sharing-open-source. ARTEX registers
// itself on the first sign-in (client_id=dynamic_agent_client, agent_name_hint),
// keeps the issued client ID, stores the token set encrypted (db.ChatGPTAccount)
// and refreshes access tokens on demand for the agent transport
// (agent.TokenSource). Tokens, codes and PKCE verifiers are never logged and
// never leave the server except to auth.openai.com.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
)

const (
	chatgptIssuer           = "https://auth.openai.com"
	chatgptResource         = "https://api.openai.com/v1"
	chatgptDynamicClientID  = "dynamic_agent_client"
	chatgptAgentName        = "ARTEX"
	chatgptScopePlanUse     = "chatgpt.tokens.use.direct"
	chatgptScopes           = "openid profile email offline_access resource.invoke " + chatgptScopePlanUse
	chatgptCallbackPath     = "/auth/callback"
	chatgptDefaultPort      = "8787"
	chatgptPendingTTL       = 10 * time.Minute
	chatgptRefreshMargin    = 5 * time.Minute
	chatgptHTTPTimeout      = 30 * time.Second
	chatgptMetadataCacheTTL = time.Hour
	chatgptSettingsPath     = "/system/llm"
)

// chatgptEndpoints are OpenAI's auth endpoints; tests point them at a fake.
type chatgptEndpoints struct {
	Authorize string
	Token     string
	Discovery string
}

var defaultChatGPTEndpoints = chatgptEndpoints{
	Authorize: "https://auth.openai.com/api/accounts/authorize",
	Token:     "https://auth.openai.com/api/accounts/oauth/token",
	Discovery: "https://auth.openai.com/.well-known/openid-configuration",
}

// chatgptPending is one sign-in attempt awaiting its callback.
type chatgptPending struct {
	nonce       string
	verifier    string
	redirectURI string
	clientID    string // the client ID sent to authorize: dynamic_agent_client or the issued one
	registering bool
	created     time.Time
}

// chatgptOAuth owns the sign-in attempts, the token refreshes and the cached
// OpenID metadata.
type chatgptOAuth struct {
	pg        func() *db.DB
	endpoints chatgptEndpoints
	client    *http.Client
	now       func() time.Time

	mu      sync.Mutex
	pending map[string]*chatgptPending // by state

	refreshMu sync.Mutex
	refreshBy map[int64]*sync.Mutex // per-account refresh serialization

	metaMu   sync.Mutex
	meta     *chatgptMetadata
	metaAt   time.Time
	jwks     map[string]any // kid -> *rsa.PublicKey / *ecdsa.PublicKey
	jwksAt   time.Time
	onChange func() // invoked after an account's usability changes (rebuild providers)
}

type chatgptMetadata struct {
	JWKSURI            string `json:"jwks_uri"`
	RevocationEndpoint string `json:"revocation_endpoint"`
	Issuer             string `json:"issuer"`
}

func newChatGPTOAuth(pg func() *db.DB) *chatgptOAuth {
	return &chatgptOAuth{
		pg:        pg,
		endpoints: defaultChatGPTEndpoints,
		client:    &http.Client{Timeout: chatgptHTTPTimeout},
		now:       time.Now,
		pending:   map[string]*chatgptPending{},
		refreshBy: map[int64]*sync.Mutex{},
	}
}

// ---------- token source (used by agent.Config) ----------

// chatgptTokenSource is the comparable agent.TokenSource of one account.
type chatgptTokenSource struct {
	o         *chatgptOAuth
	accountID int64
}

func (t chatgptTokenSource) AccessToken(ctx context.Context) (string, error) {
	return t.o.accessToken(ctx, t.accountID)
}

// errChatGPTSignin marks errors that need the operator to sign in again.
var errChatGPTSignin = errors.New("sign in again in System > LLM")

// accessToken returns a valid access token for the account, refreshing it under
// a per-account lock when it expires within chatgptRefreshMargin.
func (o *chatgptOAuth) accessToken(ctx context.Context, id int64) (string, error) {
	pg := o.pg()
	if pg == nil {
		return "", errors.New("database unavailable")
	}
	mu := o.accountLock(id)
	mu.Lock()
	defer mu.Unlock()
	// Re-read under the lock: a concurrent caller may have just refreshed.
	a, err := pg.ChatGPTAccountByID(id)
	if err != nil {
		return "", err
	}
	switch a.Status {
	case db.ChatGPTStatusNeedsSignin:
		return "", fmt.Errorf("ChatGPT account %s is signed out: %w", a.Email, errChatGPTSignin)
	case db.ChatGPTStatusPlanDisabled:
		return "", fmt.Errorf("ChatGPT account %s has not allowed plan usage for ARTEX: %w", a.Email, errChatGPTSignin)
	}
	now := o.now()
	if a.AccessToken != "" && a.AccessExpiresAt.After(now.Add(chatgptRefreshMargin)) {
		return a.AccessToken, nil
	}
	if a.RefreshToken == "" {
		_ = pg.ClearChatGPTTokens(id, db.ChatGPTStatusNeedsSignin, "no refresh token")
		return "", fmt.Errorf("ChatGPT account %s has no refresh token: %w", a.Email, errChatGPTSignin)
	}
	tok, err := o.refresh(ctx, a)
	if err != nil {
		var terminal *chatgptTerminalError
		if errors.As(err, &terminal) {
			_ = pg.ClearChatGPTTokens(id, db.ChatGPTStatusNeedsSignin, terminal.Error())
			o.changed()
			return "", fmt.Errorf("ChatGPT sign-in for %s expired (%s): %w", a.Email, terminal.code, errChatGPTSignin)
		}
		_ = pg.SetChatGPTAccountError(id, "token refresh failed: "+err.Error())
		// A still-valid access token is better than failing the request.
		if a.AccessToken != "" && a.AccessExpiresAt.After(now) {
			return a.AccessToken, nil
		}
		return "", fmt.Errorf("refresh ChatGPT access token: %w", err)
	}
	scopes := strings.Fields(tok.Scope)
	refresh := tok.RefreshToken
	if refresh == "" {
		refresh = a.RefreshToken // no rotation in this response: keep the current one
	}
	if err := pg.SaveChatGPTTokens(id, tok.AccessToken, refresh, tok.IDToken, now.Add(time.Duration(tok.ExpiresIn)*time.Second), scopes); err != nil {
		return "", fmt.Errorf("store refreshed ChatGPT tokens: %w", err)
	}
	return tok.AccessToken, nil
}

func (o *chatgptOAuth) accountLock(id int64) *sync.Mutex {
	o.refreshMu.Lock()
	defer o.refreshMu.Unlock()
	mu, ok := o.refreshBy[id]
	if !ok {
		mu = &sync.Mutex{}
		o.refreshBy[id] = mu
	}
	return mu
}

func (o *chatgptOAuth) changed() {
	if o.onChange != nil {
		o.onChange()
	}
}

// chatgptTokenResponse is the token endpoint's success body.
type chatgptTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

// chatgptTerminalError is a refresh failure that only a new sign-in fixes.
type chatgptTerminalError struct{ code, desc string }

func (e *chatgptTerminalError) Error() string {
	if e.desc != "" {
		return e.code + ": " + e.desc
	}
	return e.code
}

var chatgptTerminalRefreshCodes = map[string]bool{
	"invalid_grant": true, "invalid_refresh_token": true, "token_expired": true,
	"refresh_token_expired": true, "refresh_token_invalidated": true, "refresh_token_reused": true,
	"invalid_client": true,
}

func (o *chatgptOAuth) refresh(ctx context.Context, a *db.ChatGPTAccount) (*chatgptTokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {a.ClientID},
		"refresh_token": {a.RefreshToken},
		"resource":      {chatgptResource},
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		tok, status, err := o.postToken(ctx, form)
		if err == nil {
			return tok, nil
		}
		var terminal *chatgptTerminalError
		if errors.As(err, &terminal) {
			return nil, err
		}
		lastErr = err
		if status != 0 && status < 500 && status != http.StatusTooManyRequests {
			return nil, err // a 4xx without a terminal code: retrying will not help
		}
	}
	return nil, lastErr
}

// postToken POSTs a form to the token endpoint. Terminal OAuth error codes come
// back as *chatgptTerminalError.
func (o *chatgptOAuth) postToken(ctx context.Context, form url.Values) (*chatgptTokenResponse, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoints.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
			Desc  string `json:"error_description"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(raw, &e)
		code := e.Error
		if code == "" {
			code = e.Code
		}
		if chatgptTerminalRefreshCodes[code] {
			return nil, resp.StatusCode, &chatgptTerminalError{code: code, desc: e.Desc}
		}
		msg := code
		if e.Desc != "" {
			msg += ": " + e.Desc
		}
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		return nil, resp.StatusCode, fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, msg)
	}
	var tok chatgptTokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("token endpoint: decode response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, resp.StatusCode, errors.New("token endpoint returned no access token")
	}
	if tok.ExpiresIn <= 0 {
		tok.ExpiresIn = 3600
	}
	return &tok, resp.StatusCode, nil
}

// ---------- sign-in ----------

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hostID returns the installation's stable ext_agent_host_id, creating it once.
func (o *chatgptOAuth) hostID(pg *db.DB) (string, error) {
	if v, ok, err := pg.GetSetting(db.SettingChatGPTHostID); err != nil {
		return "", err
	} else if ok && v != "" {
		return v, nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // UUIDv4
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	id := "urn:uuid:" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	if err := pg.SetSetting(db.SettingChatGPTHostID, id); err != nil {
		return "", err
	}
	return id, nil
}

// chatgptRedirectURI builds the loopback callback for the port the operator's
// browser uses to reach ARTEX. Only 127.0.0.1 is accepted by OpenAI, so a
// console reached any other way falls back to the default port and the paste
// flow.
func chatgptRedirectURI(r *http.Request) string {
	port := chatgptDefaultPort
	host := r.Host
	if h, p, err := net.SplitHostPort(host); err == nil {
		ip := net.ParseIP(strings.Trim(h, "[]"))
		if (h == "localhost" || (ip != nil && ip.IsLoopback())) && p != "" {
			port = p
		}
	}
	return "http://127.0.0.1:" + port + chatgptCallbackPath
}

type chatgptSigninRequest struct {
	AccountID  int64 `json:"account_id,string,omitempty"` // re-sign-in of a known account (id_token_hint)
	EnablePlan bool  `json:"enable_plan"`                 // ask for consent again (plan usage was declined)
}

// startSignin creates a pending attempt and returns the authorize URL.
func (o *chatgptOAuth) startSignin(r *http.Request, in chatgptSigninRequest) (string, string, error) {
	pg := o.pg()
	if pg == nil {
		return "", "", errors.New("database unavailable")
	}
	hostID, err := o.hostID(pg)
	if err != nil {
		return "", "", err
	}
	issued, _, err := pg.GetSetting(db.SettingChatGPTClientID)
	if err != nil {
		return "", "", err
	}
	state, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	nonce, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	verifier, err := randomToken(48)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	redirectURI := chatgptRedirectURI(r)

	p := &chatgptPending{nonce: nonce, verifier: verifier, redirectURI: redirectURI, clientID: issued, created: o.now()}
	q := url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {chatgptScopes},
		"resource":              {chatgptResource},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"ext_agent_host_id":     {hostID},
	}
	if issued == "" {
		p.registering, p.clientID = true, chatgptDynamicClientID
		q.Set("agent_name_hint", chatgptAgentName)
	}
	q.Set("client_id", p.clientID)
	if in.AccountID != 0 {
		if a, err := pg.ChatGPTAccountByID(in.AccountID); err == nil {
			if a.IDToken != "" {
				q.Set("id_token_hint", a.IDToken)
			} else if a.Email != "" {
				q.Set("login_hint", a.Email)
			}
		}
	}
	if in.EnablePlan {
		q.Set("prompt", "consent")
	}

	o.mu.Lock()
	for k, v := range o.pending { // drop expired attempts
		if o.now().Sub(v.created) > chatgptPendingTTL {
			delete(o.pending, k)
		}
	}
	o.pending[state] = p
	o.mu.Unlock()
	log.Printf("[chatgpt] sign-in started (registering=%v, redirect %s)", p.registering, redirectURI)
	return o.endpoints.Authorize + "?" + q.Encode(), redirectURI, nil
}

// chatgptCallbackError is a callback failure safe to show the operator.
type chatgptCallbackError struct{ msg string }

func (e *chatgptCallbackError) Error() string { return e.msg }

func callbackErr(format string, args ...any) error {
	return &chatgptCallbackError{msg: fmt.Sprintf(format, args...)}
}

// completeSignin handles the authorization response (query parameters of the
// callback URL): it validates state, keeps the issued client ID, exchanges the
// code, validates the ID token and stores the account.
func (o *chatgptOAuth) completeSignin(ctx context.Context, q url.Values) (*db.ChatGPTAccount, error) {
	pg := o.pg()
	if pg == nil {
		return nil, errors.New("database unavailable")
	}
	state := q.Get("state")
	o.mu.Lock()
	p, ok := o.pending[state]
	delete(o.pending, state) // single use, success or not
	o.mu.Unlock()
	if !ok || state == "" {
		return nil, callbackErr("this sign-in link is unknown or was already used; start the sign-in again from System > LLM")
	}
	if o.now().Sub(p.created) > chatgptPendingTTL {
		return nil, callbackErr("the sign-in took longer than %v; start it again", chatgptPendingTTL)
	}
	if e := q.Get("error"); e != "" {
		if e == "access_denied" {
			return nil, callbackErr("sign-in was cancelled in the browser")
		}
		return nil, callbackErr("ChatGPT sign-in failed: %s %s", e, q.Get("error_description"))
	}

	clientID := p.clientID
	cbClient := q.Get("client_id")
	if p.registering {
		if cbClient == "" || cbClient == chatgptDynamicClientID {
			return nil, callbackErr("OpenAI did not return a client ID, so registration is incomplete; start the sign-in again")
		}
		// Keep the issued ID before the exchange: a failed exchange must not
		// cause a second registration on retry.
		if err := pg.SetSetting(db.SettingChatGPTClientID, cbClient); err != nil {
			return nil, err
		}
		clientID = cbClient
		log.Printf("[chatgpt] ARTEX registered with OpenAI (client %s…)", truncateID(cbClient))
	} else if cbClient != "" && cbClient != clientID {
		return nil, callbackErr("the callback carried a different client ID than this installation's; sign-in rejected")
	}

	code := q.Get("code")
	if code == "" {
		return nil, callbackErr("the callback carried no authorization code")
	}
	tok, _, err := o.postToken(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"code_verifier": {p.verifier},
		"redirect_uri":  {p.redirectURI},
		"resource":      {chatgptResource},
	})
	if err != nil {
		var terminal *chatgptTerminalError
		if errors.As(err, &terminal) && terminal.code == "invalid_grant" {
			return nil, callbackErr("the sign-in code expired or was already used; start the sign-in again")
		}
		return nil, callbackErr("exchanging the sign-in code failed: %v", err)
	}
	claims, err := o.validateIDToken(ctx, tok.IDToken, clientID, p.nonce)
	if err != nil {
		return nil, callbackErr("the ID token from OpenAI did not validate: %v", err)
	}
	scopes := strings.Fields(tok.Scope)
	a := &db.ChatGPTAccount{
		Issuer:          claims.Issuer,
		Subject:         claims.Subject,
		Email:           claims.Email,
		ClientID:        clientID,
		IDToken:         tok.IDToken,
		AccessToken:     tok.AccessToken,
		RefreshToken:    tok.RefreshToken,
		AccessExpiresAt: o.now().Add(time.Duration(tok.ExpiresIn) * time.Second),
		Scopes:          scopes,
		Status:          db.ChatGPTStatusActive,
	}
	if !a.HasScope(chatgptScopePlanUse) {
		// Signed in, but plan usage was not granted: keep the sign-in, mark plan
		// use disabled until the operator enables it (prompt=consent).
		a.Status = db.ChatGPTStatusPlanDisabled
		a.LastError = "plan usage was not allowed during sign-in"
	}
	id, err := pg.UpsertChatGPTAccount(a)
	if err != nil {
		return nil, err
	}
	a.ID = id
	o.changed()
	log.Printf("[chatgpt] signed in account #%d (%s, status %s)", id, a.Email, a.Status)
	return a, nil
}

func truncateID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// ---------- ID token validation ----------

type chatgptIDClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce"`
	Email string `json:"email"`
}

func (o *chatgptOAuth) metadata(ctx context.Context) (*chatgptMetadata, error) {
	o.metaMu.Lock()
	defer o.metaMu.Unlock()
	if o.meta != nil && o.now().Sub(o.metaAt) < chatgptMetadataCacheTTL {
		return o.meta, nil
	}
	var m chatgptMetadata
	if err := o.getJSON(ctx, o.endpoints.Discovery, &m); err != nil {
		return nil, fmt.Errorf("OpenID discovery: %w", err)
	}
	o.meta, o.metaAt = &m, o.now()
	return &m, nil
}

func (o *chatgptOAuth) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// signingKey returns the JWKS key for kid, refetching the key set once when
// the kid is unknown (key rotation).
func (o *chatgptOAuth) signingKey(ctx context.Context, kid string) (any, error) {
	meta, err := o.metadata(ctx)
	if err != nil {
		return nil, err
	}
	o.metaMu.Lock()
	defer o.metaMu.Unlock()
	if k, ok := o.jwks[kid]; ok && o.now().Sub(o.jwksAt) < chatgptMetadataCacheTTL {
		return k, nil
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if meta.JWKSURI == "" {
		return nil, errors.New("discovery document has no jwks_uri")
	}
	if err := o.getJSON(ctx, meta.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	keys := map[string]any{}
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	o.jwks, o.jwksAt = keys, o.now()
	k, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("no signing key %q in OpenAI's JWKS", kid)
	}
	return k, nil
}

// validateIDToken checks signature (JWKS), issuer, audience, expiry and nonce.
func (o *chatgptOAuth) validateIDToken(ctx context.Context, raw, clientID, nonce string) (*chatgptIDClaims, error) {
	if raw == "" {
		return nil, errors.New("no id_token in the token response")
	}
	claims := &chatgptIDClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return o.signingKey(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256"}),
		jwt.WithIssuer(chatgptIssuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(o.now),
		jwt.WithLeeway(time.Minute),
	)
	if err != nil {
		return nil, err
	}
	if claims.Nonce == "" || claims.Nonce != nonce {
		return nil, errors.New("nonce mismatch")
	}
	if claims.Subject == "" {
		return nil, errors.New("no subject")
	}
	return claims, nil
}

// ---------- sign-out ----------

// signOut revokes the refresh token (retrying transient failures) and clears
// the tokens. It reports whether OpenAI confirmed the revocation; the account
// row, its client ID and ID token stay for a later sign-in.
func (o *chatgptOAuth) signOut(ctx context.Context, id int64) (bool, error) {
	pg := o.pg()
	if pg == nil {
		return false, errors.New("database unavailable")
	}
	mu := o.accountLock(id)
	mu.Lock()
	defer mu.Unlock()
	a, err := pg.ChatGPTAccountByID(id)
	if err != nil {
		return false, err
	}
	revoked := a.RefreshToken == "" // nothing to revoke
	if !revoked {
		revoked = o.revoke(ctx, a)
	}
	msg := "signed out"
	if !revoked {
		msg = "signed out locally; OpenAI did not confirm the revocation (disconnect ARTEX in ChatGPT Settings to be sure)"
	}
	if err := pg.ClearChatGPTTokens(id, db.ChatGPTStatusNeedsSignin, msg); err != nil {
		return revoked, err
	}
	o.changed()
	return revoked, nil
}

func (o *chatgptOAuth) revoke(ctx context.Context, a *db.ChatGPTAccount) bool {
	meta, err := o.metadata(ctx)
	if err != nil || meta.RevocationEndpoint == "" {
		return false
	}
	form := url.Values{"token": {a.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {a.ClientID}}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.RevocationEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := o.client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
		if resp.StatusCode < 500 {
			return false
		}
	}
	return false
}

// ---------- models ----------

// listModels returns the account's selectable models (visibility "list").
func (o *chatgptOAuth) listModels(ctx context.Context, accountID int64) ([]map[string]string, error) {
	tok, err := o.accessToken(ctx, accountID)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chatgptModelsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("list models: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var body struct {
		Models []struct {
			Slug        string `json:"slug"`
			DisplayName string `json:"display_name"`
			Visibility  string `json:"visibility"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("list models: %w", err)
	}
	var out []map[string]string
	for _, m := range body.Models {
		if m.Visibility == "list" && m.Slug != "" {
			name := m.DisplayName
			if name == "" {
				name = m.Slug
			}
			out = append(out, map[string]string{"id": m.Slug, "name": name})
		}
	}
	return out, nil
}

// chatgptModelsURL is the account's model list; tests override it.
var chatgptModelsURL = agent.ChatGPTPlanBaseURL + "/models"

// ---------- HTTP handlers ----------

type chatgptAccountDTO struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Status          string    `json:"status"`
	PlanUsage       bool      `json:"plan_usage"`
	LastError       string    `json:"last_error,omitempty"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func chatgptAccountToDTO(a *db.ChatGPTAccount) chatgptAccountDTO {
	return chatgptAccountDTO{
		ID: strconv.FormatInt(a.ID, 10), Email: a.Email, Status: a.Status,
		PlanUsage: a.HasScope(chatgptScopePlanUse), LastError: a.LastError,
		AccessExpiresAt: a.AccessExpiresAt, UpdatedAt: a.UpdatedAt,
	}
}

// GET /api/llm/chatgpt/accounts
func (s *Server) chatgptListAccounts(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	list, err := pg.ListChatGPTAccounts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]chatgptAccountDTO, 0, len(list))
	for _, a := range list {
		out = append(out, chatgptAccountToDTO(a))
	}
	clientID, _, _ := pg.GetSetting(db.SettingChatGPTClientID)
	writeJSON(w, 200, map[string]any{"accounts": out, "registered": clientID != ""})
}

// POST /api/llm/chatgpt/signin -> {authorize_url, redirect_uri}
func (s *Server) chatgptStartSignin(w http.ResponseWriter, r *http.Request) {
	var in chatgptSigninRequest
	if r.ContentLength != 0 {
		if err := decode(w, r, &in); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	authURL, redirectURI, err := s.chatgpt.startSignin(r, in)
	if err != nil {
		writeErr(w, 500, "start ChatGPT sign-in: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"authorize_url": authURL, "redirect_uri": redirectURI})
}

// GET /auth/callback — the browser redirect from auth.openai.com. Public (the
// browser carries no API token here); the single-use state is the guard. It
// redirects to the console's LLM settings with the outcome.
func (s *Server) chatgptCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	dest := url.Values{}
	a, err := s.chatgpt.completeSignin(r.Context(), r.URL.Query())
	if err != nil {
		dest.Set("chatgpt_error", chatgptUserError(err))
	} else {
		dest.Set("chatgpt", a.Status)
		s.afterChatGPTChange()
	}
	http.Redirect(w, r, chatgptSettingsPath+"?"+dest.Encode(), http.StatusSeeOther)
}

// POST /api/llm/chatgpt/callback-paste {url} — the paste fallback for a browser
// that could not reach 127.0.0.1 (console behind a reverse proxy or SSH).
func (s *Server) chatgptPasteCallback(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url"`
	}
	if err := decode(w, r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	u, err := url.Parse(strings.TrimSpace(in.URL))
	if err != nil || u.RawQuery == "" {
		writeErr(w, 400, "paste the full address from the browser's address bar (it contains code= and state=)")
		return
	}
	a, err := s.chatgpt.completeSignin(r.Context(), u.Query())
	if err != nil {
		writeErr(w, 400, chatgptUserError(err))
		return
	}
	s.afterChatGPTChange()
	writeJSON(w, 200, map[string]any{"account": chatgptAccountToDTO(a)})
}

// POST /api/llm/chatgpt/accounts/{id}/signout
func (s *Server) chatgptSignOut(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid account id")
		return
	}
	revoked, err := s.chatgpt.signOut(r.Context(), id)
	if errors.Is(err, db.ErrChatGPTAccountNotFound) {
		writeErr(w, 404, err.Error())
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.afterChatGPTChange()
	writeJSON(w, 200, map[string]any{"ok": true, "revoked": revoked})
}

// DELETE /api/llm/chatgpt/accounts/{id} — only when no profile uses it.
func (s *Server) chatgptDeleteAccount(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid account id")
		return
	}
	if a, err := pg.ChatGPTAccountByID(id); err == nil && a.RefreshToken != "" {
		writeErr(w, 409, "sign the account out first")
		return
	}
	switch err := pg.DeleteChatGPTAccount(id); {
	case errors.Is(err, db.ErrChatGPTAccountInUse):
		writeErr(w, 409, err.Error())
	case errors.Is(err, db.ErrChatGPTAccountNotFound):
		writeErr(w, 404, err.Error())
	case err != nil:
		writeErr(w, 500, err.Error())
	default:
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// GET /api/llm/chatgpt/accounts/{id}/models
func (s *Server) chatgptListModels(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "invalid account id")
		return
	}
	models, err := s.chatgpt.listModels(r.Context(), id)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "models": models})
}

// chatgptUserError returns text safe for the console: callback errors as is,
// anything else generic (internal details go to the log).
func chatgptUserError(err error) string {
	var ce *chatgptCallbackError
	if errors.As(err, &ce) {
		return ce.msg
	}
	log.Printf("[chatgpt] sign-in failed: %v", err)
	return "ChatGPT sign-in failed; see the server log"
}

// afterChatGPTChange rebuilds providers so profiles pick up a new sign-in or
// sign-out immediately.
func (s *Server) afterChatGPTChange() {
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
}

// applyProfileAuth gives a chatgpt-plan config the token source of its account.
func (s *Server) applyProfileAuth(cfg *agent.Config, p *db.LLMProfile) {
	if cfg.Format != agent.FormatChatGPTPlan || p.OAuthAccountID == 0 {
		return
	}
	cfg.TokenSource = chatgptTokenSource{o: s.chatgpt, accountID: p.OAuthAccountID}
}
