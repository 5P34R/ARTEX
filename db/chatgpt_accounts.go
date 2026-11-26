package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// FormatChatGPTPlan is the profile format reported for a profile that signs in
// with "Sign in with ChatGPT" OAuth (a chatgpt_accounts row) instead of an API
// key. The row itself stores the wire format, storedFormatChatGPTPlan, with
// oauth_account_id set, so the llm_profiles format CHECK stays upstream's.
const FormatChatGPTPlan = "chatgpt-plan"

const storedFormatChatGPTPlan = "openai-responses"

// storedProfileFormat maps a profile format to the value stored in llm_profiles.
func storedProfileFormat(format string) string {
	if format == FormatChatGPTPlan {
		return storedFormatChatGPTPlan
	}
	return format
}

// ErrChatGPTProfileNeedsAccount refuses a chatgpt-plan profile without a signed-in account.
var ErrChatGPTProfileNeedsAccount = errors.New("a ChatGPT plan profile needs a signed-in ChatGPT account")

// ErrChatGPTAccountInUse refuses to remove an account a profile still signs in with.
var ErrChatGPTAccountInUse = errors.New("the ChatGPT account is used by a model profile; change or delete that profile first")

// ChatGPT account statuses (chatgpt_accounts.status).
const (
	ChatGPTStatusActive       = "active"        // tokens usable
	ChatGPTStatusNeedsSignin  = "needs_signin"  // refresh failed terminally or signed out: sign in again
	ChatGPTStatusPlanDisabled = "plan_disabled" // signed in, but plan usage (chatgpt.tokens.use.direct) not granted
)

// ChatGPT settings keys: one installation-wide host ID (ext_agent_host_id) and
// the client ID OpenAI issued at the first registration, reused for every
// later authorization and refresh.
const (
	SettingChatGPTHostID   = "chatgpt_host_id"
	SettingChatGPTClientID = "chatgpt_client_id"
)

// ErrChatGPTAccountNotFound is returned when no chatgpt_accounts row has the id.
var ErrChatGPTAccountNotFound = errors.New("ChatGPT account not found")

// ChatGPTAccount is one signed-in ChatGPT identity. Token fields never
// serialize; the list query leaves them empty.
type ChatGPTAccount struct {
	ID              int64     `json:"id"`
	Issuer          string    `json:"issuer"`
	Subject         string    `json:"-"`
	Email           string    `json:"email"`
	ClientID        string    `json:"-"`
	IDToken         string    `json:"-"`
	AccessToken     string    `json:"-"`
	RefreshToken    string    `json:"-"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
	Scopes          []string  `json:"scopes"`
	Status          string    `json:"status"`
	LastError       string    `json:"last_error,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// HasScope reports whether the account's granted scopes include s.
func (a *ChatGPTAccount) HasScope(s string) bool {
	for _, x := range a.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

const chatgptAccountCols = `id,issuer,subject,email,client_id,access_expires_at,array_to_string(scopes,' '),status,last_error,created_at,updated_at`

func scanChatGPTAccount(sc interface{ Scan(...any) error }, a *ChatGPTAccount, tokens bool) error {
	var exp sql.NullTime
	var scopes string
	dest := []any{&a.ID, &a.Issuer, &a.Subject, &a.Email, &a.ClientID, &exp, &scopes, &a.Status, &a.LastError, &a.CreatedAt, &a.UpdatedAt}
	if tokens {
		dest = append(dest, &a.IDToken, &a.AccessToken, &a.RefreshToken)
	}
	if err := sc.Scan(dest...); err != nil {
		return err
	}
	if exp.Valid {
		a.AccessExpiresAt = exp.Time
	}
	a.Scopes = strings.Fields(scopes)
	if !tokens {
		return nil
	}
	var err error
	if a.IDToken, err = openSecret(colChatGPTIDToken, a.IDToken); err != nil {
		return err
	}
	if a.AccessToken, err = openSecret(colChatGPTAccessToken, a.AccessToken); err != nil {
		return err
	}
	a.RefreshToken, err = openSecret(colChatGPTRefreshToken, a.RefreshToken)
	return err
}

// ListChatGPTAccounts returns every account without tokens, oldest first.
func (d *DB) ListChatGPTAccounts() ([]*ChatGPTAccount, error) {
	rows, err := d.Query(`SELECT ` + chatgptAccountCols + ` FROM chatgpt_accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ChatGPTAccount
	for rows.Next() {
		var a ChatGPTAccount
		if err := scanChatGPTAccount(rows, &a, false); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// ChatGPTAccountByID returns one account with its decrypted tokens.
func (d *DB) ChatGPTAccountByID(id int64) (*ChatGPTAccount, error) {
	var a ChatGPTAccount
	err := scanChatGPTAccount(d.QueryRow(`SELECT `+chatgptAccountCols+`,id_token,access_token,refresh_token FROM chatgpt_accounts WHERE id=$1`, id), &a, true)
	if err == sql.ErrNoRows {
		return nil, ErrChatGPTAccountNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpsertChatGPTAccount stores a completed sign-in, keyed by (issuer, subject):
// a new identity inserts a row, a returning one replaces its client ID, email,
// tokens, scopes and status. It returns the row id.
func (d *DB) UpsertChatGPTAccount(a *ChatGPTAccount) (int64, error) {
	idTok, err := sealSecret(colChatGPTIDToken, a.IDToken)
	if err != nil {
		return 0, err
	}
	access, err := sealSecret(colChatGPTAccessToken, a.AccessToken)
	if err != nil {
		return 0, err
	}
	refresh, err := sealSecret(colChatGPTRefreshToken, a.RefreshToken)
	if err != nil {
		return 0, err
	}
	status := a.Status
	if status == "" {
		status = ChatGPTStatusActive
	}
	var id int64
	err = d.QueryRow(`INSERT INTO chatgpt_accounts(issuer,subject,email,client_id,id_token,access_token,refresh_token,access_expires_at,scopes,status,last_error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,string_to_array(NULLIF($9,''),' '),$10,$11)
ON CONFLICT (issuer,subject) DO UPDATE SET email=EXCLUDED.email,client_id=EXCLUDED.client_id,id_token=EXCLUDED.id_token,
  access_token=EXCLUDED.access_token,refresh_token=EXCLUDED.refresh_token,access_expires_at=EXCLUDED.access_expires_at,
  scopes=EXCLUDED.scopes,status=EXCLUDED.status,last_error=EXCLUDED.last_error
RETURNING id`,
		a.Issuer, a.Subject, a.Email, a.ClientID, idTok, access, refresh, nullTime(a.AccessExpiresAt),
		strings.Join(a.Scopes, " "), status, a.LastError).Scan(&id)
	if err != nil {
		return 0, err
	}
	// string_to_array(NULL) yields NULL; keep the NOT NULL '{}' default instead.
	_, err = d.Exec(`UPDATE chatgpt_accounts SET scopes='{}' WHERE id=$1 AND scopes IS NULL`, id)
	return id, err
}

// SaveChatGPTTokens stores a refreshed token set in one write: the rotated
// refresh token, the new access token and its expiry, and the granted scopes.
// An empty idToken keeps the stored one. The account returns to active.
func (d *DB) SaveChatGPTTokens(id int64, access, refresh, idToken string, expires time.Time, scopes []string) error {
	accessS, err := sealSecret(colChatGPTAccessToken, access)
	if err != nil {
		return err
	}
	refreshS, err := sealSecret(colChatGPTRefreshToken, refresh)
	if err != nil {
		return err
	}
	idS, err := sealSecret(colChatGPTIDToken, idToken)
	if err != nil {
		return err
	}
	res, err := d.Exec(`UPDATE chatgpt_accounts SET access_token=$2,refresh_token=$3,id_token=CASE WHEN $4='' THEN id_token ELSE $4 END,
access_expires_at=$5,scopes=CASE WHEN $6='' THEN scopes ELSE string_to_array($6,' ') END,status='active',last_error='' WHERE id=$1`,
		id, accessS, refreshS, idS, nullTime(expires), strings.Join(scopes, " "))
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// ClearChatGPTTokens drops an account's access and refresh tokens (terminal
// refresh failure or sign-out) and records why. The row, its client ID and its
// ID token stay, so a later sign-in can reuse the registration and id_token_hint.
func (d *DB) ClearChatGPTTokens(id int64, status, lastErr string) error {
	res, err := d.Exec(`UPDATE chatgpt_accounts SET access_token='',refresh_token='',access_expires_at=NULL,status=$2,last_error=$3 WHERE id=$1`,
		id, status, lastErr)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// SetChatGPTAccountError records a non-terminal problem (shown in the UI)
// without touching the tokens or the status.
func (d *DB) SetChatGPTAccountError(id int64, lastErr string) error {
	_, err := d.Exec(`UPDATE chatgpt_accounts SET last_error=$2 WHERE id=$1`, id, lastErr)
	return err
}

// DeleteChatGPTAccount removes an account that no profile references (the FK
// is ON DELETE RESTRICT); a referenced account returns ErrChatGPTAccountInUse.
func (d *DB) DeleteChatGPTAccount(id int64) error {
	res, err := d.Exec(`DELETE FROM chatgpt_accounts WHERE id=$1`, id)
	if err != nil {
		if strings.Contains(err.Error(), "violates foreign key constraint") {
			return ErrChatGPTAccountInUse
		}
		return err
	}
	return requireOneRow(res)
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func requireOneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrChatGPTAccountNotFound
	}
	return nil
}
