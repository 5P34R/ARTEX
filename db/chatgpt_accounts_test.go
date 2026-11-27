package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newTestChatGPTAccount(t *testing.T, d *DB) *ChatGPTAccount {
	t.Helper()
	a := &ChatGPTAccount{
		Issuer:          "https://auth.openai.com",
		Subject:         fmt.Sprintf("user-%d", time.Now().UnixNano()),
		Email:           "operator@example.com",
		ClientID:        "oaiapp_synthetic",
		IDToken:         "synthetic-id-token",
		AccessToken:     "synthetic-access-token",
		RefreshToken:    "synthetic-refresh-token",
		AccessExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second),
		Scopes:          []string{"openid", "offline_access", "chatgpt.tokens.use.direct"},
	}
	id, err := d.UpsertChatGPTAccount(a)
	if err != nil {
		t.Fatal(err)
	}
	a.ID = id
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM chatgpt_accounts WHERE id=$1`, id) })
	return a
}

func TestChatGPTAccountTokensEncryptedAndRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	a := newTestChatGPTAccount(t, d)

	var idTok, access, refresh string
	if err := d.QueryRow(`SELECT id_token,access_token,refresh_token FROM chatgpt_accounts WHERE id=$1`, a.ID).Scan(&idTok, &access, &refresh); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{idTok, access, refresh} {
		if !isEncrypted(v) || strings.Contains(v, "synthetic") {
			t.Fatalf("token stored in plaintext: %q", v)
		}
	}

	got, err := d.ChatGPTAccountByID(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != a.AccessToken || got.RefreshToken != a.RefreshToken || got.IDToken != a.IDToken {
		t.Fatal("tokens did not round-trip")
	}
	if got.ClientID != "oaiapp_synthetic" || got.Status != ChatGPTStatusActive || !got.HasScope("chatgpt.tokens.use.direct") {
		t.Fatalf("unexpected account: %+v", got)
	}

	list, err := d.ListChatGPTAccounts()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "synthetic-") || strings.Contains(string(b), "oaiapp_") {
		t.Fatalf("account list leaked a secret: %s", b)
	}
}

func TestChatGPTAccountUpsertRefreshAndClear(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	a := newTestChatGPTAccount(t, d)

	// A returning sign-in for the same identity updates the same row.
	a.AccessToken, a.Email = "second-access", "new@example.com"
	id, err := d.UpsertChatGPTAccount(a)
	if err != nil || id != a.ID {
		t.Fatalf("upsert of the same identity: id=%d want %d err=%v", id, a.ID, err)
	}

	exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	if err := d.SaveChatGPTTokens(a.ID, "rotated-access", "rotated-refresh", "", exp, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := d.ChatGPTAccountByID(a.ID)
	if got.AccessToken != "rotated-access" || got.RefreshToken != "rotated-refresh" || got.IDToken != "synthetic-id-token" {
		t.Fatalf("refresh did not store the rotated set: %+v", got)
	}
	if !got.AccessExpiresAt.Equal(exp) || len(got.Scopes) != 3 || got.Email != "new@example.com" {
		t.Fatalf("expiry/scopes/email: %+v", got)
	}

	if err := d.ClearChatGPTTokens(a.ID, ChatGPTStatusNeedsSignin, "refresh token expired"); err != nil {
		t.Fatal(err)
	}
	got, _ = d.ChatGPTAccountByID(a.ID)
	if got.AccessToken != "" || got.RefreshToken != "" || got.Status != ChatGPTStatusNeedsSignin || got.ClientID == "" || got.IDToken == "" {
		t.Fatalf("clear: %+v", got)
	}
	if err := d.ClearChatGPTTokens(-1, ChatGPTStatusNeedsSignin, ""); !errors.Is(err, ErrChatGPTAccountNotFound) {
		t.Fatalf("missing row: %v", err)
	}
}

func TestChatGPTPlanProfileStoredAsResponsesWithAccount(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	a := newTestChatGPTAccount(t, d)
	name := fmt.Sprintf("t-chatgpt-%d", time.Now().UnixNano())

	if _, err := d.SaveProfile(&LLMProfile{Name: name, Format: FormatChatGPTPlan, Model: "gpt-test"}); !errors.Is(err, ErrChatGPTProfileNeedsAccount) {
		t.Fatalf("profile without account: %v", err)
	}
	p := &LLMProfile{Name: name, Format: FormatChatGPTPlan, Model: "gpt-test", APIKey: "must-not-be-stored", OAuthAccountID: a.ID, Streaming: true}
	id, err := d.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	defer deleteTestProfile(t, d, id)
	if p.Format != FormatChatGPTPlan {
		t.Fatalf("SaveProfile changed the caller's format to %q", p.Format)
	}

	var stored string
	var key *string
	if err := d.QueryRow(`SELECT format,api_key FROM llm_profiles WHERE id=$1`, id).Scan(&stored, &key); err != nil {
		t.Fatal(err)
	}
	if stored != "openai-responses" || key != nil {
		t.Fatalf("stored format=%q key=%v, want openai-responses and no key", stored, key)
	}

	got, err := d.ProfileByID(id)
	if err != nil || got.Format != FormatChatGPTPlan || got.OAuthAccountID != a.ID {
		t.Fatalf("load: %+v err=%v", got, err)
	}
	pool, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range pool {
		found = found || x.ID == id
	}
	if !found {
		t.Fatal("a signed-in ChatGPT plan profile must be usable in the pool query")
	}

	if err := d.DeleteChatGPTAccount(a.ID); !errors.Is(err, ErrChatGPTAccountInUse) {
		t.Fatalf("deleting a referenced account: %v", err)
	}

	// Switching the profile to another format drops the account reference.
	got.Format, got.APIKey = "openai", "sk-test"
	if _, err := d.SaveProfile(got); err != nil {
		t.Fatal(err)
	}
	again, _ := d.ProfileByID(id)
	if again.Format != "openai" || again.OAuthAccountID != 0 {
		t.Fatalf("after switching format: %+v", again)
	}
}
