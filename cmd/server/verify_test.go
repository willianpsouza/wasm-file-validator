package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// sealInGo mirrors the WASM module's seal_to_backend so tests can craft
// envelopes the server is expected to open.
func sealInGo(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	serverPub, err := curve25519.X25519(x25519Secret, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("server pub: %v", err)
	}
	ephSec := make([]byte, 32)
	if _, err := rand.Read(ephSec); err != nil {
		t.Fatal(err)
	}
	ephPub, err := curve25519.X25519(ephSec, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(ephSec, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	hk := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hk, key); err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct := aead.Seal(nil, nonce, plaintext, ephPub)
	env := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	env = append(env, ephPub...)
	env = append(env, nonce...)
	env = append(env, ct...)
	return env
}

func post(t *testing.T, body string) *verifyResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleVerify(w, req)
	var resp verifyResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, w.Body.String())
	}
	return &resp
}

func sealedPayload(t *testing.T, reportBytes, sig []byte) string {
	inner := sealedInner{
		ReportB64: base64.StdEncoding.EncodeToString(reportBytes),
		SigB64:    base64.StdEncoding.EncodeToString(sig),
	}
	innerJSON, _ := json.Marshal(inner)
	env := sealInGo(t, innerJSON)
	reqBody, _ := json.Marshal(verifyRequest{Payload: base64.StdEncoding.EncodeToString(env)})
	return string(reqBody)
}

func TestUnsealRoundTrip(t *testing.T) {
	msg := []byte("roundtrip payload 123")
	env := sealInGo(t, msg)
	out, err := unseal(env)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if string(out) != string(msg) {
		t.Fatalf("got %q want %q", out, msg)
	}
}

func TestUnsealTooShort(t *testing.T) {
	if _, err := unseal([]byte("short")); err == nil {
		t.Fatal("expected error for short envelope")
	}
}

func TestVerifyHappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	orig := ed25519Pub
	ed25519Pub = pub
	defer func() { ed25519Pub = orig }()

	report := []byte(`{"verdict":"malicious","file_type":"pdf"}`)
	sig := ed25519.Sign(priv, report)

	resp := post(t, sealedPayload(t, report, sig))
	if !resp.Decrypted {
		t.Errorf("Verified=false, err=%q", resp.Error)
	}
	if !resp.SignatureOK {
		t.Error("SignatureOK=false, want true")
	}
	if string(resp.Report) != string(report) {
		t.Errorf("report echoed wrong: %s", resp.Report)
	}
}

func TestVerifyBadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	orig := ed25519Pub
	ed25519Pub = pub
	defer func() { ed25519Pub = orig }()

	report := []byte(`{"verdict":"clean"}`)
	sig := ed25519.Sign(priv, []byte("different bytes")) // sign wrong data

	resp := post(t, sealedPayload(t, report, sig))
	if !resp.Decrypted {
		t.Error("Verified should be true (decryption worked)")
	}
	if resp.SignatureOK {
		t.Error("SignatureOK should be false for tampered signature")
	}
}

func TestVerifyBadJSON(t *testing.T) {
	resp := post(t, "{not json")
	if resp.Error == "" {
		t.Error("expected error for bad json")
	}
}

func TestVerifyBadBase64(t *testing.T) {
	resp := post(t, `{"payload":"!!!not-base64!!!"}`)
	if resp.Error == "" {
		t.Error("expected error for bad base64 payload")
	}
}

func TestVerifyShortEnvelope(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("tiny"))
	resp := post(t, `{"payload":"`+short+`"}`)
	if resp.Decrypted {
		t.Error("Verified should be false for short envelope")
	}
	if resp.Error == "" {
		t.Error("expected unseal error")
	}
}

func TestVerifyBadInnerJSON(t *testing.T) {
	env := sealInGo(t, []byte("this is not valid inner json"))
	body, _ := json.Marshal(verifyRequest{Payload: base64.StdEncoding.EncodeToString(env)})
	resp := post(t, string(body))
	if resp.Error == "" {
		t.Error("expected inner json error")
	}
}
