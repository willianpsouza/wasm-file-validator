package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	maxBody   = 16 << 20 // 16 MB
	hkdfInfo  = "wasm-file-validator-v1"
	ephLen    = 32
	nonceLen  = 24 // XChaCha20-Poly1305
	minEnvLen = ephLen + nonceLen + 16
)

type verifyRequest struct {
	Payload string `json:"payload"` // base64 envelope
}

type sealedInner struct {
	ReportB64 string `json:"report_b64"`
	SigB64    string `json:"sig_b64"`
}

type verifyResponse struct {
	Verified    bool            `json:"verified"`
	SignatureOK bool            `json:"signature_ok"`
	Report      json.RawMessage `json:"report,omitempty"`
	Error       string          `json:"error,omitempty"`
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "read body: " + err.Error()})
		return
	}
	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "bad json: " + err.Error()})
		return
	}
	envelope, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "bad base64: " + err.Error()})
		return
	}

	plaintext, err := unseal(envelope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "unseal: " + err.Error()})
		return
	}

	var inner sealedInner
	if err := json.Unmarshal(plaintext, &inner); err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "inner json: " + err.Error()})
		return
	}
	reportBytes, err := base64.StdEncoding.DecodeString(inner.ReportB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "report b64: " + err.Error()})
		return
	}
	sig, err := base64.StdEncoding.DecodeString(inner.SigB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "sig b64: " + err.Error()})
		return
	}

	sigOK := ed25519.Verify(ed25519Pub, reportBytes, sig)

	resp := verifyResponse{
		Verified:    true, // decryption succeeded -> came through our sealed channel
		SignatureOK: sigOK,
		Report:      json.RawMessage(reportBytes),
	}
	writeJSON(w, http.StatusOK, resp)
}

// unseal reverses seal_to_backend in the WASM module:
// envelope = ephemeral_pub(32) || nonce(24) || ciphertext
func unseal(envelope []byte) ([]byte, error) {
	if len(envelope) < minEnvLen {
		return nil, errors.New("envelope too short")
	}
	ephPub := envelope[:ephLen]
	nonce := envelope[ephLen : ephLen+nonceLen]
	ct := envelope[ephLen+nonceLen:]

	shared, err := curve25519.X25519(x25519Secret, ephPub)
	if err != nil {
		return nil, err
	}

	hk := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	// AAD must match the ephemeral public key bound at encrypt time.
	return aead.Open(nil, nonce, ct, ephPub)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
