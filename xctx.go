// Copyright 2025 Arieditya Pramadyana Deha <arieditya.prdh@live.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// file: xctx.go

// Package xctx provides typed, encrypted propagation of contextual information
// between HTTP services using a single request header (default: "X-Context").
//
// Overview
//
//   - You define a *typed* struct T (e.g., PassingContext) representing values
//     to carry across services (UserID, UserName, Tenant, etc.).
//   - On the *caller*, the struct is read from context.Context via your
//     Extractor[T], encrypted with AES‑256‑GCM, and emitted as a compact,
//     versioned header value.
//   - On the *callee*, the header is decrypted, validated (time window, optional
//     issuer/audience), and the typed struct is injected back into a derived
//     Context via your Injector[T].
//
// Security
//
//   - AES‑256‑GCM (stdlib only) provides confidentiality + integrity.
//   - Each token carries iat/nbf/exp and a random jti. Key rotation via kid.
//   - Optional AAD (Additional Authenticated Data) binding lets you couple the
//     token to ambient bytes (e.g., method|host|path) to reduce replay class.
//
// Wire format & versioning
//
//	Header value:  "v1." + base64url(JSON(envelope))
//	Envelope:      { v, alg, kid, n (nonce b64url), ct (ciphertext b64url) }
//	Payload:       { ctx: T, iss, aud, iat, nbf, exp, jti }
//
// The package is *schema‑agnostic*: it never needs to know your struct layout.
//
// Context key identity (important)
//
// xctx offers a TypedKey[T] for storing/retrieving T in a context.Context.
// This implementation includes a hidden unique token so two keys created with
// the same name *do not* compare equal. This avoids accidental collisions
// across packages. It also means you must reuse the exact TypedKey[T] instance
// within a process if you use DefaultExtractor/DefaultInjector.
package xctx

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultHeaderName is the header used when no override is provided.
const DefaultHeaderName = "X-Context"

// ==========================
// Key management
// ==========================

// Keyring stores symmetric keys for encryption/decryption keyed by a string
// "kid". All keys MUST be exactly 32 bytes (AES‑256). The CurrentKID key is
// used for new tokens; previous keys can remain accepted for decryption.
// Construct via NewKeyring to enforce constraints.
type Keyring struct {
	currentKID string
	keys       map[string][]byte // kid -> 32‑byte AES keys
}

// NewKeyring constructs a Keyring with a current key and an optional set of
// previous keys to keep accepting during rotation.
//
// Errors:
//   - currentKey32 must be 32 bytes
//   - every entry in others must be 32 bytes
func NewKeyring(currentKID string, currentKey32 []byte, others map[string][]byte) (*Keyring, error) {
	if len(currentKey32) != 32 {
		return nil, errors.New("xctx: current key must be 32 bytes (AES-256)")
	}
	keys := map[string][]byte{currentKID: currentKey32}
	for kid, k := range others {
		if len(k) != 32 {
			return nil, fmt.Errorf("xctx: key %q must be 32 bytes (AES-256)", kid)
		}
		keys[kid] = k
	}
	return &Keyring{currentKID: currentKID, keys: keys}, nil
}

// CurrentKID returns the identifier for the key used to encrypt new headers.
func (k *Keyring) CurrentKID() string { return k.currentKID }

// ==========================
// Typed keys + extract/inject hooks
// ==========================

// TypedKey is a helper for stashing a typed struct T in a context.Context.
//
// Safer identity: it embeds a hidden unique token pointer; therefore, two
// TypedKey[T] values created with the same name string are *not* equal.
// Only the exact same instance matches lookups. This prevents accidental
// cross‑package collisions. Keep the key instance you intend to use.
type TypedKey[T any] struct {
	name  string
	token *byte // unique identity; prevents accidental collisions
}

// NewTypedKey returns a new unique key to store/retrieve a T in context.
// The name is for debugging/logging only; it does not influence equality.
func NewTypedKey[T any](name string) TypedKey[T] {
	return TypedKey[T]{name: name, token: new(byte)}
}

// Extractor reads a typed value T from a Context. You provide this; the
// library does not inspect your struct.
type Extractor[T any] func(ctx context.Context) (T, error)

// Injector pushes a typed value T into a derived Context and returns it.
type Injector[T any] func(parent context.Context, v T) context.Context

// DefaultExtractor returns an Extractor that attempts to read a T stored under
// the given TypedKey. If no value is present, it returns the zero value of T
// and a nil error. Use a custom Extractor if you need stricter semantics.
func DefaultExtractor[T any](key TypedKey[T]) Extractor[T] {
	return func(ctx context.Context) (T, error) {
		v, _ := ctx.Value(key).(T)
		return v, nil
	}
}

// DefaultInjector returns an Injector that stores v under the TypedKey and
// returns the resulting derived Context.
func DefaultInjector[T any](key TypedKey[T]) Injector[T] {
	return func(parent context.Context, v T) context.Context {
		return context.WithValue(parent, key, v)
	}
}

// ==========================
// Codec: core API
// ==========================

// Codec holds configuration and crypto for a specific typed payload T.
//
// Create with NewCodec[T], providing a Keyring and options. Set an Extractor
// and Injector so the library can read your struct from Context and inject it
// later on the receiving side.
type Codec[T any] struct {
	headerName string
	keyring    *Keyring
	issuer     string
	audience   string
	ttl        time.Duration

	extract Extractor[T]
	inject  Injector[T]

	// Advanced: optional binder for Additional Authenticated Data (AAD).
	// If set, these bytes are authenticated with the ciphertext, preventing
	// valid tokens from being replayed across channels where AAD differs.
	aadBinder func() []byte
}

// Option configures Codec construction.
type Option[T any] func(*Codec[T])

// WithHeaderName sets the HTTP header name (default "X-Context").
func WithHeaderName[T any](name string) Option[T] { return func(c *Codec[T]) { c.headerName = name } }

// WithIssuer sets the issuer claim recorded in the payload (optional) and
// validated on parse when both sides set it.
func WithIssuer[T any](iss string) Option[T] { return func(c *Codec[T]) { c.issuer = iss } }

// WithAudience sets the audience claim recorded in the payload (optional) and
// validated on parse when both sides set it.
func WithAudience[T any](aud string) Option[T] { return func(c *Codec[T]) { c.audience = aud } }

// WithTTL sets the lifetime for the encrypted header (default 5 minutes).
func WithTTL[T any](ttl time.Duration) Option[T] { return func(c *Codec[T]) { c.ttl = ttl } }

// WithExtractor installs the function that retrieves T from a Context.
func WithExtractor[T any](ex Extractor[T]) Option[T] { return func(c *Codec[T]) { c.extract = ex } }

// WithInjector installs the function that injects T into a Context.
func WithInjector[T any](in Injector[T]) Option[T] { return func(c *Codec[T]) { c.inject = in } }

// WithAADBinder sets an optional function that returns bytes to be used as
// Additional Authenticated Data (AAD). If unset, no AAD is used.
func WithAADBinder[T any](fn func() []byte) Option[T] { return func(c *Codec[T]) { c.aadBinder = fn } }

// NewCodec builds a new Codec for a typed payload T.
//
// Required:
//   - kr: a Keyring with at least one 32‑byte AES key
//   - WithExtractor and WithInjector should be set unless you manage values
//     manually (ParseCtx returns T directly as well).
//
// Defaults:
//   - header name: "X-Context"
//   - ttl: 5 minutes
func NewCodec[T any](kr *Keyring, opts ...Option[T]) *Codec[T] {
	c := &Codec[T]{
		headerName: DefaultHeaderName,
		keyring:    kr,
		ttl:        5 * time.Minute,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// EmbedHeaderCtx encrypts the typed value T (obtained from the provided Context
// via the configured Extractor) and returns the header key and value that you
// should set on the outbound request.
//
// Typical use:
//
//	k, v, err := codec.EmbedHeaderCtx(req.Context())
//	if err != nil { ... }
//	req.Header.Set(k, v)
//
// Errors:
//   - if no Extractor has been set
//   - if building payload or encryption fails
func (c *Codec[T]) EmbedHeaderCtx(ctx context.Context) (string, string, error) {
	if c.extract == nil {
		return "", "", errors.New("xctx: extractor not set")
	}
	payload, err := c.buildPayload(ctx)
	if err != nil {
		return "", "", err
	}
	val, err := c.encryptV1(payload)
	if err != nil {
		return "", "", err
	}
	return c.headerName, val, nil
}

// SetHeader is a convenience wrapper around EmbedHeaderCtx that directly
// sets the header on the provided *http.Request.
func (c *Codec[T]) SetHeader(req *http.Request, ctx context.Context) error {
	k, v, err := c.EmbedHeaderCtx(ctx)
	if err != nil {
		return err
	}
	req.Header.Set(k, v)
	return nil
}

// ParseCtx reads and decrypts the typed value T from the inbound request
// header, validates temporal and issuer/audience constraints, injects it into
// a derived Context using the configured Injector (if any) and returns
// (newCtx, value, error).
//
// Errors include missing/unknown header version, unknown kid, base64/JSON
// issues, AEAD auth failure, invalid time window, issuer/audience mismatch.
func (c *Codec[T]) ParseCtx(r *http.Request) (context.Context, T, error) {
	var zero T

	raw := r.Header.Get(c.headerName)
	if raw == "" {
		return r.Context(), zero, errors.New("xctx: header missing")
	}
	if !strings.HasPrefix(raw, "v1.") {
		return r.Context(), zero, errors.New("xctx: unknown header version")
	}

	var env v1Envelope
	if err := json.Unmarshal(b64urlDecode(raw[3:]), &env); err != nil {
		return r.Context(), zero, fmt.Errorf("xctx: bad envelope: %w", err)
	}
	if env.V != 1 || env.Alg != "AES256-GCM" {
		return r.Context(), zero, errors.New("xctx: envelope mismatch")
	}
	key, ok := c.keyring.keys[env.KID]
	if !ok {
		return r.Context(), zero, errors.New("xctx: unknown kid")
	}

	nonce, err := b64url(env.N)
	if err != nil {
		return r.Context(), zero, fmt.Errorf("xctx: bad nonce: %w", err)
	}
	ct, err := b64url(env.CT)
	if err != nil {
		return r.Context(), zero, fmt.Errorf("xctx: bad ciphertext: %w", err)
	}

	aad := c.bindAAD()
	pt, err := gcmOpen(key, nonce, ct, aad)
	if err != nil {
		return r.Context(), zero, fmt.Errorf("xctx: decrypt failed: %w", err)
	}

	var pl v1Payload[T]
	if err := json.Unmarshal(pt, &pl); err != nil {
		return r.Context(), zero, fmt.Errorf("xctx: bad payload: %w", err)
	}

	now := nowFn().Unix()
	if now < pl.Nbf || now >= pl.Exp {
		return r.Context(), zero, errors.New("xctx: token not valid (time)")
	}
	if c.audience != "" && pl.Aud != "" && pl.Aud != c.audience {
		return r.Context(), zero, errors.New("xctx: bad audience")
	}
	if c.issuer != "" && pl.Iss != "" && pl.Iss != c.issuer {
		return r.Context(), zero, errors.New("xctx: bad issuer")
	}

	if c.inject != nil {
		return c.inject(r.Context(), pl.Ctx), pl.Ctx, nil
	}
	return r.Context(), pl.Ctx, nil
}

// ==========================
// Internals (wire & crypto)
// ==========================

type v1Envelope struct {
	V   int    `json:"v"`   // version (1)
	Alg string `json:"alg"` // "AES256-GCM"
	KID string `json:"kid"` // key id
	N   string `json:"n"`   // nonce (12 bytes, base64url)
	CT  string `json:"ct"`  // ciphertext (base64url; includes GCM tag)
}

type v1Payload[T any] struct {
	Ctx T      `json:"ctx"`           // your typed struct
	Iss string `json:"iss,omitempty"` // issuer (optional)
	Aud string `json:"aud,omitempty"` // audience (optional)
	Iat int64  `json:"iat"`           // issued at (unix seconds)
	Nbf int64  `json:"nbf"`           // not before (unix seconds)
	Exp int64  `json:"exp"`           // expiry (unix seconds)
	Jti string `json:"jti"`           // unique id (not persisted by library)
}

// Dependency‑injectable time and randomness for tests.
var (
	nowFn                = time.Now
	randSource io.Reader = rand.Reader
)

// buildPayload serializes the typed value plus standard claims into JSON.
func (c *Codec[T]) buildPayload(ctx context.Context) ([]byte, error) {
	v, err := c.extract(ctx)
	if err != nil {
		return nil, err
	}
	now := nowFn()
	pl := v1Payload[T]{
		Ctx: v,
		Iss: c.issuer,
		Aud: c.audience,
		Iat: now.Unix(),
		Nbf: now.Unix(),
		Exp: now.Add(c.ttl).Unix(),
		Jti: makeJTI(now),
	}
	return json.Marshal(pl)
}

// encryptV1 seals the given plaintext as a v1 envelope and returns the header
// value ("v1." + base64url(JSON(envelope))).
func (c *Codec[T]) encryptV1(plain []byte) (string, error) {
	key := c.keyring.keys[c.keyring.currentKID]
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(randSource, nonce); err != nil {
		return "", err
	}
	aad := c.bindAAD()
	ct, err := gcmSeal(key, nonce, plain, aad)
	if err != nil {
		return "", err
	}
	env := v1Envelope{
		V:   1,
		Alg: "AES256-GCM",
		KID: c.keyring.currentKID,
		N:   b64urlEncode(nonce),
		CT:  b64urlEncode(ct),
	}
	raw, _ := json.Marshal(env)
	return "v1." + b64urlEncode(raw), nil
}

// bindAAD returns the Additional Authenticated Data, if any.
func (c *Codec[T]) bindAAD() []byte {
	if c.aadBinder == nil {
		return nil
	}
	return c.aadBinder()
}

// gcm returns an AEAD configured with AES‑GCM for the provided key.
func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// gcmSeal encrypts plain with nonce and optional aad.
func gcmSeal(key, nonce, plain, aad []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plain, aad), nil
}

// gcmOpen decrypts ct with nonce and optional aad.
func gcmOpen(key, nonce, ct, aad []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ct, aad)
}

// b64 helpers
func b64urlEncode(b []byte) string    { return base64.RawURLEncoding.EncodeToString(b) }
func b64url(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func b64urlDecode(s string) []byte    { b, _ := b64url(s); return b }

// makeJTI produces a short, high‑entropy identifier. The exact length is
// stable for testability. It uses a random key to HMAC the timestamp, then
// base64url‑encodes and truncates to 22 characters.
func makeJTI(now time.Time) string {
	var rnd [16]byte
	_, _ = io.ReadFull(randSource, rnd[:])
	mac := hmac.New(sha256.New, rnd[:])
	_, _ = mac.Write([]byte(now.UTC().Format(time.RFC3339Nano)))
	return b64urlEncode(mac.Sum(nil))[:22]
}
