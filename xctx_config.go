// SPDX-License-Identifier: Apache-2.0

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

// file: ./xctx_config.go

// Configuration helpers for the xctx package.
//
// This file provides a non-generic Config plus utilities to:
//   1) Load defaults from environment variables (LoadEnvConfig),
//   2) Overlay user overrides (Merge),
//   3) Apply library defaults (WithDefaults),
//   4) Validate strict requirements (Validate),
//   5) Construct typed Codecs in several ergonomic ways:
//        • BuildCodec[T]                 – explicit extractor/injector
//        • BuildCodecFromEnv[T]          – env + overrides, explicit hooks
//        • BuildCodecWithKey[T]          – use a TypedKey (auto-create if nil)
//        • BuildCodecFromEnvWithKey[T]   – env + overrides + (auto)TypedKey
//
// The helpers never call log.Fatalf or os.Exit; they return errors so that
// your application retains full control over lifecycle and error handling.
//
// Environment variables recognized by LoadEnvConfig (all optional unless noted):
//   XCTX_HEADER_NAME     : string    (default "X-Context")
//   XCTX_ISSUER          : string    (optional)
//   XCTX_AUDIENCE        : string    (optional)
//   XCTX_TTL             : duration  (e.g., "2m", "30s")
//   XCTX_CURRENT_KID     : string    (required if not provided by overrides)
//   XCTX_CURRENT_KEY     : key str   (32-byte key; accepts base64 (std or rawurl),
//                                     hex, or raw 32-character text)
//   XCTX_OTHER_KEYS      : CSV       (e.g., "kid1=<key>,kid2=<key>"; same encodings)
//   XCTX_TYPED_KEY_NAME  : string    (local-only; default "xctx" when auto-creating)
//
// Notes:
//   • Keys must decode to exactly 32 bytes (AES-256).
//   • TTL must be > 0; WithDefaults sets 5m if unset.
//   • Issuer/Audience may be empty to disable those checks.
//   • TypedKeyName is purely in-process (NOT sent over the wire) and affects
//     only the human-readable name when we auto-create a TypedKey.

package xctx

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all knobs required to construct a Codec for a typed payload.
//
// Cross-process values (affect wire/crypto): HeaderName, Issuer, Audience, TTL,
// CurrentKID, CurrentKey, OtherKeys.
//
// Local-only value (in-process only): TypedKeyName.
// This name is used only when the helpers auto-create a TypedKey[T]; it is not
// serialized, does not leave the process, and does not participate in crypto.
type Config struct {
	HeaderName string
	Issuer     string
	Audience   string
	TTL        time.Duration

	CurrentKID string
	CurrentKey []byte            // exactly 32 bytes
	OtherKeys  map[string][]byte // map of kid -> 32-byte key

	// Local-only: used when auto-creating a TypedKey[T]. Optional.
	TypedKeyName string
}

// LoadEnvConfig reads configuration from process environment. Missing values
// remain zero so they can be supplied by Merge(overrides) and WithDefaults().
func LoadEnvConfig() (Config, error) {
	var c Config

	c.HeaderName = strings.TrimSpace(os.Getenv("XCTX_HEADER_NAME"))
	c.Issuer = os.Getenv("XCTX_ISSUER")
	c.Audience = os.Getenv("XCTX_AUDIENCE")
	c.TypedKeyName = strings.TrimSpace(os.Getenv("XCTX_TYPED_KEY_NAME"))

	if s := strings.TrimSpace(os.Getenv("XCTX_TTL")); s != "" {
		ttl, err := time.ParseDuration(s)
		if err != nil {
			return c, fmt.Errorf("xctx: invalid XCTX_TTL %q: %w", s, err)
		}
		c.TTL = ttl
	}

	c.CurrentKID = strings.TrimSpace(os.Getenv("XCTX_CURRENT_KID"))

	if s := strings.TrimSpace(os.Getenv("XCTX_CURRENT_KEY")); s != "" {
		key, err := decodeKeyString(s)
		if err != nil {
			return c, fmt.Errorf("xctx: invalid XCTX_CURRENT_KEY: %w", err)
		}
		c.CurrentKey = key
	}

	if s := strings.TrimSpace(os.Getenv("XCTX_OTHER_KEYS")); s != "" {
		m, err := parseOtherKeys(s)
		if err != nil {
			return c, fmt.Errorf("xctx: invalid XCTX_OTHER_KEYS: %w", err)
		}
		c.OtherKeys = m
	}

	return c, nil
}

// Merge overlays non-zero values from overrides onto the receiver and returns
// a new Config. Strings override when non-empty; TTL overrides when > 0;
// key fields override when present; maps override when non-nil.
func (c Config) Merge(overrides Config) Config {
	out := c
	if overrides.HeaderName != "" {
		out.HeaderName = overrides.HeaderName
	}
	if overrides.Issuer != "" {
		out.Issuer = overrides.Issuer
	}
	if overrides.Audience != "" {
		out.Audience = overrides.Audience
	}
	if overrides.TTL > 0 {
		out.TTL = overrides.TTL
	}
	if overrides.CurrentKID != "" {
		out.CurrentKID = overrides.CurrentKID
	}
	if len(overrides.CurrentKey) > 0 {
		out.CurrentKey = overrides.CurrentKey
	}
	if overrides.OtherKeys != nil {
		out.OtherKeys = overrides.OtherKeys
	}
	if overrides.TypedKeyName != "" {
		out.TypedKeyName = overrides.TypedKeyName
	}
	return out
}

// WithDefaults returns a copy where unset values are populated with library
// defaults. It does not mutate the receiver.
func (c Config) WithDefaults() Config {
	out := c
	if out.HeaderName == "" {
		out.HeaderName = DefaultHeaderName
	}
	if out.TTL <= 0 {
		out.TTL = 5 * time.Minute
	}
	if out.TypedKeyName == "" {
		out.TypedKeyName = "xctx"
	}
	return out
}

// Validate performs strict checks on the config. It does not mutate the receiver.
// Returns the first error encountered.
func (c Config) Validate() error {
	if c.HeaderName == "" {
		return errors.New("xctx: HeaderName is required")
	}
	if c.CurrentKID == "" {
		return errors.New("xctx: CurrentKID is required")
	}
	if len(c.CurrentKey) != 32 {
		return fmt.Errorf("xctx: CurrentKey must be 32 bytes (got %d)", len(c.CurrentKey))
	}
	for kid, k := range c.OtherKeys {
		if len(k) != 32 {
			return fmt.Errorf("xctx: OtherKeys[%s] must be 32 bytes (got %d)", kid, len(k))
		}
	}
	if c.TTL <= 0 {
		return errors.New("xctx: TTL must be > 0")
	}
	return nil
}

// MergeEnv loads env, overlays user overrides, applies defaults, validates,
// and returns the final Config (or an error). No side effects beyond reading env.
func MergeEnv(user Config) (Config, error) {
	env, err := LoadEnvConfig()
	if err != nil {
		return Config{}, err
	}
	cfg := env.Merge(user).WithDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// BuildCodec constructs a Codec[T] from a ready Config.
// Use this when you want to supply a custom Extractor/Injector.
func BuildCodec[T any](cfg Config, extract Extractor[T], inject Injector[T], aad func() []byte) (*Codec[T], error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	kr, err := NewKeyring(cfg.CurrentKID, cfg.CurrentKey, cfg.OtherKeys)
	if err != nil {
		return nil, err
	}
	opts := []Option[T]{
		WithHeaderName[T](cfg.HeaderName),
		WithIssuer[T](cfg.Issuer),
		WithAudience[T](cfg.Audience),
		WithTTL[T](cfg.TTL),
	}
	if extract != nil {
		opts = append(opts, WithExtractor[T](extract))
	}
	if inject != nil {
		opts = append(opts, WithInjector[T](inject))
	}
	if aad != nil {
		opts = append(opts, WithAADBinder[T](aad))
	}
	return NewCodec[T](kr, opts...), nil
}

// BuildCodecFromEnv is a convenience wrapper that calls MergeEnv(user) and then
// BuildCodec. It returns an error instead of exiting the process.
func BuildCodecFromEnv[T any](user Config, extract Extractor[T], inject Injector[T], aad func() []byte) (*Codec[T], error) {
	cfg, err := MergeEnv(user)
	if err != nil {
		return nil, err
	}
	return BuildCodec[T](cfg, extract, inject, aad)
}

// BuildCodecWithKey builds a Codec[T] from a ready Config and either:
//   - uses the provided key instance (if non-nil), or
//   - auto-creates a key using cfg.TypedKeyName (or "xctx" if empty).
//
// It wires DefaultExtractor/DefaultInjector with that key and returns both the
// constructed Codec and the TypedKey that was used.
func BuildCodecWithKey[T any](cfg Config, key *TypedKey[T], aad func() []byte) (*Codec[T], TypedKey[T], error) {
	if err := cfg.Validate(); err != nil {
		return nil, TypedKey[T]{}, err
	}
	kr, err := NewKeyring(cfg.CurrentKID, cfg.CurrentKey, cfg.OtherKeys)
	if err != nil {
		return nil, TypedKey[T]{}, err
	}
	var k TypedKey[T]
	if key != nil {
		k = *key
	} else {
		name := cfg.TypedKeyName
		if name == "" {
			name = "xctx"
		}
		k = NewTypedKey[T](name)
	}
	opts := []Option[T]{
		WithHeaderName[T](cfg.HeaderName),
		WithIssuer[T](cfg.Issuer),
		WithAudience[T](cfg.Audience),
		WithTTL[T](cfg.TTL),
		WithExtractor[T](DefaultExtractor[T](k)),
		WithInjector[T](DefaultInjector[T](k)),
	}
	if aad != nil {
		opts = append(opts, WithAADBinder[T](aad))
	}
	return NewCodec[T](kr, opts...), k, nil
}

// BuildCodecFromEnvWithKey merges env + user overrides, applies defaults,
// validates, then calls BuildCodecWithKey. Returns both Codec and TypedKey.
func BuildCodecFromEnvWithKey[T any](user Config, key *TypedKey[T], aad func() []byte) (*Codec[T], TypedKey[T], error) {
	cfg, err := MergeEnv(user)
	if err != nil {
		return nil, TypedKey[T]{}, err
	}
	return BuildCodecWithKey[T](cfg, key, aad)
}

// --- helpers ---

// decodeKeyString attempts, in order, to decode s as base64 (rawurl), base64
// (std), hex, or raw text. The result must be exactly 32 bytes.
func decodeKeyString(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty key")
	}
	try := []func(string) ([]byte, error){
		func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) },
		func(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) },
		func(s string) ([]byte, error) { return hex.DecodeString(s) },
		func(s string) ([]byte, error) { return []byte(s), nil }, // raw text
	}
	for _, dec := range try {
		b, err := dec(s)
		if err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("key must decode to 32 bytes (got %q)", s)
}

// parseOtherKeys parses "kid1=ENCODEDKEY,kid2=ENCODEDKEY" where keys decode via
// decodeKeyString and must be 32 bytes each.
func parseOtherKeys(s string) (map[string][]byte, error) {
	m := make(map[string][]byte)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("bad entry %q (want kid=key)", part)
		}
		kid := strings.TrimSpace(kv[0])
		if kid == "" {
			return nil, fmt.Errorf("missing kid in %q", part)
		}
		key, err := decodeKeyString(strings.TrimSpace(kv[1]))
		if err != nil {
			return nil, fmt.Errorf("kid %s: %w", kid, err)
		}
		m[kid] = key
	}
	return m, nil
}
