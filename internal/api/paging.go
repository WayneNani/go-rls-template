package api

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPageSize = 50
	maxPageSize     = 100
)

// pageSize applies the default. The request rules in proto (lte: 100) reject larger
// values; the cap stays as the last line of defence.
func pageSize(requested int32) int32 {
	switch {
	case requested <= 0:
		return defaultPageSize
	case requested > maxPageSize:
		return maxPageSize
	default:
		return requested
	}
}

// A page token is the sort key of the last row returned. It is opaque to clients
// but not secret: a forged token only changes where the list starts, and RLS
// still decides which rows exist.
type pageKey struct {
	createdAt *time.Time
	id        *int64
}

func encodePageToken(createdAt time.Time, id int64) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(strconv.FormatInt(createdAt.UnixMicro(), 10) + "." + strconv.FormatInt(id, 10)))
}

func decodePageToken(token string) (pageKey, error) {
	if token == "" {
		return pageKey{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return pageKey{}, err
	}
	micros, idText, ok := strings.Cut(string(raw), ".")
	if !ok {
		return pageKey{}, errors.New("malformed page token")
	}
	us, err := strconv.ParseInt(micros, 10, 64)
	if err != nil {
		return pageKey{}, err
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil {
		return pageKey{}, err
	}
	t := time.UnixMicro(us)
	return pageKey{createdAt: &t, id: &id}, nil
}

// ID tokens page lists ordered by id.
func encodeIDToken(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

func decodeIDToken(token string) (*int64, error) {
	if token == "" {
		return nil, nil // no token: the first page
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// Key tokens page lists ordered by two text columns. NUL separates them: Postgres
// text cannot contain it.
func encodeKeyToken(a, b string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(a + "\x00" + b))
}

func decodeKeyToken(token string) (a, b *string, err error) {
	if token == "" {
		return nil, nil, nil // no token: the first page
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, nil, err
	}
	first, second, ok := strings.Cut(string(raw), "\x00")
	if !ok {
		return nil, nil, errors.New("malformed page token")
	}
	return &first, &second, nil
}
