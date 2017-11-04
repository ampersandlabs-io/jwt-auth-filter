package JWTAuthFilter

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/h2non/gock"
)

func TestExtractAuthToken(t *testing.T) {
	defer gock.Off()

	gock.New("http://foo.com").
		MatchHeader("Authorization", "^JWT bar$").
		HeaderPresent("Accept").
		Reply(200).
		BodyString("")

	expected := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImRyZXdicm5zQGdtYWlsLmNvbSIsIm9yaWdfaWF0IjoxNTA5NzAxMjc4LCJ1c2VyX2lkIjo3LCJlbWFpbCI6ImRyZXdicm5zQGdtYWlsLmNvbSIsImV4cCI6MTUwOTc0NDQ3OH0.u1eAneWw-6pxnLBfawYeMaEaxoXtgG0mlS5Ym7dozMk"

	r, err := http.NewRequest("GET", "http://foo.com", nil)
	r.Header.Set("Authorization", "JWT "+expected)
	r.Header.Set("Accept", "application/javascript")

	if err != nil {
		fmt.Println(err)
	}

	actual, err := extractAuthToken(r)

	if actual != expected {
		t.Errorf("Test failed, expected: '%s', got '%s'", expected, actual)
	}

}

func TestExtractAuthTokenWithNoTokenInHeader(t *testing.T) {
	defer gock.Off()

	gock.New("http://foo.com").
		MatchHeader("Authorization", "^JWT bar$").
		HeaderPresent("Accept").
		Reply(200).
		BodyString("")

	r, err := http.NewRequest("GET", "http://foo.com", nil)
	r.Header.Set("Accept", "application/javascript")

	if err != nil {
		fmt.Println(err)
	}

	expected := ""
	actual, err := extractAuthToken(r)

	if err != ErrNoTokenInRequest && actual != "" {
		t.Errorf("Test failed, expected: '%s', got '%s'", ErrNoTokenInRequest, err)
	}

	if actual != expected {
		t.Errorf("Test failed, expected: '%s', got '%s'", expected, actual)
	}

}

func TestExtractAuthTokenWithInvalidTokenFormat(t *testing.T) {
	defer gock.Off()

	gock.New("http://foo.com").
		HeaderPresent("Accept").
		Reply(200).
		BodyString("")

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImRyZXdicm5zQGdtYWlsLmNvbSIsIm9yaWdfaWF0IjoxNTA5NzAxMjc4LCJ1c2VyX2lkIjo3LCJlbWFpbCI6ImRyZXdicm5zQGdtYWlsLmNvbSIsImV4cCI6MTUwOTc0NDQ3OH0.u1eAneWw-6pxnLBfawYeMaEaxoXtgG0mlS5Ym7dozMk"

	r, err := http.NewRequest("GET", "http://foo.com", nil)
	r.Header.Set("Authorization", "Token "+token)
	r.Header.Set("Accept", "application/javascript")

	if err != nil {
		fmt.Println(err)
	}

	actual, err := extractAuthToken(r)
	expected := ""

	if err != ErrInvalidTokenFormat && actual != expected {
		t.Errorf("Test failed, expected: '%s', got '%s'", ErrInvalidTokenFormat, err)
	}

}
