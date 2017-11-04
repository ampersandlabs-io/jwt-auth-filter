package JWTAuthFilter

import (
	"context"
	"fmt"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
)

func validateRequest(r *http.Request) (*http.Request, error) {

	tokenString, err := extractAuthToken(r)
	if err != nil {
		return r, err
	}

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		secretKey := os.Getenv("SECRET_KEY")
		// ... is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secretKey), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		ctx := context.WithValue(r.Context(), RequestUserIDKey, claims["user_id"])
		r = r.WithContext(ctx)
		return r, nil
	}
	return r, err

}
