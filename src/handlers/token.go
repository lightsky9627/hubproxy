package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	// 用于为客户端签发 JWT Token 的 HMAC 密钥
	jwtSecretKey = []byte("hubproxy-auth-secret-key-change-in-production")
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type TokenClaims struct {
	Iss       string   `json:"iss"`
	Sub       string   `json:"sub"`
	Aud       string   `json:"aud"`
	Exp       int64    `json:"exp"`
	Nbf       int64    `json:"nbf"`
	Iat       int64    `json:"iat"`
	Jti       string   `json:"jti"`
	Access    []Access `json:"access"`
	Username  string   `json:"username"`
	IsAdmin   bool     `json:"is_admin"`
}

type Access struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// 签发 Token
func GenerateLocalToken(username string, isAdmin bool, service string, access []Access, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := TokenClaims{
		Iss:      "hubproxy",
		Sub:      username,
		Aud:      service,
		Exp:      now.Add(ttl).Unix(),
		Nbf:      now.Add(-time.Minute).Unix(),
		Iat:      now.Unix(),
		Jti:      fmt.Sprintf("%d", now.UnixNano()),
		Access:   access,
		Username: username,
		IsAdmin:  isAdmin,
	}

	headerJSON, _ := json.Marshal(JWTHeader{Alg: "HS256", Typ: "JWT"})
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	h := hmac.New(sha256.New, jwtSecretKey)
	h.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return signingInput + "." + sig, nil
}

// 验证并解析 Token
func ParseLocalToken(tokenString string) (*TokenClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, jwtSecretKey)
	h.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, errors.New("invalid token signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims TokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	if claims.Exp > 0 && now > claims.Exp {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

// 管理员身份验证中间件 (用于 Web 后台 API)
func AdminAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := ""
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			cookie, err := c.Cookie("admin_token")
			if err == nil {
				tokenStr = cookie
			}
		}

		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "需要登录管理员权限"})
			c.Abort()
			return
		}

		claims, err := ParseLocalToken(tokenStr)
		if err != nil || !claims.IsAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "无效或过期的管理员 Token"})
			c.Abort()
			return
		}

		c.Set("admin_user", claims.Username)
		c.Next()
	}
}
