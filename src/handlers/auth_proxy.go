package handlers

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"hubproxy/db"
	"hubproxy/utils"
)

// 用于缓存服务端拿到的上游 Registry Token (例如用配置的 DockerHub 账号拿到的 token)
type upstreamTokenCache struct {
	mu     sync.RWMutex
	tokens map[string]cachedUpstreamToken
}

type cachedUpstreamToken struct {
	token     string
	expiresAt time.Time
}

var serverUpstreamTokens = &upstreamTokenCache{
	tokens: make(map[string]cachedUpstreamToken),
}

func (c *upstreamTokenCache) Get(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.tokens[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return ""
	}
	return entry.token
}

func (c *upstreamTokenCache) Set(key, token string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[key] = cachedUpstreamToken{
		token:     token,
		expiresAt: time.Now().Add(ttl),
	}
}

// 处理客户端请求 Token (GET /token?service=...&scope=...)
func HandleDockerAuthToken(c *gin.Context) {
	target, ok := resolveTokenTarget(c)
	if !ok {
		c.String(http.StatusBadRequest, "Unknown registry target")
		return
	}

	scope := c.Query("scope")
	service := c.Query("service")
	if service == "" {
		service = target.AuthService
	}

	// 0. 优先检测二级专属泛域名 (形如 <subdomain>.hub.bravexist.cn)
	// 专属二级域名无需密码，直接免登录签发对应用户 Token！
	host := c.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		subdomain := parts[0]
		if subdomain != "www" && subdomain != "hub" && subdomain != "api" {
			if user, err := db.GetUserByUsername(subdomain); err == nil && user != nil && user.IsEnabled {
				if user.ExpiresAt == nil || time.Now().Before(*user.ExpiresAt) {
					access := parseAccessFromScope(scope)
					token, err := GenerateLocalToken(user.Username, user.IsAdmin, service, access, 4*time.Hour)
					if err == nil {
						c.JSON(http.StatusOK, gin.H{
							"token":        token,
							"access_token": token,
							"expires_in":   14400,
							"issued_at":    time.Now().Format(time.RFC3339),
						})
						return
					}
				}
			}
		}
	}

	username, password, hasBasic := c.Request.BasicAuth()

	// 1. 尝试本地用户鉴权 (如果在管理后台注册的用户)
	if hasBasic && username != "" {
		user, err := db.GetUserByUsername(username)
		if err == nil && db.VerifyPassword(password, user.PasswordHash) {
			if !user.IsEnabled {
				c.Header("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="%s",error="account_disabled"`, c.Request.URL.String(), service))
				c.JSON(http.StatusForbidden, gin.H{"details": "Account disabled"})
				return
			}
			if user.ExpiresAt != nil && time.Now().After(*user.ExpiresAt) {
				c.Header("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="%s",error="account_expired"`, c.Request.URL.String(), service))
				c.JSON(http.StatusForbidden, gin.H{"details": "Account expired"})
				return
			}

			// 签发代理层自建 JWT Token
			access := parseAccessFromScope(scope)
			token, err := GenerateLocalToken(user.Username, user.IsAdmin, service, access, 4*time.Hour)
			if err != nil {
				c.String(http.StatusInternalServerError, "Failed to sign token")
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"token":        token,
				"access_token": token,
				"expires_in":   14400,
				"issued_at":    time.Now().Format(time.RFC3339),
			})
			return
		}
	}

	// 2. 如果携带了基础认证，但不是本地用户，检查是否允许透传到 DockerHub/上游
	allowPassthrough := db.GetSetting("allow_passthrough", "true") == "true"
	if hasBasic && allowPassthrough {
		// 透传去上游认证换取 Token
		proxyAuthToUpstream(c, target)
		return
	}

	// 3. 匿名用户认证请求
	allowAnonymous := db.GetSetting("allow_anonymous", "true") == "true"
	if !allowAnonymous {
		// 不允许匿名拉取，直接要求登录
		realm := fmt.Sprintf("%s://%s/token", getScheme(c), c.Request.Host)
		c.Header("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="%s",error="unauthorized"`, realm, service))
		c.String(http.StatusUnauthorized, "Unauthorized: authentication required")
		return
	}

	// 检查匿名月度限额 (按客户端 IP 统计)
	anonLimitStr := db.GetSetting("anonymous_monthly_quota", "50")
	anonLimit, _ := strconv.ParseInt(anonLimitStr, 10, 64)
	clientIP := c.ClientIP()
	if ok, reason := db.CheckAndConsumeIPQuota(clientIP, anonLimit); !ok {
		c.String(http.StatusTooManyRequests, reason)
		return
	}

	// 匿名拉取：如果我们服务端配置了全局的上游 Docker Hub 凭证，我们直接代表客户端向官方请求带有上游凭证的 token！
	// 这样可以突破 Docker Hub 的匿名 IP 限制
	if upstreamCred, err := db.GetActiveUpstreamCredential(target.Name); err == nil && upstreamCred != nil {
		upstreamToken, err := fetchUpstreamTokenWithCred(target, scope, upstreamCred.Username, upstreamCred.Password)
		if err == nil && upstreamToken != "" {
			// 将匿名 Token 返回给客户端
			c.Header("Content-Type", "application/json")
			c.String(http.StatusOK, upstreamToken)
			return
		}
	}

	// 否则常规请求上游匿名 Token
	proxyAuthToUpstream(c, target)
}

// 解析 scope: "repository:nginx:pull" 为 Access 对象
func parseAccessFromScope(scope string) []Access {
	if scope == "" {
		return []Access{}
	}
	parts := strings.Split(scope, ":")
	if len(parts) >= 3 && parts[0] == "repository" {
		actions := strings.Split(parts[2], ",")
		return []Access{
			{
				Type:    "repository",
				Name:    parts[1],
				Actions: actions,
			},
		}
	}
	return []Access{}
}

func getScheme(c *gin.Context) string {
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	if c.Request.TLS != nil {
		return "https"
	}
	return "http"
}

// 向上游官方获取指定凭证的 Token
func fetchUpstreamTokenWithCred(target registryTarget, scope, username, password string) (string, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s", target.Name, username, scope)
	if tok := serverUpstreamTokens.Get(cacheKey); tok != "" {
		return tok, nil
	}

	rawQuery := "scope=" + url.QueryEscape(scope)
	authURL, err := buildAuthURL(target, rawQuery)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodGet, authURL, nil)
	if err != nil {
		return "", err
	}
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := utils.GetGlobalHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusOK {
		serverUpstreamTokens.Set(cacheKey, string(body), 30*time.Minute)
		return string(body), nil
	}
	return "", fmt.Errorf("upstream auth failed with status %d", resp.StatusCode)
}

// 原生向上游代理认证（用于透传或普通匿名）
func proxyAuthToUpstream(c *gin.Context, target registryTarget) {
	cacheable := c.GetHeader("Authorization") == "" && utils.IsTokenCacheEnabled() && c.Request.Method == http.MethodGet
	cacheKey := utils.BuildTokenCacheKey(target.Name + ":" + c.Request.URL.RawQuery)
	if cacheable {
		if cachedToken := utils.GlobalCache.GetToken(cacheKey); cachedToken != "" {
			utils.WriteTokenResponse(c, cachedToken)
			return
		}
	}

	authURL, err := buildAuthURL(target, c.Request.URL.RawQuery)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to build auth request")
		return
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, authURL, nil)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to create auth request")
		return
	}
	forwardSelectedRequestHeaders(req.Header, c.Request.Header)

	resp, err := utils.GetGlobalHTTPClient().Do(req)
	if err != nil {
		c.String(http.StatusBadGateway, "Auth request failed")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.String(http.StatusBadGateway, "Failed to read auth response")
		return
	}

	copyResponseHeaders(c, resp.Header, target)
	if cacheable && resp.StatusCode == http.StatusOK && len(body) > 0 {
		ttl := utils.ExtractTTLFromResponse(body)
		utils.GlobalCache.SetToken(cacheKey, string(body), ttl)
		anonymousTokens.RememberFromResponse(body, ttl)
	}

	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}
