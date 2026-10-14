package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"hubproxy/config"
	"hubproxy/db"
	"hubproxy/utils"
)

type registryTarget struct {
	Name              string
	Upstream          string
	AuthRealm         string
	AuthService       string
	AuthType          string
	AutoLibraryPrefix bool
}

const (
	dockerHubName         = "docker.io"
	dockerHubUpstream     = "https://registry-1.docker.io"
	dockerHubAuthRealm    = "https://auth.docker.io/token"
	dockerHubAuthService  = "registry.docker.io"
	maxCachedManifestSize = 4 << 20
	maxAnonymousTokens    = 4096
)

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

var forwardedRequestHeaders = []string{
	"Authorization",
	"Accept",
	"Range",
	"If-Range",
	"If-Match",
	"If-None-Match",
	"If-Modified-Since",
	"If-Unmodified-Since",
}

type anonymousTokenStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

var anonymousTokens = &anonymousTokenStore{entries: make(map[string]time.Time)}

// 保留初始化入口，在线代理无状态。
func InitDockerProxy() {}

func defaultRegistryTarget() registryTarget {
	cfg := config.GetConfig()
	if mapping, exists := cfg.Registries[dockerHubName]; exists && mapping.Enabled {
		target := registryTargetFromMapping(dockerHubName, mapping)
		target.AuthService = dockerHubAuthService
		target.AutoLibraryPrefix = true
		return target
	}

	return registryTarget{
		Name:              dockerHubName,
		Upstream:          dockerHubUpstream,
		AuthRealm:         dockerHubAuthRealm,
		AuthService:       dockerHubAuthService,
		AutoLibraryPrefix: true,
	}
}

func registryTargetFromMapping(name string, mapping config.RegistryMapping) registryTarget {
	upstream := strings.TrimRight(strings.TrimSpace(mapping.Upstream), "/")
	if upstream == "" {
		upstream = name
	}
	if !strings.HasPrefix(upstream, "http://") && !strings.HasPrefix(upstream, "https://") {
		upstream = "https://" + upstream
	}

	authRealm := strings.TrimSpace(mapping.AuthHost)
	if authRealm == "" {
		authRealm = strings.TrimPrefix(upstream, "https://")
		authRealm = strings.TrimPrefix(authRealm, "http://")
	}

	// 强制自动规范化：针对知名 Registry 进行内置容错纠正，即使用户旧 config.toml 填了裸域名也能自适应
	// 如果配置本身是自定义的完整 URL（例如 mock 测试服务器 http://127.0.0.1:xxx），则不强行覆盖
	if !strings.HasPrefix(mapping.AuthHost, "http://") && !strings.HasPrefix(mapping.AuthHost, "https://") {
		switch name {
		case "registry.k8s.io":
			if !strings.Contains(authRealm, "/token") {
				authRealm = "registry.k8s.io/token"
			}
		case "nvcr.io":
			if !strings.Contains(authRealm, "/proxy_auth") {
				authRealm = "nvcr.io/proxy_auth"
			}
		case "docker.elastic.co":
			if !strings.Contains(authRealm, "/auth") {
				authRealm = "docker-auth.elastic.co/auth"
			}
		case "gcr.io":
			if !strings.Contains(authRealm, "/token") {
				authRealm = "gcr.io/v2/token"
			}
		case "ghcr.io":
			if !strings.Contains(authRealm, "/token") {
				authRealm = "ghcr.io/token"
			}
		case "quay.io":
			if !strings.Contains(authRealm, "/auth") {
				authRealm = "quay.io/v2/auth"
			}
		}
	}

	if !strings.HasPrefix(authRealm, "http://") && !strings.HasPrefix(authRealm, "https://") {
		authRealm = "https://" + authRealm
	}

	authService := strings.TrimPrefix(strings.TrimPrefix(upstream, "https://"), "http://")
	if name == "nvcr.io" {
		authService = "registry"
	} else if name == "docker.elastic.co" {
		authService = "token-service"
	}

	return registryTarget{
		Name:              name,
		Upstream:          upstream,
		AuthRealm:         authRealm,
		AuthService:       authService,
		AuthType:          mapping.AuthType,
		AutoLibraryPrefix: false,
	}
}

func resolveRegistryTarget(c *gin.Context, pathWithoutV2 string) (registryTarget, string) {
	cfg := config.GetConfig()

	if ns := strings.TrimSpace(c.Query("ns")); ns != "" {
		if mapping, exists := cfg.Registries[ns]; exists && mapping.Enabled {
			return registryTargetFromMapping(ns, mapping), pathWithoutV2
		}
	}

	for domain, mapping := range cfg.Registries {
		if mapping.Enabled && strings.HasPrefix(pathWithoutV2, domain+"/") {
			return registryTargetFromMapping(domain, mapping), strings.TrimPrefix(pathWithoutV2, domain+"/")
		}
	}

	return defaultRegistryTarget(), pathWithoutV2
}

func resolveTokenTarget(c *gin.Context) (registryTarget, bool) {
	name := strings.Trim(strings.TrimSpace(c.Param("path")), "/")
	if name == "" || isDockerHubAlias(name) {
		return inferTokenTargetFromScope(c.Query("scope"))
	}

	cfg := config.GetConfig()
	if mapping, exists := cfg.Registries[name]; exists && mapping.Enabled {
		return registryTargetFromMapping(name, mapping), true
	}

	return registryTarget{}, false
}

func inferTokenTargetFromScope(scope string) (registryTarget, bool) {
	if registryName, ok := registryNameFromScope(scope); ok {
		if isDockerHubAlias(registryName) {
			return defaultRegistryTarget(), true
		}

		cfg := config.GetConfig()
		if mapping, exists := cfg.Registries[registryName]; exists && mapping.Enabled {
			return registryTargetFromMapping(registryName, mapping), true
		}
	}

	return defaultRegistryTarget(), true
}

func registryNameFromScope(scope string) (string, bool) {
	parts := strings.Split(scope, ":")
	if len(parts) != 3 || parts[0] != "repository" {
		return "", false
	}

	repo := parts[1]
	slash := strings.Index(repo, "/")
	if slash == -1 {
		return "", false
	}

	registryName := repo[:slash]
	if strings.Contains(registryName, ".") || strings.Contains(registryName, ":") || registryName == "localhost" {
		return registryName, true
	}
	return "", false
}

func isDockerHubAlias(name string) bool {
	return name == dockerHubName || name == "dockerhub" || name == "registry-1.docker.io"
}

// 透明代理 Docker Registry API v2 请求。
func ProxyDockerRegistryGin(c *gin.Context) {
	path := c.Request.URL.Path

	// 检查当前请求的认证信息，看是否是我们签发的 JWT
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if claims, err := ParseLocalToken(tokenStr); err == nil && claims.Username != "" {
			if path == "/v2/" {
				// docker login 握手成功：客户端携带有效 Token 探测 /v2/，直接响应 200 OK
				c.Header("Docker-Distribution-API-Version", "registry/2.0")
				c.JSON(http.StatusOK, gin.H{})
				return
			}
		}
	}

	// 检查二级专属域名是否直接合法（如果是专属域名用户，/v2/ 探测也视为登录成功）
	reqHost := c.Request.Host
	if colonIdx := strings.Index(reqHost, ":"); colonIdx != -1 {
		reqHost = reqHost[:colonIdx]
	}
	hostParts := strings.Split(reqHost, ".")
	if len(hostParts) >= 3 {
		sub := hostParts[0]
		if sub != "www" && sub != "hub" && sub != "api" {
			if user, err := db.GetUserByUsername(sub); err == nil && user != nil && user.IsEnabled {
				if user.ExpiresAt == nil || time.Now().Before(*user.ExpiresAt) {
					if path == "/v2/" {
						c.Header("Docker-Distribution-API-Version", "registry/2.0")
						c.JSON(http.StatusOK, gin.H{})
						return
					}
				}
			}
		}
	}

	if path == "/v2/" {
		target, _ := resolveRegistryTarget(c, "")
		proxyRegistryHTTP(c, target, "/v2/")
		return
	}

	start := time.Now()
	username := "anonymous"

	// 检查泛域名绑定的空间 (例如: qiankong.hub.bravexist.cn)
	host := c.Request.Host
	if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		// 形如 <subdomain>.hub.bravexist.cn，提取前缀子域名
		subdomain := parts[0]
		if subdomain != "www" && subdomain != "hub" && subdomain != "api" {
			// 检查是否存在对应的用户空间
			if user, err := db.GetUserByUsername(subdomain); err == nil && user != nil && user.IsEnabled {
				username = user.Username
			}
		}
	}

	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if claims, err := ParseLocalToken(tokenStr); err == nil && claims.Username != "" {
			username = claims.Username
		}
	}

	// 扣减用户月度配额（只在拉取 manifest 时扣减，避免 blob 下载每个分块重复计费）
	if username != "anonymous" && strings.Contains(path, "/manifests/") {
		if ok, reason := db.CheckAndConsumeUserQuota(username); !ok {
			c.String(http.StatusTooManyRequests, reason)
			return
		}
	}

	if !strings.HasPrefix(path, "/v2/") {
		c.String(http.StatusNotFound, "Docker Registry API v2 only")
		return
	}

	// 如果禁止匿名拉取，且当前未认证为本地用户，则直接要求认证返回 401
	if username == "anonymous" {
		allowAnonymous := db.GetSetting("allow_anonymous", "true") == "true"
		if !allowAnonymous {
			target, _ := resolveRegistryTarget(c, strings.TrimPrefix(path, "/v2/"))
			baseURL := publicBaseURL(c)
			// 注意：service 必须设置为当前请求的 Host (例如 hub.bravexist.cn)，
			// 否则 Docker 客户端在检查 ~/.docker/config.json 发现 service 与登录域名不一致时，会拒绝携带 Basic Auth 凭据
			challengeService := c.Request.Host
			c.Header("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s/token/%s",service="%s",error="unauthorized"`, baseURL, target.Name, challengeService))
			c.Header("Docker-Distribution-API-Version", "registry/2.0")
			c.JSON(http.StatusUnauthorized, gin.H{
				"errors": []gin.H{
					{
						"code":    "UNAUTHORIZED",
						"message": "authentication required: anonymous pull is disabled",
					},
				},
			})
			return
		}
	}

	handleRegistryRequest(c, path)

	// 记录拉取日志 (保留原汁原味日志，记录每次真实请求)
	if strings.Contains(path, "/manifests/") || strings.Contains(path, "/blobs/") {
		status := c.Writer.Status()
		pathWithoutV2 := strings.TrimPrefix(path, "/v2/")
		target, targetPath := resolveRegistryTarget(c, pathWithoutV2)
		imageName, apiType, _ := parseRegistryPath(targetPath)
		if imageName != "" {
			duration := time.Since(start).Milliseconds()
			go db.RecordPullLog(db.PullLog{
				Username:   username,
				ClientIP:   c.ClientIP(),
				Registry:   target.Name,
				Image:      imageName,
				Action:     apiType,
				Status:     status,
				DurationMs: duration,
				UserAgent:  c.Request.UserAgent(),
			})
		}
	}
}

func handleRegistryRequest(c *gin.Context, path string) {
	pathWithoutV2 := strings.TrimPrefix(path, "/v2/")
	target, targetPath := resolveRegistryTarget(c, pathWithoutV2)

	imageName, apiType, _ := parseRegistryPath(targetPath)
	if imageName == "" || apiType == "" {
		c.String(http.StatusBadRequest, "Invalid path format")
		return
	}

	if target.AutoLibraryPrefix && !strings.Contains(imageName, "/") {
		imageName = "library/" + imageName
		targetPath = strings.TrimPrefix(targetPath, strings.TrimPrefix(imageName, "library/"))
		targetPath = imageName + targetPath
	}

	accessName := imageName
	if target.Name != dockerHubName {
		accessName = target.Name + "/" + imageName
	}
	if allowed, reason := utils.GlobalAccessController.CheckDockerAccess(accessName); !allowed {
		fmt.Printf("Docker image %s access denied: %s\n", accessName, reason)
		c.String(http.StatusForbidden, reason)
		return
	}

	proxyRegistryHTTP(c, target, "/v2/"+targetPath)
}

// 解析去掉 /v2/ 前缀后的 Registry 路径。
func parseRegistryPath(path string) (imageName, apiType, reference string) {
	if idx := strings.Index(path, "/manifests/"); idx != -1 {
		return path[:idx], "manifests", path[idx+len("/manifests/"):]
	}
	if idx := strings.Index(path, "/blobs/"); idx != -1 {
		return path[:idx], "blobs", path[idx+len("/blobs/"):]
	}
	if idx := strings.Index(path, "/tags/list"); idx != -1 {
		return path[:idx], "tags", "list"
	}
	return "", "", ""
}

// 统一认证入口
func ProxyDockerAuthGin(c *gin.Context) {
	HandleDockerAuthToken(c)
}

func (s *anonymousTokenStore) RememberFromResponse(body []byte, ttl time.Duration) {
	token := tokenFromAuthResponse(body)
	if token == "" || ttl <= 0 {
		return
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	key := tokenHash(token)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(now)
	if len(s.entries) >= maxAnonymousTokens {
		return
	}
	s.entries[key] = expiresAt
}

func (s *anonymousTokenStore) IsKnown(token string) bool {
	if token == "" {
		return false
	}

	key := tokenHash(token)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	expiresAt, ok := s.entries[key]
	if !ok {
		return false
	}
	if now.After(expiresAt) {
		delete(s.entries, key)
		return false
	}
	return true
}

func (s *anonymousTokenStore) cleanupLocked(now time.Time) {
	for key, expiresAt := range s.entries {
		if now.After(expiresAt) {
			delete(s.entries, key)
		}
	}
}

func tokenFromAuthResponse(body []byte) string {
	var tokenResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return ""
	}
	if tokenResp.Token != "" {
		return tokenResp.Token
	}
	return tokenResp.AccessToken
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func buildAuthURL(target registryTarget, rawQuery string) (string, error) {
	authURL, err := url.Parse(target.AuthRealm)
	if err != nil {
		return "", err
	}

	query := authURL.Query()
	query.Set("service", target.AuthService)

	if rawQuery != "" {
		incoming, err := url.ParseQuery(rawQuery)
		if err != nil {
			return "", err
		}
		for key, values := range incoming {
			if strings.EqualFold(key, "service") {
				continue
			}
			for _, value := range values {
				if strings.EqualFold(key, "scope") {
					value = normalizeScopeForTarget(value, target)
				}
				query.Add(key, value)
			}
		}
	}

	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func normalizeScopeForTarget(scope string, target registryTarget) string {
	scope = stripTargetRegistryFromScope(scope, target)
	if target.AutoLibraryPrefix {
		return addLibraryPrefixToScope(scope)
	}
	return scope
}

func stripTargetRegistryFromScope(scope string, target registryTarget) string {
	parts := strings.Split(scope, ":")
	if len(parts) != 3 || parts[0] != "repository" {
		return scope
	}

	prefixes := []string{target.Name + "/"}
	if target.Name == dockerHubName {
		prefixes = append(prefixes, "dockerhub/", "registry-1.docker.io/")
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(parts[1], prefix) {
			parts[1] = strings.TrimPrefix(parts[1], prefix)
			return strings.Join(parts, ":")
		}
	}
	return scope
}

func addLibraryPrefixToScope(scope string) string {
	parts := strings.Split(scope, ":")
	if len(parts) != 3 || parts[0] != "repository" || strings.Contains(parts[1], "/") {
		return scope
	}
	return "repository:library/" + parts[1] + ":" + parts[2]
}

func proxyRegistryHTTP(c *gin.Context, target registryTarget, upstreamPath string) {
	if cacheKey, ok := manifestCacheKey(c, target, upstreamPath); ok {
		if cachedItem := utils.GlobalCache.Get(cacheKey); cachedItem != nil {
			utils.WriteCachedResponse(c, cachedItem)
			return
		}
	}

	targetURL := target.Upstream + upstreamPath
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, targetURL, nil)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to create registry request")
		return
	}
	forwardSelectedRequestHeaders(req.Header, c.Request.Header)

	// 如果客户端携带的是本站自建 JWT Token，需要将其转换为官方或上游 Token 传给上游 registry
	// 如果客户端未携带 Authorization（例如专属二级域名免登直拉，或公开匿名直拉），则自动向上游申请并注入 Token
	authHeader := c.GetHeader("Authorization")
	scope := "repository:" + strings.TrimPrefix(upstreamPath, "/v2/")
	if idx := strings.Index(scope, "/manifests/"); idx != -1 {
		scope = scope[:idx] + ":pull"
	} else if idx := strings.Index(scope, "/blobs/"); idx != -1 {
		scope = scope[:idx] + ":pull"
	}

	needsInjectUpstreamToken := false
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if claims, err := ParseLocalToken(tokenStr); err == nil {
			req.Header.Del("Authorization") // 移除本站自建 JWT
			needsInjectUpstreamToken = true
			_ = claims
		}
	} else if authHeader == "" && target.AuthRealm != "" {
		// 客户端未携带 Authorization（专属二级域名直拉或匿名模式），自动代理上游鉴权
		needsInjectUpstreamToken = true
	}

	if needsInjectUpstreamToken {
		if upstreamCred, err := db.GetActiveUpstreamCredential(target.Name); err == nil && upstreamCred != nil {
			upstreamToken, err := fetchUpstreamTokenWithCred(target, scope, upstreamCred.Username, upstreamCred.Password)
			if err == nil && upstreamToken != "" {
				var tokStruct struct {
					Token       string `json:"token"`
					AccessToken string `json:"access_token"`
				}
				_ = json.Unmarshal([]byte(upstreamToken), &tokStruct)
				finalTok := tokStruct.Token
				if finalTok == "" {
					finalTok = tokStruct.AccessToken
				}
				if finalTok != "" {
					req.Header.Set("Authorization", "Bearer "+finalTok)
				}
			}
		} else {
			// 如果服务端没有配置专门的 upstreamCred，以匿名身份向上游 registry 换取临时上游 token
			anonToken, err := fetchUpstreamTokenWithCred(target, scope, "", "")
			if err == nil && anonToken != "" {
				var tokStruct struct {
					Token       string `json:"token"`
					AccessToken string `json:"access_token"`
				}
				_ = json.Unmarshal([]byte(anonToken), &tokStruct)
				finalTok := tokStruct.Token
				if finalTok == "" {
					finalTok = tokStruct.AccessToken
				}
				if finalTok != "" {
					req.Header.Set("Authorization", "Bearer "+finalTok)
				}
			}
		}
	}

	resp, err := utils.GetGlobalHTTPClient().Do(req)
	if err != nil {
		c.String(http.StatusBadGateway, "Registry request failed")
		return
	}
	defer resp.Body.Close()

	// 对于 301, 302, 307 重定向（Docker Registry 的 Blob 下载通常重定向到 Cloudflare R2 / AWS S3 / 官方 CDN）
	// 我们透明地在代理层代为拉取并流式回传给客户端，或者重写 Location，避免国内客户端直连 Cloudflare/AWS S3 被墙超时！
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusMovedPermanently {
		loc := resp.Header.Get("Location")
		if loc != "" && (strings.Contains(upstreamPath, "/blobs/") || strings.Contains(upstreamPath, "/manifests/")) {
			// 服务端代理下载重定向的实际 Blob 数据流
			redirectReq, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, loc, nil)
			if err == nil {
				forwardSelectedRequestHeaders(redirectReq.Header, c.Request.Header)
				redirectReq.Header.Del("Authorization") // S3/Cloudflare 签名 URL 不需要且不能带原有 Registry Bearer Token
				redirectResp, err := utils.GetRedirectHTTPClient().Do(redirectReq)
				if err == nil {
					defer redirectResp.Body.Close()
					for k, vv := range redirectResp.Header {
						if !shouldSkipResponseHeader(k) {
							for _, v := range vv {
								c.Header(k, v)
							}
						}
					}
					c.Status(redirectResp.StatusCode)
					if c.Request.Method != http.MethodHead {
						_, _ = io.Copy(c.Writer, redirectResp.Body)
					}
					return
				}
			}
			// 如果服务端请求重定向目标失败，则保留 Location 返回给客户端自行尝试
		}
	}

	copyResponseHeaders(c, resp.Header, target)
	c.Status(resp.StatusCode)

	if c.Request.Method == http.MethodHead {
		return
	}

	if cacheKey, ok := manifestCacheKey(c, target, upstreamPath); ok && canCacheManifestResponse(resp) {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Failed to read manifest response: %v\n", err)
			return
		}
		contentType := resp.Header.Get("Content-Type")
		utils.GlobalCache.Set(cacheKey, body, contentType, cacheHeaders(resp.Header), utils.GetManifestTTL(manifestReference(upstreamPath)))
		c.Data(resp.StatusCode, contentType, body)
		return
	}

	if _, err := io.Copy(c.Writer, resp.Body); err != nil {
		fmt.Printf("Failed to stream registry response: %v\n", err)
	}
}

func manifestCacheKey(c *gin.Context, target registryTarget, upstreamPath string) (string, bool) {
	if c.Request.Method != http.MethodGet || !utils.IsCacheEnabled() || !isAnonymousManifestRequest(c) {
		return "", false
	}
	if !strings.Contains(upstreamPath, "/manifests/") {
		return "", false
	}

	key := strings.Join([]string{
		target.Name,
		upstreamPath,
		c.Request.URL.RawQuery,
		strings.Join(c.Request.Header.Values("Accept"), ","),
	}, "|")
	return utils.BuildCacheKey("manifest", key), true
}

func isAnonymousManifestRequest(c *gin.Context) bool {
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if authHeader == "" {
		return true
	}

	const bearerPrefix = "bearer "
	if len(authHeader) <= len(bearerPrefix) || !strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
		return false
	}

	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	return anonymousTokens.IsKnown(token)
}

func canCacheManifestResponse(resp *http.Response) bool {
	return resp.StatusCode == http.StatusOK &&
		resp.ContentLength > 0 &&
		resp.ContentLength <= maxCachedManifestSize
}

func manifestReference(upstreamPath string) string {
	_, _, reference := parseRegistryPath(strings.TrimPrefix(upstreamPath, "/v2/"))
	return reference
}

func cacheHeaders(headers http.Header) map[string]string {
	cached := make(map[string]string)
	for name, values := range headers {
		if shouldSkipResponseHeader(name) || strings.EqualFold(name, "WWW-Authenticate") || len(values) == 0 {
			continue
		}
		cached[name] = values[0]
	}
	return cached
}

func forwardSelectedRequestHeaders(dst http.Header, src http.Header) {
	for _, name := range forwardedRequestHeaders {
		for _, value := range src.Values(name) {
			dst.Add(name, value)
		}
	}
}

func copyResponseHeaders(c *gin.Context, headers http.Header, target registryTarget) {
	for name, values := range headers {
		if shouldSkipResponseHeader(name) {
			continue
		}

		for _, value := range values {
			if strings.EqualFold(name, "WWW-Authenticate") {
				value = rewriteAuthChallenge(value, target, publicBaseURL(c))
				c.Header("WWW-Authenticate", value)
			} else {
				c.Header(name, value)
			}
		}
	}
}

func shouldSkipResponseHeader(name string) bool {
	_, hopByHop := hopByHopHeaders[strings.ToLower(name)]
	return hopByHop
}

func publicBaseURL(c *gin.Context) string {
	proto := "http"
	if c.Request.TLS != nil {
		proto = "https"
	}
	if forwardedProto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); forwardedProto != "" {
		proto = strings.Split(forwardedProto, ",")[0]
	}

	host := c.Request.Host
	if host == "" {
		cfg := config.GetConfig()
		host = fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
		if cfg.Server.Host == "0.0.0.0" {
			host = fmt.Sprintf("localhost:%d", cfg.Server.Port)
		}
	}

	return strings.TrimRight(proto+"://"+host, "/")
}

func rewriteAuthChallenge(authHeader string, target registryTarget, baseURL string) string {
	if !strings.HasPrefix(strings.TrimSpace(strings.ToLower(authHeader)), "bearer ") {
		return authHeader
	}

	scope := bearerParam(authHeader, "scope")
	challenge := fmt.Sprintf(
		`Bearer realm="%s/token/%s",service="%s"`,
		baseURL,
		escapeAuthParam(target.Name),
		escapeAuthParam(target.AuthService),
	)
	if scope != "" {
		challenge += fmt.Sprintf(`,scope="%s"`, escapeAuthParam(scope))
	}
	return challenge
}

func bearerParam(authHeader, paramName string) string {
	input := strings.TrimSpace(authHeader)
	if len(input) < len("Bearer ") || !strings.EqualFold(input[:len("Bearer ")], "Bearer ") {
		return ""
	}
	input = strings.TrimSpace(input[len("Bearer "):])

	for input != "" {
		input = strings.TrimLeft(input, ", \t")
		key, rest, found := strings.Cut(input, "=")
		if !found {
			return ""
		}
		key = strings.TrimSpace(key)
		rest = strings.TrimSpace(rest)

		var value string
		if strings.HasPrefix(rest, `"`) {
			rest = rest[1:]
			var b strings.Builder
			escaped := false
			end := -1
			for i, r := range rest {
				if escaped {
					b.WriteRune(r)
					escaped = false
					continue
				}
				if r == '\\' {
					escaped = true
					continue
				}
				if r == '"' {
					end = i + 1
					break
				}
				b.WriteRune(r)
			}
			if end == -1 {
				return ""
			}
			value = b.String()
			input = rest[end:]
		} else {
			value, input, _ = strings.Cut(rest, ",")
			value = strings.TrimSpace(value)
		}

		if strings.EqualFold(key, paramName) {
			return value
		}
	}

	return ""
}

func escapeAuthParam(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
