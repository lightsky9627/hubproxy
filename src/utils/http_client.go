package utils

import (
	"net"
	"net/http"
	"os"
	"time"

	"hubproxy/config"
)

var (
	globalHTTPClient   *http.Client
	redirectHTTPClient *http.Client
	searchHTTPClient   *http.Client
)

// InitHTTPClients 初始化HTTP客户端
func InitHTTPClients() {
	cfg := config.GetConfig()

	if p := cfg.Access.Proxy; p != "" {
		os.Setenv("HTTP_PROXY", p)
		os.Setenv("HTTPS_PROXY", p)
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   1000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 300 * time.Second,
	}

	// globalHTTPClient: 禁止默认跟随重定向，用于捕获 Registry 返回的 301/302/307
	globalHTTPClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}

	// redirectHTTPClient: 允许正常跟随重定向（最多 10 跳），用于下载 S3/Cloudflare/Google 实际资源分块
	redirectHTTPClient = &http.Client{
		Transport: transport,
	}

	searchHTTPClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			DisableCompression:  false,
		},
	}
}

// GetGlobalHTTPClient 获取全局HTTP客户端
func GetGlobalHTTPClient() *http.Client {
	if globalHTTPClient == nil {
		InitHTTPClients()
	}
	return globalHTTPClient
}

// GetRedirectHTTPClient 获取用于流式下载重定向 Blob/Manifest 资源的客户端（自动跟随重定向）
func GetRedirectHTTPClient() *http.Client {
	if redirectHTTPClient == nil {
		InitHTTPClients()
	}
	return redirectHTTPClient
}

// GetSearchHTTPClient 获取搜索HTTP客户端
func GetSearchHTTPClient() *http.Client {
	if searchHTTPClient == nil {
		InitHTTPClients()
	}
	return searchHTTPClient
}
