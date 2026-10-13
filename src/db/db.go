package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	DB   *sql.DB
	once sync.Once
)

type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	MonthlyQuota int64      `json:"monthly_quota"` // 每月限额拉取次数，0 表示无限制
	UsedQuota    int64      `json:"used_quota"`    // 当前自然月已用次数
	QuotaMonth   string     `json:"quota_month"`   // 当前统计月份，如 "2026-10"
	IsEnabled    bool       `json:"is_enabled"`
	IsAdmin      bool       `json:"is_admin"`
	ExpiresAt    *time.Time `json:"expires_at"` // 到期时间，nil 表示永不过期
	Remark       string     `json:"remark"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type PullLog struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"` // 匿名则为 "anonymous"
	ClientIP  string    `json:"client_ip"`
	Registry  string    `json:"registry"` // 目标 registry，如 docker.io, ghcr.io
	Image     string    `json:"image"`    // 镜像名
	Action    string    `json:"action"`   // pull, manifest, search, tar
	Status    int       `json:"status"`   // HTTP 状态码
	DurationMs int64    `json:"duration_ms"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}

type UpstreamCredential struct {
	ID        int64     `json:"id"`
	Registry  string    `json:"registry"` // 如 "docker.io"
	Username  string    `json:"username"`
	Password  string    `json:"password"` // Docker Hub PAT 或密码
	IsEnabled bool      `json:"is_enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SystemSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func InitDB(dbPath string) error {
	var initErr error
	once.Do(func() {
		if dbPath == "" {
			dbPath = "hubproxy.db"
		}

		absPath, err := filepath.Abs(dbPath)
		if err == nil {
			dbPath = absPath
		}

		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			initErr = fmt.Errorf("create db dir %s failed: %w", dir, err)
			return
		}

		dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", dbPath)
		DB, err = sql.Open("sqlite", dsn)
		if err != nil {
			initErr = fmt.Errorf("open sqlite db failed: %w", err)
			return
		}

		DB.SetMaxOpenConns(1) // SQLite 保持单写连接防锁竞争

		if err := createTables(); err != nil {
			initErr = fmt.Errorf("create tables failed: %w", err)
			return
		}

		if err := initDefaultData(); err != nil {
			initErr = fmt.Errorf("init default data failed: %w", err)
			return
		}
	})

	return initErr
}

func createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		monthly_quota INTEGER NOT NULL DEFAULT 0,
		used_quota INTEGER NOT NULL DEFAULT 0,
		quota_month TEXT NOT NULL DEFAULT '',
		is_enabled INTEGER NOT NULL DEFAULT 1,
		is_admin INTEGER NOT NULL DEFAULT 0,
		expires_at DATETIME,
		remark TEXT DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS pull_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL DEFAULT 'anonymous',
		client_ip TEXT NOT NULL DEFAULT '',
		registry TEXT NOT NULL DEFAULT '',
		image TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT '',
		status INTEGER NOT NULL DEFAULT 200,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		user_agent TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_pull_logs_created_at ON pull_logs(created_at);
	CREATE INDEX IF NOT EXISTS idx_pull_logs_username ON pull_logs(username);
	CREATE INDEX IF NOT EXISTS idx_pull_logs_client_ip ON pull_logs(client_ip);

	CREATE TABLE IF NOT EXISTS upstream_credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		registry TEXT NOT NULL,
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		is_enabled INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS system_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	`
	_, err := DB.Exec(schema)
	return err
}

func initDefaultData() error {
	// 初始化系统默认设置
	defaultSettings := map[string]string{
		"allow_anonymous":         "true", // 是否允许匿名拉取
		"anonymous_monthly_quota": "50",   // 每个IP匿名拉取的月限额（0为不限）
		"allow_passthrough":       "true", // 是否允许未在本地注册的 docker hub 用户账号透传
	}

	for k, v := range defaultSettings {
		_, _ = DB.Exec(`INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)`, k, v)
	}

	// 初始化默认管理员 admin / admin123456 (如果不存在任何管理员)
	var count int
	err := DB.QueryRow(`SELECT COUNT(*) FROM users WHERE is_admin = 1`).Scan(&count)
	if err == nil && count == 0 {
		now := time.Now()
		// SHA256 of "admin123456" = "e10adc3949ba59abbe56e057f20f883e" (md5) or sha256
		// 我们用 sha256: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
		adminHash := HashPassword("admin123456")
		_, _ = DB.Exec(`INSERT INTO users (username, password_hash, monthly_quota, used_quota, quota_month, is_enabled, is_admin, remark, created_at, updated_at) 
			VALUES (?, ?, ?, 0, ?, 1, 1, '默认超级管理员', ?, ?)`,
			"admin", adminHash, 0, now.Format("2006-01"), now, now)
	}

	return nil
}
