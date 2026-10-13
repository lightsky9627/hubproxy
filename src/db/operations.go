package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

func HashPassword(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func VerifyPassword(raw, hash string) bool {
	return HashPassword(raw) == hash
}

// User CRUD
func GetUserByUsername(username string) (*User, error) {
	if DB == nil {
		return nil, sql.ErrNoRows
	}
	row := DB.QueryRow(`
		SELECT id, username, password_hash, monthly_quota, used_quota, quota_month, 
		       is_enabled, is_admin, expires_at, remark, created_at, updated_at
		FROM users WHERE username = ?
	`, username)

	var u User
	var expiresAt sql.NullTime
	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.MonthlyQuota, &u.UsedQuota, &u.QuotaMonth,
		&u.IsEnabled, &u.IsAdmin, &expiresAt, &u.Remark, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		u.ExpiresAt = &expiresAt.Time
	}
	return &u, nil
}

func ListUsers() ([]User, error) {
	rows, err := DB.Query(`
		SELECT id, username, monthly_quota, used_quota, quota_month, 
		       is_enabled, is_admin, expires_at, remark, created_at, updated_at
		FROM users ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var expiresAt sql.NullTime
		if err := rows.Scan(
			&u.ID, &u.Username, &u.MonthlyQuota, &u.UsedQuota, &u.QuotaMonth,
			&u.IsEnabled, &u.IsAdmin, &expiresAt, &u.Remark, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if expiresAt.Valid {
			u.ExpiresAt = &expiresAt.Time
		}
		users = append(users, u)
	}
	return users, nil
}

func CreateUser(username, password string, monthlyQuota int64, isAdmin bool, expiresAt *time.Time, remark string) error {
	now := time.Now()
	month := now.Format("2006-01")
	hash := HashPassword(password)
	_, err := DB.Exec(`
		INSERT INTO users (username, password_hash, monthly_quota, used_quota, quota_month, is_enabled, is_admin, expires_at, remark, created_at, updated_at)
		VALUES (?, ?, ?, 0, ?, 1, ?, ?, ?, ?, ?)
	`, username, hash, monthlyQuota, month, isAdmin, expiresAt, remark, now, now)
	return err
}

func UpdateUser(id int64, password string, monthlyQuota int64, isEnabled bool, isAdmin bool, expiresAt *time.Time, remark string) error {
	now := time.Now()
	if password != "" {
		hash := HashPassword(password)
		_, err := DB.Exec(`
			UPDATE users SET password_hash = ?, monthly_quota = ?, is_enabled = ?, is_admin = ?, expires_at = ?, remark = ?, updated_at = ?
			WHERE id = ?
		`, hash, monthlyQuota, isEnabled, isAdmin, expiresAt, remark, now, id)
		return err
	}
	_, err := DB.Exec(`
		UPDATE users SET monthly_quota = ?, is_enabled = ?, is_admin = ?, expires_at = ?, remark = ?, updated_at = ?
		WHERE id = ?
	`, monthlyQuota, isEnabled, isAdmin, expiresAt, remark, now, id)
	return err
}

func DeleteUser(id int64) error {
	_, err := DB.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// 检查并扣除配额（按自然月重置）
func CheckAndConsumeUserQuota(username string) (bool, string) {
	if DB == nil {
		return true, ""
	}
	currentMonth := time.Now().Format("2006-01")
	user, err := GetUserByUsername(username)
	if err != nil {
		return false, "用户不存在"
	}

	if !user.IsEnabled {
		return false, "用户已被禁用"
	}

	if user.ExpiresAt != nil && time.Now().After(*user.ExpiresAt) {
		return false, "账号已过期"
	}

	if user.MonthlyQuota <= 0 {
		// 无限制配额
		return true, ""
	}

	// 月度重置判断
	used := user.UsedQuota
	if user.QuotaMonth != currentMonth {
		used = 0
		_, _ = DB.Exec(`UPDATE users SET used_quota = 0, quota_month = ? WHERE username = ?`, currentMonth, username)
	}

	if used >= user.MonthlyQuota {
		return false, fmt.Sprintf("已达到当月配额上限 (%d/%d)", used, user.MonthlyQuota)
	}

	// 递增配额
	_, _ = DB.Exec(`UPDATE users SET used_quota = used_quota + 1, quota_month = ? WHERE username = ?`, currentMonth, username)
	return true, ""
}

// 检查并扣除 IP 匿名配额
func CheckAndConsumeIPQuota(ip string, monthlyLimit int64) (bool, string) {
	if monthlyLimit <= 0 || DB == nil {
		return true, ""
	}

	currentMonth := time.Now().Format("2006-01")
	// 统计当前 IP 在本月的匿名拉取次数
	var count int64
	err := DB.QueryRow(`
		SELECT COUNT(*) FROM pull_logs 
		WHERE client_ip = ? AND username = 'anonymous' AND strftime('%Y-%m', created_at) = ?
	`, ip, currentMonth).Scan(&count)
	if err != nil {
		return true, "" // 查询异常时放行
	}

	if count >= monthlyLimit {
		return false, fmt.Sprintf("匿名用户本月拉取次数已达上限 (%d/%d)", count, monthlyLimit)
	}

	return true, ""
}

// PullLog 操作
func RecordPullLog(log PullLog) {
	if DB == nil {
		return
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	_, _ = DB.Exec(`
		INSERT INTO pull_logs (username, client_ip, registry, image, action, status, duration_ms, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, log.Username, log.ClientIP, log.Registry, log.Image, log.Action, log.Status, log.DurationMs, log.UserAgent, log.CreatedAt)
}

func QueryPullLogs(limit, offset int, username, keyword string) ([]PullLog, int64, error) {
	query := `FROM pull_logs WHERE 1=1`
	var args []interface{}

	if username != "" {
		query += ` AND username = ?`
		args = append(args, username)
	}
	if keyword != "" {
		query += ` AND (image LIKE ? OR client_ip LIKE ?)`
		pattern := "%" + keyword + "%"
		args = append(args, pattern, pattern)
	}

	var total int64
	countSQL := `SELECT COUNT(*) ` + query
	if err := DB.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataSQL := `SELECT id, username, client_ip, registry, image, action, status, duration_ms, user_agent, created_at ` +
		query + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := DB.Query(dataSQL, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []PullLog
	for rows.Next() {
		var l PullLog
		if err := rows.Scan(
			&l.ID, &l.Username, &l.ClientIP, &l.Registry, &l.Image,
			&l.Action, &l.Status, &l.DurationMs, &l.UserAgent, &l.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}

// Upstream Credentials 操作
func ListUpstreamCredentials() ([]UpstreamCredential, error) {
	rows, err := DB.Query(`SELECT id, registry, username, password, is_enabled, created_at, updated_at FROM upstream_credentials ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []UpstreamCredential
	for rows.Next() {
		var c UpstreamCredential
		if err := rows.Scan(&c.ID, &c.Registry, &c.Username, &c.Password, &c.IsEnabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, nil
}

func GetActiveUpstreamCredential(registry string) (*UpstreamCredential, error) {
	if DB == nil {
		return nil, sql.ErrNoRows
	}
	row := DB.QueryRow(`
		SELECT id, registry, username, password, is_enabled, created_at, updated_at 
		FROM upstream_credentials 
		WHERE (registry = ? OR registry = 'docker.io') AND is_enabled = 1 
		ORDER BY id ASC LIMIT 1
	`, registry)

	var c UpstreamCredential
	if err := row.Scan(&c.ID, &c.Registry, &c.Username, &c.Password, &c.IsEnabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

func SaveUpstreamCredential(c UpstreamCredential) error {
	now := time.Now()
	if c.ID > 0 {
		_, err := DB.Exec(`
			UPDATE upstream_credentials SET registry = ?, username = ?, password = ?, is_enabled = ?, updated_at = ?
			WHERE id = ?
		`, c.Registry, c.Username, c.Password, c.IsEnabled, now, c.ID)
		return err
	}
	_, err := DB.Exec(`
		INSERT INTO upstream_credentials (registry, username, password, is_enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, c.Registry, c.Username, c.Password, c.IsEnabled, now, now)
	return err
}

func DeleteUpstreamCredential(id int64) error {
	_, err := DB.Exec(`DELETE FROM upstream_credentials WHERE id = ?`, id)
	return err
}

// System Settings 操作
func GetSetting(key, defaultVal string) string {
	if DB == nil {
		return defaultVal
	}
	var val string
	err := DB.QueryRow(`SELECT value FROM system_settings WHERE key = ?`, key).Scan(&val)
	if err != nil {
		return defaultVal
	}
	return val
}

func SetSetting(key, value string) error {
	_, err := DB.Exec(`INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?`, key, value, value)
	return err
}

func GetAllSettings() map[string]string {
	rows, err := DB.Query(`SELECT key, value FROM system_settings`)
	if err != nil {
		return make(map[string]string)
	}
	defer rows.Close()

	res := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			res[k] = v
		}
	}
	return res
}
