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
func GetUserByID(id int64) (*User, error) {
	if DB == nil {
		return nil, sql.ErrNoRows
	}
	row := DB.QueryRow(`
		SELECT id, username, password_hash, monthly_quota, used_quota, monthly_traffic_quota, used_traffic_bytes, quota_month, 
		       is_enabled, is_admin, expires_at, remark, created_at, updated_at
		FROM users WHERE id = ?
	`, id)

	var u User
	var expiresAt sql.NullTime
	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.MonthlyQuota, &u.UsedQuota, &u.MonthlyTrafficQuota, &u.UsedTrafficBytes, &u.QuotaMonth,
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

func GetUserByUsername(username string) (*User, error) {
	if DB == nil {
		return nil, sql.ErrNoRows
	}
	row := DB.QueryRow(`
		SELECT id, username, password_hash, monthly_quota, used_quota, monthly_traffic_quota, used_traffic_bytes, quota_month, 
		       is_enabled, is_admin, expires_at, remark, created_at, updated_at
		FROM users WHERE username = ?
	`, username)

	var u User
	var expiresAt sql.NullTime
	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.MonthlyQuota, &u.UsedQuota, &u.MonthlyTrafficQuota, &u.UsedTrafficBytes, &u.QuotaMonth,
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
		SELECT id, username, monthly_quota, used_quota, monthly_traffic_quota, used_traffic_bytes, quota_month, 
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
			&u.ID, &u.Username, &u.MonthlyQuota, &u.UsedQuota, &u.MonthlyTrafficQuota, &u.UsedTrafficBytes, &u.QuotaMonth,
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

func CreateUser(username, password string, monthlyQuota, monthlyTrafficQuota int64, isAdmin bool, expiresAt *time.Time, remark string) error {
	now := time.Now()
	month := now.Format("2006-01")
	hash := HashPassword(password)
	_, err := DB.Exec(`
		INSERT INTO users (username, password_hash, monthly_quota, used_quota, monthly_traffic_quota, used_traffic_bytes, quota_month, is_enabled, is_admin, expires_at, remark, created_at, updated_at)
		VALUES (?, ?, ?, 0, ?, 0, ?, 1, ?, ?, ?, ?, ?)
	`, username, hash, monthlyQuota, monthlyTrafficQuota, month, isAdmin, expiresAt, remark, now, now)
	return err
}

func UpdateUser(id int64, password string, monthlyQuota, monthlyTrafficQuota int64, isEnabled bool, isAdmin bool, expiresAt *time.Time, remark string) error {
	now := time.Now()
	if password != "" {
		hash := HashPassword(password)
		_, err := DB.Exec(`
			UPDATE users SET password_hash = ?, monthly_quota = ?, monthly_traffic_quota = ?, is_enabled = ?, is_admin = ?, expires_at = ?, remark = ?, updated_at = ?
			WHERE id = ?
		`, hash, monthlyQuota, monthlyTrafficQuota, isEnabled, isAdmin, expiresAt, remark, now, id)
		return err
	}
	_, err := DB.Exec(`
		UPDATE users SET monthly_quota = ?, monthly_traffic_quota = ?, is_enabled = ?, is_admin = ?, expires_at = ?, remark = ?, updated_at = ?
		WHERE id = ?
	`, monthlyQuota, monthlyTrafficQuota, isEnabled, isAdmin, expiresAt, remark, now, id)
	return err
}

func DeleteUser(id int64) error {
	_, err := DB.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// 检查并扣除配额（按自然月重置，同时检查次数和总流量配额）
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

	// 流量超限检查 (月流量上限 > 0 且已用流量 >= 上限)
	if user.MonthlyTrafficQuota > 0 && user.UsedTrafficBytes >= user.MonthlyTrafficQuota {
		return false, fmt.Sprintf("当月总流量已耗尽 (%d MB / %d MB)", user.UsedTrafficBytes/(1024*1024), user.MonthlyTrafficQuota/(1024*1024))
	}

	if user.MonthlyQuota <= 0 {
		// 无限制次数配额
		return true, ""
	}

	// 月度重置判断
	used := user.UsedQuota
	if user.QuotaMonth != currentMonth {
		used = 0
		_, _ = DB.Exec(`UPDATE users SET used_quota = 0, used_traffic_bytes = 0, quota_month = ? WHERE username = ?`, currentMonth, username)
	}

	if used >= user.MonthlyQuota {
		return false, fmt.Sprintf("已达到当月配额上限 (%d/%d)", used, user.MonthlyQuota)
	}

	// 递增配额
	_, _ = DB.Exec(`UPDATE users SET used_quota = used_quota + 1, quota_month = ? WHERE username = ?`, currentMonth, username)
	return true, ""
}

// 累计增加用户已消耗流量
func AddUserTraffic(username string, bytes int64) {
	if DB == nil || bytes <= 0 {
		return
	}
	currentMonth := time.Now().Format("2006-01")
	_, _ = DB.Exec(`
		UPDATE users 
		SET used_traffic_bytes = used_traffic_bytes + ?,
		    quota_month = CASE WHEN quota_month = ? THEN quota_month ELSE ? END,
		    used_quota = CASE WHEN quota_month = ? THEN used_quota ELSE 0 END
		WHERE username = ?
	`, bytes, currentMonth, currentMonth, currentMonth, username)
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
		INSERT INTO pull_logs (username, client_ip, registry, image, action, status, duration_ms, bytes_sent, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, log.Username, log.ClientIP, log.Registry, log.Image, log.Action, log.Status, log.DurationMs, log.BytesSent, log.UserAgent, log.CreatedAt)

	// 同时将消耗的流量累计到对应用户（或 anonymous 统一虚拟用户）
	if log.BytesSent > 0 && log.Username != "" {
		AddUserTraffic(log.Username, log.BytesSent)
	}
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

	dataSQL := `SELECT id, username, client_ip, registry, image, action, status, duration_ms, bytes_sent, user_agent, created_at ` +
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
			&l.Action, &l.Status, &l.DurationMs, &l.BytesSent, &l.UserAgent, &l.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}

// 清理指定天数前的历史拉取日志 (默认 30 天)
func CleanOldPullLogs(retentionDays int) (int64, error) {
	if DB == nil {
		return 0, nil
	}
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02 15:04:05")
	res, err := DB.Exec(`DELETE FROM pull_logs WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// 启动后台日志定期清理任务 (每 24 小时执行一次)
func StartLogCleanupCron(retentionDays int) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		// 启动时先执行一次清理
		_, _ = CleanOldPullLogs(retentionDays)

		for range ticker.C {
			_, _ = CleanOldPullLogs(retentionDays)
		}
	}()
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
