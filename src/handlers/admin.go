package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"hubproxy/db"
)

// 管理员登录
func AdminLoginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	user, err := db.GetUserByUsername(req.Username)
	if err != nil || !db.VerifyPassword(req.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	if !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "非管理员用户无权访问后台"})
		return
	}

	if !user.IsEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "账号已被禁用"})
		return
	}

	token, err := GenerateLocalToken(user.Username, true, "admin-dashboard", nil, 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成凭证失败"})
		return
	}

	c.SetCookie("admin_token", token, 86400, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"username": user.Username,
	})
}

// 获取仪表盘统计数据
func AdminStatsHandler(c *gin.Context) {
	var totalUsers int64
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username != 'anonymous'`).Scan(&totalUsers)

	var totalPulls int64
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM pull_logs`).Scan(&totalPulls)

	currentMonth := time.Now().Format("2006-01")
	var monthlyPulls int64
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM pull_logs WHERE strftime('%Y-%m', created_at) = ?`, currentMonth).Scan(&monthlyPulls)

	var todayPulls int64
	todayStr := time.Now().Format("2006-01-02")
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM pull_logs WHERE date(created_at) = ?`, todayStr).Scan(&todayPulls)

	var totalTraffic int64
	_ = db.DB.QueryRow(`SELECT COALESCE(SUM(bytes_sent), 0) FROM pull_logs`).Scan(&totalTraffic)

	var monthlyTraffic int64
	_ = db.DB.QueryRow(`SELECT COALESCE(SUM(bytes_sent), 0) FROM pull_logs WHERE strftime('%Y-%m', created_at) = ?`, currentMonth).Scan(&monthlyTraffic)

	c.JSON(http.StatusOK, gin.H{
		"total_users":     totalUsers,
		"total_pulls":     totalPulls,
		"monthly_pulls":   monthlyPulls,
		"today_pulls":     todayPulls,
		"total_traffic":   totalTraffic,
		"monthly_traffic": monthlyTraffic,
	})
}

// 用户列表
func AdminListUsersHandler(c *gin.Context) {
	users, err := db.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// 创建用户
func AdminCreateUserHandler(c *gin.Context) {
	var req struct {
		Username            string  `json:"username"`
		Password            string  `json:"password"`
		MonthlyQuota        int64   `json:"monthly_quota"`
		MonthlyTrafficQuota int64   `json:"monthly_traffic_quota"` // 流量配额（字节）
		IsAdmin             bool    `json:"is_admin"`
		ExpiresAt           *string `json:"expires_at"`
		Remark              string  `json:"remark"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	var exp *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err == nil {
			exp = &t
		}
	}

	err := db.CreateUser(req.Username, req.Password, req.MonthlyQuota, req.MonthlyTrafficQuota, req.IsAdmin, exp, req.Remark)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "创建成功"})
}

// 更新用户
func AdminUpdateUserHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	var req struct {
		Password            string  `json:"password"`
		MonthlyQuota        int64   `json:"monthly_quota"`
		MonthlyTrafficQuota int64   `json:"monthly_traffic_quota"` // 流量配额（字节）
		IsEnabled           bool    `json:"is_enabled"`
		IsAdmin             bool    `json:"is_admin"`
		ExpiresAt           *string `json:"expires_at"`
		Remark              string  `json:"remark"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	var exp *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err == nil {
			exp = &t
		}
	}

	err := db.UpdateUser(id, req.Password, req.MonthlyQuota, req.MonthlyTrafficQuota, req.IsEnabled, req.IsAdmin, exp, req.Remark)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// 删除用户
func AdminDeleteUserHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	err := db.DeleteUser(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// 日志查询
func AdminLogsHandler(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	username := c.Query("username")
	keyword := c.Query("keyword")

	logs, total, err := db.QueryPullLogs(limit, offset, username, keyword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total": total,
		"logs":  logs,
	})
}

// 上游凭据列表
func AdminListUpstreamHandler(c *gin.Context) {
	list, err := db.ListUpstreamCredentials()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"credentials": list})
}

// 保存上游凭据
func AdminSaveUpstreamHandler(c *gin.Context) {
	var req db.UpstreamCredential
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	err := db.SaveUpstreamCredential(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "保存成功"})
}

// 删除上游凭据
func AdminDeleteUpstreamHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	err := db.DeleteUpstreamCredential(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// 系统设置获取与更新
func AdminGetSettingsHandler(c *gin.Context) {
	settings := db.GetAllSettings()
	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

func AdminUpdateSettingsHandler(c *gin.Context) {
	var settings map[string]string
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	for k, v := range settings {
		_ = db.SetSetting(k, v)
	}
	c.JSON(http.StatusOK, gin.H{"message": "保存成功"})
}

// 注册后台 API 路由
func RegisterAdminRoutes(router *gin.Engine) {
	api := router.Group("/api/admin")
	{
		api.POST("/login", AdminLoginHandler)

		// 受保护后台接口
		protected := api.Group("")
		protected.Use(AdminAuthRequired())
		{
			protected.GET("/stats", AdminStatsHandler)
			protected.GET("/users", AdminListUsersHandler)
			protected.POST("/users", AdminCreateUserHandler)
			protected.PUT("/users/:id", AdminUpdateUserHandler)
			protected.DELETE("/users/:id", AdminDeleteUserHandler)

			protected.GET("/logs", AdminLogsHandler)

			protected.GET("/upstreams", AdminListUpstreamHandler)
			protected.POST("/upstreams", AdminSaveUpstreamHandler)
			protected.DELETE("/upstreams/:id", AdminDeleteUpstreamHandler)

			protected.GET("/settings", AdminGetSettingsHandler)
			protected.POST("/settings", AdminUpdateSettingsHandler)
		}
	}
}
