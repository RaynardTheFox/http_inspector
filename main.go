package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// User represents a user in the system
type User struct {
	Username  string
	Password  string // NOT HASHED, for demo purposes only!
	IsDeleted bool
}

// Message represents a chat message
type Message struct {
	ID       int       `json:"id"`
	Username string    `json:"username"`
	Text     string    `json:"text"`
	Time     time.Time `json:"time"`
}

// DebugLogEntry represents a debug log entry
type DebugLogEntry struct {
	Timestamp   time.Time
	Host        string
	Path        string
	Method      string
	Code        int
	RemoteAddr  string
	Headers     string
	HandlerFunc string
	Info        string
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type     string    `json:"type"`
	Username string    `json:"username,omitempty"`
	Text     string    `json:"text,omitempty"`
	Messages []Message `json:"messages,omitempty"`
}

// Global variables (must be protected by mutexes)
var (
	users            = make(map[string]*User)
	sessions         = make(map[string]string) // session token -> username
	messages         []Message
	debugLog         []DebugLogEntry
	debugChan        = make(chan DebugLogEntry, 100)  // Channel for log collection
	connections      = make(map[*websocket.Conn]bool) // WebSocket connections
	usersMutex       = &sync.RWMutex{}
	sessionsMutex    = &sync.RWMutex{}
	messagesMutex    = &sync.RWMutex{}
	debugMutex       = &sync.RWMutex{}
	connectionsMutex = &sync.RWMutex{}
	messageID        = 0
	messageIDMutex   = &sync.Mutex{}
)

// generateToken generates a random session token
func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// logDebug adds an entry to the debug log
func logDebug(host, path, method string, code int, remoteAddr, headers, handlerFunc, info string) {
	entry := DebugLogEntry{
		Timestamp:   time.Now(),
		Host:        host,
		Path:        path,
		Method:      method,
		Code:        code,
		RemoteAddr:  remoteAddr,
		Headers:     headers,
		HandlerFunc: handlerFunc,
		Info:        info,
	}

	select {
	case debugChan <- entry:
	default:
		// If channel is full, skip the entry
	}
}

// collectDebugLogs collects log entries from the channel
func collectDebugLogs() {
	for entry := range debugChan {
		debugMutex.Lock()
		debugLog = append(debugLog, entry)
		// Keep log up to 100 entries
		if len(debugLog) > 100 {
			debugLog = debugLog[1:]
		}
		debugMutex.Unlock()
	}
}

// requireAuth checks user authentication
func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logDebug(r.Host, r.URL.Path, r.Method, 401, r.RemoteAddr,
				fmt.Sprintf("%v", r.Header), "requireAuth", "Missing Authorization header")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			logDebug(r.Host, r.URL.Path, r.Method, 401, r.RemoteAddr,
				fmt.Sprintf("%v", r.Header), "requireAuth", "Invalid Authorization header format")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := parts[1]
		sessionsMutex.RLock()
		username, exists := sessions[token]
		sessionsMutex.RUnlock()

		if !exists {
			logDebug(r.Host, r.URL.Path, r.Method, 401, r.RemoteAddr,
				fmt.Sprintf("%v", r.Header), "requireAuth", "Invalid session token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check that user is not deleted
		usersMutex.RLock()
		user, userExists := users[username]
		usersMutex.RUnlock()

		if !userExists || user.IsDeleted {
			logDebug(r.Host, r.URL.Path, r.Method, 401, r.RemoteAddr,
				fmt.Sprintf("%v", r.Header), "requireAuth", "User is deleted")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Create new request with username in header
		r.Header.Set("X-Username", username)
		handler(w, r)
	}
}

// handleRegister handles user registration
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		logDebug(r.Host, r.URL.Path, r.Method, 405, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleRegister", "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logDebug(r.Host, r.URL.Path, r.Method, 400, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleRegister", "Invalid JSON")
		http.Error(w, "Invalid JSON", 400)
		return
	}

	if req.Username == "" || req.Password == "" {
		logDebug(r.Host, r.URL.Path, r.Method, 400, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleRegister", "Empty username or password")
		http.Error(w, "Username and password are required", 400)
		return
	}

	usersMutex.Lock()
	defer usersMutex.Unlock()

	if _, exists := users[req.Username]; exists {
		logDebug(r.Host, r.URL.Path, r.Method, 400, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleRegister", fmt.Sprintf("Username '%s' already exists", req.Username))
		http.Error(w, "Username already exists", 400)
		return
	}

	users[req.Username] = &User{
		Username:  req.Username,
		Password:  req.Password,
		IsDeleted: false,
	}

	logDebug(r.Host, r.URL.Path, r.Method, 200, r.RemoteAddr,
		fmt.Sprintf("%v", r.Header), "handleRegister", fmt.Sprintf("New user registration attempt for username '%s'", req.Username))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// handleLogin handles user authentication
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		logDebug(r.Host, r.URL.Path, r.Method, 405, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleLogin", "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logDebug(r.Host, r.URL.Path, r.Method, 400, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleLogin", "Invalid JSON")
		http.Error(w, "Invalid JSON", 400)
		return
	}

	usersMutex.RLock()
	user, exists := users[req.Username]
	usersMutex.RUnlock()

	if exists && !user.IsDeleted && user.Password == req.Password {
		token := generateToken()

		sessionsMutex.Lock()
		sessions[token] = req.Username
		sessionsMutex.Unlock()

		logDebug(r.Host, r.URL.Path, r.Method, 200, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleLogin", fmt.Sprintf("User '%s' attempted authentication. Success: true", req.Username))

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
		return
	}

	logDebug(r.Host, r.URL.Path, r.Method, 401, r.RemoteAddr,
		fmt.Sprintf("%v", r.Header), "handleLogin", fmt.Sprintf("User '%s' attempted authentication. Success: false", req.Username))

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// handleProfile handles getting and deleting profile
func handleProfile(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")

	switch r.Method {
	case "GET":
		usersMutex.RLock()
		user, exists := users[username]
		usersMutex.RUnlock()

		if !exists || user.IsDeleted {
			logDebug(r.Host, r.URL.Path, r.Method, 404, r.RemoteAddr,
				fmt.Sprintf("%v", r.Header), "handleProfile", fmt.Sprintf("User '%s' requested profile of user '%s'", username, username))
			http.Error(w, "User not found", 404)
			return
		}

		profile := map[string]interface{}{
			"username":  user.Username,
			"isDeleted": user.IsDeleted,
		}

		logDebug(r.Host, r.URL.Path, r.Method, 200, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleProfile", fmt.Sprintf("User '%s' requested profile of user '%s'", username, username))

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(profile)

	case "DELETE":
		usersMutex.Lock()
		user, exists := users[username]
		if exists {
			user.IsDeleted = true
			user.Password = ""
		}
		usersMutex.Unlock()

		// Invalidate all sessions for this user
		sessionsMutex.Lock()
		for token, user := range sessions {
			if user == username {
				delete(sessions, token)
			}
		}
		sessionsMutex.Unlock()

		logDebug(r.Host, r.URL.Path, r.Method, 200, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleProfile", fmt.Sprintf("User '%s' deleted their profile", username))

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"message": "Profile deleted successfully"})

	default:
		logDebug(r.Host, r.URL.Path, r.Method, 405, r.RemoteAddr,
			fmt.Sprintf("%v", r.Header), "handleProfile", "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleWebSocket handles WebSocket connections for chat
func handleWebSocket(ws *websocket.Conn) {
	defer ws.Close()

	connectionsMutex.Lock()
	connections[ws] = true
	connectionsMutex.Unlock()

	logDebug(ws.Request().Host, "/messages", "GET", 101, ws.Request().RemoteAddr,
		fmt.Sprintf("%v", ws.Request().Header), "handleWebSocket", "New WebSocket connection established")

	// Send last 10 messages to new client
	messagesMutex.RLock()
	var recentMessages []Message
	if len(messages) > 10 {
		recentMessages = messages[len(messages)-10:]
	} else {
		recentMessages = messages
	}
	messagesMutex.RUnlock()

	// Replace names of deleted users
	for i := range recentMessages {
		usersMutex.RLock()
		user, exists := users[recentMessages[i].Username]
		if exists && user.IsDeleted {
			recentMessages[i].Username = "<deleted>"
		}
		usersMutex.RUnlock()
	}

	websocket.JSON.Send(ws, WebSocketMessage{
		Type:     "history",
		Messages: recentMessages,
	})

	// Process incoming messages
	for {
		var msg WebSocketMessage
		if err := websocket.JSON.Receive(ws, &msg); err != nil {
			break
		}

		if msg.Type == "message" && msg.Text != "" {
			// Get username from token (simplified version)
			// In real application, token should be passed through WebSocket
			username := "anonymous" // For demonstration

			messageIDMutex.Lock()
			messageID++
			newMessage := Message{
				ID:       messageID,
				Username: username,
				Text:     msg.Text,
				Time:     time.Now(),
			}
			messageIDMutex.Unlock()

			messagesMutex.Lock()
			messages = append(messages, newMessage)
			messagesMutex.Unlock()

			// Replace name of deleted user
			displayMessage := newMessage
			usersMutex.RLock()
			user, exists := users[displayMessage.Username]
			if exists && user.IsDeleted {
				displayMessage.Username = "<deleted>"
			}
			usersMutex.RUnlock()

			logDebug(ws.Request().Host, "/messages", "WebSocket", 200, ws.Request().RemoteAddr,
				fmt.Sprintf("%v", ws.Request().Header), "handleWebSocket", fmt.Sprintf("User '%s' sent a message: '%s'", username, msg.Text))

			// Broadcast message to all connected clients
			connectionsMutex.RLock()
			clientCount := len(connections)
			connectionsMutex.RUnlock()

			connectionsMutex.RLock()
			for conn := range connections {
				if err := websocket.JSON.Send(conn, WebSocketMessage{
					Type:     "message",
					Username: displayMessage.Username,
					Text:     displayMessage.Text,
				}); err != nil {
					delete(connections, conn)
					conn.Close()
				}
			}
			connectionsMutex.RUnlock()

			logDebug(ws.Request().Host, "/messages", "WebSocket", 200, ws.Request().RemoteAddr,
				fmt.Sprintf("%v", ws.Request().Header), "handleWebSocket", fmt.Sprintf("Broadcasting message to %d clients", clientCount))
		}
	}

	connectionsMutex.Lock()
	delete(connections, ws)
	connectionsMutex.Unlock()
}

// handleDebug displays the debug page
func handleDebug(w http.ResponseWriter, r *http.Request) {
	debugMutex.RLock()
	logEntries := make([]DebugLogEntry, len(debugLog))
	copy(logEntries, debugLog)
	debugMutex.RUnlock()

	// Reverse order so new entries are on top
	for i, j := 0, len(logEntries)-1; i < j; i, j = i+1, j-1 {
		logEntries[i], logEntries[j] = logEntries[j], logEntries[i]
	}

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HTTP Inspector - Debug Log</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .stats { display: flex; justify-content: space-around; margin-bottom: 30px; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        .stat { text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #007bff; }
        .stat-label { color: #666; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .status-200 { color: #28a745; font-weight: bold; }
        .status-400 { color: #ffc107; font-weight: bold; }
        .status-401 { color: #dc3545; font-weight: bold; }
        .status-403 { color: #dc3545; font-weight: bold; }
        .status-404 { color: #6c757d; font-weight: bold; }
        .status-405 { color: #fd7e14; font-weight: bold; }
        .status-101 { color: #17a2b8; font-weight: bold; }
        .timestamp { white-space: nowrap; }
        .info { max-width: 300px; word-wrap: break-word; }
        .headers { max-width: 200px; word-wrap: break-word; font-family: monospace; font-size: 10px; }
        .auto-refresh { position: fixed; top: 10px; right: 10px; background: #007bff; color: white; padding: 10px; border-radius: 5px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="auto-refresh">Auto-refresh: 2s</div>
    <div class="container">
        <h1>🔍 HTTP Inspector - Debug Log</h1>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{{len .LogEntries}}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat">
                <div class="stat-number">{{.UserCount}}</div>
                <div class="stat-label">Registered Users</div>
            </div>
            <div class="stat">
                <div class="stat-number">{{.SessionCount}}</div>
                <div class="stat-label">Active Sessions</div>
            </div>
            <div class="stat">
                <div class="stat-number">{{.MessageCount}}</div>
                <div class="stat-label">Chat Messages</div>
            </div>
            <div class="stat">
                <div class="stat-number">{{.WebSocketCount}}</div>
                <div class="stat-label">WebSocket Connections</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Host</th>
                    <th>Path</th>
                    <th>Method</th>
                    <th>Status</th>
                    <th>Remote Addr</th>
                    <th>Headers</th>
                    <th>Handler Function</th>
                    <th>Internal Info</th>
                </tr>
            </thead>
            <tbody>
                {{range .LogEntries}}
                <tr>
                    <td class="timestamp">{{.Timestamp.Format "15:04:05.000"}}</td>
                    <td>{{.Host}}</td>
                    <td>{{.Path}}</td>
                    <td>{{.Method}}</td>
                    <td class="status-{{.Code}}">{{.Code}}</td>
                    <td>{{.RemoteAddr}}</td>
                    <td class="headers">{{.Headers}}</td>
                    <td>{{.HandlerFunc}}</td>
                    <td class="info">{{.Info}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`

	t, err := template.New("debug").Parse(tmpl)
	if err != nil {
		http.Error(w, "Template error", 500)
		return
	}

	// Collect statistics
	usersMutex.RLock()
	userCount := len(users)
	usersMutex.RUnlock()

	sessionsMutex.RLock()
	sessionCount := len(sessions)
	sessionsMutex.RUnlock()

	messagesMutex.RLock()
	messageCount := len(messages)
	messagesMutex.RUnlock()

	connectionsMutex.RLock()
	wsCount := len(connections)
	connectionsMutex.RUnlock()

	data := struct {
		LogEntries     []DebugLogEntry
		UserCount      int
		SessionCount   int
		MessageCount   int
		WebSocketCount int
	}{
		LogEntries:     logEntries,
		UserCount:      userCount,
		SessionCount:   sessionCount,
		MessageCount:   messageCount,
		WebSocketCount: wsCount,
	}

	logDebug(r.Host, r.URL.Path, r.Method, 200, r.RemoteAddr,
		fmt.Sprintf("%v", r.Header), "handleDebug", "Debug page accessed")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

// handleHome displays the home page
func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HTTP Inspector - Home</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .section h2 { color: #007bff; margin-top: 0; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .result { margin-top: 15px; padding: 10px; border-radius: 4px; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .links { text-align: center; margin: 30px 0; }
        .links a { margin: 0 15px; color: #007bff; text-decoration: none; }
        .links a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 HTTP Inspector</h1>
        <p style="text-align: center; color: #666;">Educational web server for learning HTTP protocol</p>
        
        <div class="links">
            <a href="/debug">📊 Debug Log</a>
            <a href="/messages">💬 Chat</a>
        </div>

        <div class="section">
            <h2>📝 Registration</h2>
            <div class="form-group">
                <label for="reg-username">Username:</label>
                <input type="text" id="reg-username" placeholder="Enter username">
            </div>
            <div class="form-group">
                <label for="reg-password">Password:</label>
                <input type="password" id="reg-password" placeholder="Enter password">
            </div>
            <button onclick="register()">Register</button>
            <div id="reg-result"></div>
        </div>

        <div class="section">
            <h2>🔐 Login</h2>
            <div class="form-group">
                <label for="login-username">Username:</label>
                <input type="text" id="login-username" placeholder="Enter username">
            </div>
            <div class="form-group">
                <label for="login-password">Password:</label>
                <input type="password" id="login-password" placeholder="Enter password">
            </div>
            <button onclick="login()">Login</button>
            <div id="login-result"></div>
        </div>

        <div class="section">
            <h2>👤 Profile</h2>
            <div class="form-group">
                <label for="profile-token">Token:</label>
                <input type="text" id="profile-token" placeholder="Enter token from login">
            </div>
            <button onclick="getProfile()">Get Profile</button>
            <button onclick="deleteProfile()">Delete Profile</button>
            <div id="profile-result"></div>
        </div>
    </div>

    <script>
        let currentToken = '';

        async function register() {
            const username = document.getElementById('reg-username').value;
            const password = document.getElementById('reg-password').value;
            const result = document.getElementById('reg-result');

            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();
                
                if (response.ok) {
                    result.innerHTML = '<div class="result success">✅ ' + data.message + '</div>';
                } else {
                    result.innerHTML = '<div class="result error">❌ ' + data.error + '</div>';
                }
            } catch (error) {
                result.innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
            }
        }

        async function login() {
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            const result = document.getElementById('login-result');

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json();
                
                if (response.ok) {
                    currentToken = data.token;
                    document.getElementById('profile-token').value = currentToken;
                    result.innerHTML = '<div class="result success">✅ Login successful! Token: ' + currentToken + '</div>';
                } else {
                    result.innerHTML = '<div class="result error">❌ ' + data.error + '</div>';
                }
            } catch (error) {
                result.innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
            }
        }

        async function getProfile() {
            const token = document.getElementById('profile-token').value;
            const result = document.getElementById('profile-result');

            if (!token) {
                result.innerHTML = '<div class="result error">❌ Enter token</div>';
                return;
            }

            try {
                const response = await fetch('/profile', {
                    method: 'GET',
                    headers: { 'Authorization': 'Bearer ' + token }
                });

                const data = await response.json();
                
                if (response.ok) {
                    result.innerHTML = '<div class="result success">✅ Profile: ' + JSON.stringify(data) + '</div>';
                } else {
                    result.innerHTML = '<div class="result error">❌ ' + data.error + '</div>';
                }
            } catch (error) {
                result.innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
            }
        }

        async function deleteProfile() {
            const token = document.getElementById('profile-token').value;
            const result = document.getElementById('profile-result');

            if (!token) {
                result.innerHTML = '<div class="result error">❌ Enter token</div>';
                return;
            }

            try {
                const response = await fetch('/profile', {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + token }
                });

                const data = await response.json();
                
                if (response.ok) {
                    result.innerHTML = '<div class="result success">✅ ' + data.message + '</div>';
                    document.getElementById('profile-token').value = '';
                    currentToken = '';
                } else {
                    result.innerHTML = '<div class="result error">❌ ' + data.error + '</div>';
                }
            } catch (error) {
                result.innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
            }
        }
    </script>
</body>
</html>`

	logDebug(r.Host, r.URL.Path, r.Method, 200, r.RemoteAddr,
		fmt.Sprintf("%v", r.Header), "handleHome", "Home page accessed")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleMessages displays the chat page
func handleMessages(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HTTP Inspector - Chat</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .chat-container { border: 1px solid #ddd; border-radius: 8px; height: 400px; overflow-y: auto; padding: 15px; margin: 20px 0; background: #fafafa; }
        .message { margin: 10px 0; padding: 8px; border-radius: 8px; }
        .message.own { background: #007bff; color: white; margin-left: 20%; }
        .message.other { background: #e9ecef; color: #333; margin-right: 20%; }
        .message.deleted { background: #dc3545; color: white; }
        .message-header { font-size: 12px; opacity: 0.7; margin-bottom: 5px; }
        .message-text { word-wrap: break-word; }
        .input-container { display: flex; gap: 10px; }
        input[type="text"] { flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
        .status { margin: 10px 0; padding: 10px; border-radius: 4px; }
        .status.connected { background: #d4edda; color: #155724; }
        .status.disconnected { background: #f8d7da; color: #721c24; }
        .back-link { text-align: center; margin: 20px 0; }
        .back-link a { color: #007bff; text-decoration: none; }
        .back-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>💬 HTTP Inspector - Chat</h1>
        
        <div class="back-link">
            <a href="/">← Back to Home</a> | 
            <a href="/debug">📊 Debug Log</a>
        </div>

        <div id="status" class="status disconnected">❌ Not connected to WebSocket</div>
        
        <div id="chat" class="chat-container"></div>
        
        <div class="input-container">
            <input type="text" id="messageInput" placeholder="Enter message..." disabled>
            <button id="sendButton" onclick="sendMessage()" disabled>Send</button>
        </div>
    </div>

    <script>
        let ws = null;
        let isConnected = false;

        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/ws';
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                isConnected = true;
                updateStatus('✅ Connected to WebSocket', 'connected');
                document.getElementById('messageInput').disabled = false;
                document.getElementById('sendButton').disabled = false;
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === 'history') {
                    // Show message history
                    data.messages.forEach(msg => addMessage(msg.username, msg.text, msg.time, false));
                } else if (data.type === 'message') {
                    // Show new message
                    addMessage(data.username, data.text, new Date(), false);
                }
            };
            
            ws.onclose = function() {
                isConnected = false;
                updateStatus('❌ Connection closed', 'disconnected');
                document.getElementById('messageInput').disabled = true;
                document.getElementById('sendButton').disabled = true;
            };
            
            ws.onerror = function() {
                updateStatus('❌ WebSocket error', 'disconnected');
            };
        }

        function updateStatus(message, className) {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status ' + className;
        }

        function addMessage(username, text, time, isOwn) {
            const chat = document.getElementById('chat');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            
            if (username === '<deleted>') {
                messageDiv.className += ' deleted';
            } else if (isOwn) {
                messageDiv.className += ' own';
            } else {
                messageDiv.className += ' other';
            }
            
            const timeStr = new Date(time).toLocaleTimeString();
            messageDiv.innerHTML = 
                '<div class="message-header">' + username + ' • ' + timeStr + '</div>' +
                '<div class="message-text">' + text + '</div>';
            
            chat.appendChild(messageDiv);
            chat.scrollTop = chat.scrollHeight;
        }

        function sendMessage() {
            const input = document.getElementById('messageInput');
            const text = input.value.trim();
            
            if (text && ws && isConnected) {
                ws.send(JSON.stringify({
                    type: 'message',
                    text: text
                }));
                input.value = '';
            }
        }

        // Connect on page load
        connect();

        // Handle Enter key in input field
        document.getElementById('messageInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>`

	logDebug(r.Host, r.URL.Path, r.Method, 200, r.RemoteAddr,
		fmt.Sprintf("%v", r.Header), "handleMessages", "Chat page accessed")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func main() {
	// Start goroutine for log collection
	go collectDebugLogs()

	// Register HTTP handlers
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/profile", requireAuth(handleProfile))
	http.HandleFunc("/debug", handleDebug)
	http.HandleFunc("/messages", handleMessages)

	// WebSocket handler
	http.Handle("/ws", websocket.Handler(handleWebSocket))

	fmt.Println("🚀 HTTP Inspector started on http://localhost:8080")
	fmt.Println("📊 Debug Log: http://localhost:8080/debug")
	fmt.Println("💬 Chat: http://localhost:8080/messages")
	fmt.Println("🏠 Home: http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
