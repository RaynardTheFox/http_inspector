# 🔍 HTTP Inspector - Educational Web Server

**HTTP Inspector** is a transparent, simple and visual web server built in pure Go that visualizes its internal work in real-time through a special `/debug` endpoint. The project is created for learning HTTP protocol, WebSocket connections and internal web server operations.

## 🎯 Project Goal

Create an educational tool that allows you to "look under the hood" of a web server and see:
- How HTTP requests are processed
- How authentication and authorization work
- How WebSocket connections function
- How the server maintains internal operation logs

## 🚀 Quick Start

### Requirements
- Go 1.21 or higher
- Browser with WebSocket support

### Installation and Launch

1. **Clone the repository:**
```bash
git clone <repository-url>
cd http_inspector
```

2. **Install dependencies:**
```bash
go mod tidy
```

3. **Start the server:**
```bash
go run main.go
```

4. **Open in browser:**
- Home page: http://localhost:8080
- Debug Log: http://localhost:8080/debug
- Chat: http://localhost:8080/messages

## 📋 Functionality

### 🔐 Authentication System

#### POST /register - User Registration
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass"}'
```

**Logic:**
- Checks username uniqueness
- Saves user in memory (password NOT hashed for clarity!)
- Returns 200 OK on success or 400 Bad Request on error

#### POST /login - Authentication
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass"}'
```

**Logic:**
- Finds user by username
- Compares password in plain text (only for educational purposes!)
- Generates session token and saves in memory
- Returns token on success or 401 Unauthorized

#### GET /profile - Get Profile
```bash
curl -X GET http://localhost:8080/profile \
  -H "Authorization: Bearer <your-token>"
```

**Logic:**
- Checks token validity
- Finds user by token
- Returns user information (without password)

#### DELETE /profile - Delete Profile
```bash
curl -X DELETE http://localhost:8080/profile \
  -H "Authorization: Bearer <your-token>"
```

**Logic:**
- Authentication by token
- Sets flag `isDeleted: true`
- Clears `Password` field
- Invalidates all user sessions

### 💬 WebSocket Chat

#### GET /messages - WebSocket Connection
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');
```

**Functionality:**
- Upgrade HTTP connection to WebSocket
- Send last 10 messages to new client
- Process new messages from clients
- Broadcast messages to all connected clients
- Display deleted users as `<deleted>`

### 📊 Debug System

#### GET /debug - Server Operation Log
Open in browser: http://localhost:8080/debug

**Displayed Information:**
- **Timestamp**: Event time
- **Host**: Target request host
- **Path**: Requested path
- **Method**: HTTP method
- **Status Code**: Response code
- **Remote Addr**: Client IP address
- **Headers**: Request headers
- **Handler Function**: Called handler function
- **Internal Info**: Internal operation information

**Real-time Statistics:**
- Total number of requests
- Number of registered users
- Number of active sessions
- Number of chat messages
- Number of WebSocket connections

## 🏗️ Architecture

### Data Structures

```go
// User in the system
type User struct {
    Username  string
    Password  string // NOT HASHED (for demo purposes only!)
    IsDeleted bool
}

// Chat message
type Message struct {
    ID       int
    Username string
    Text     string
    Time     time.Time
}

// Debug log entry
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
```

### Global Variables

```go
var (
    users       = make(map[string]*User)           // Users
    sessions    = make(map[string]string)          // Sessions [token] = username
    messages    []Message                          // Chat messages
    debugLog    []DebugLogEntry                    // Debug log
    connections = make(map[*websocket.Conn]bool)   // WebSocket connections
    
    // Mutexes for thread safety
    usersMutex       = &sync.RWMutex{}
    sessionsMutex    = &sync.RWMutex{}
    messagesMutex    = &sync.RWMutex{}
    debugMutex       = &sync.RWMutex{}
    connectionsMutex = &sync.RWMutex{}
)
```

### Logging System

1. **Channel for log collection:**
```go
debugChan = make(chan DebugLogEntry, 100)
```

2. **Goroutine for log processing:**
```go
func collectDebugLogs() {
    for entry := range debugChan {
        debugMutex.Lock()
        debugLog = append(debugLog, entry)
        if len(debugLog) > 100 {
            debugLog = debugLog[1:] // Keep only last 100 entries
        }
        debugMutex.Unlock()
    }
}
```

3. **Logging function:**
```go
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
```

## 🔧 Technical Details

### Thread Safety
All operations with global variables are protected by mutexes:
- `usersMutex` - for user operations
- `sessionsMutex` - for session operations
- `messagesMutex` - for message operations
- `debugMutex` - for log operations
- `connectionsMutex` - for WebSocket connection operations

### Authentication
The `requireAuth` function checks the token from the `Authorization: Bearer <token>` header:
1. Extracts token from header
2. Checks its existence in sessions map
3. Checks that user is not deleted
4. Adds username to request context

### WebSocket Processing
1. When connecting, client is added to connections map
2. History of last 10 messages is sent
3. When receiving a new message:
   - Sender's session is checked
   - Message is saved to common slice
   - Broadcasted to all connected clients
   - Deleted users are displayed as `<deleted>`

## 📖 Usage Instructions

### 1. Studying HTTP Requests

1. Open http://localhost:8080/debug in one browser window
2. Open http://localhost:8080 in another window
3. Perform various operations (registration, login, get profile)
4. Watch in real-time how requests are processed in the debug log

### 2. Testing Authentication

1. **Registration:**
   - Enter username and password
   - Click "Register"
   - In debug log you'll see: "New user registration attempt for username 'X'"

2. **Login:**
   - Enter the same data
   - Click "Login"
   - Get token
   - In debug log you'll see: "User 'X' attempted authentication. Success: true"

3. **Get Profile:**
   - Insert token in "Token" field
   - Click "Get Profile"
   - In debug log you'll see: "User 'X' requested profile of user 'X'"

4. **Delete Profile:**
   - Click "Delete Profile"
   - Try to get profile again - you'll get an error

### 3. Testing WebSocket

1. Open http://localhost:8080/messages
2. Enter a message and send it
3. In debug log you'll see:
   - "New WebSocket connection established"
   - "User 'X' sent a message: 'Y'"
   - "Broadcasting message to N clients"

### 4. Analyzing Debug Log

Debug log shows:
- **Event time** - exact time of request processing
- **Method and path** - which HTTP method and to which path
- **Status code** - processing result (200, 400, 401, etc.)
- **IP address** - where the request came from
- **Headers** - all HTTP request headers
- **Handler** - which function processed the request
- **Internal information** - what exactly happened inside the server

## ⚠️ Important Notes

### Security
⚠️ **WARNING**: This project is created exclusively for educational purposes!

- Passwords are stored in plain text (in real projects this is NOT ALLOWED!)
- Session tokens are generated in a simple way
- No protection against CSRF attacks
- No input validation
- No rate limiting

### Performance
- All data is stored in memory (disappears on restart)
- No persistent storage
- No optimization for high loads
- WebSocket connections don't scale

### Limitations
- Maximum 100 entries in debug log
- Simple authentication without refresh tokens
- WebSocket doesn't support token authentication
- No network error handling

## 🎓 Educational Value

This project helps understand:

1. **HTTP Protocol:**
   - How HTTP methods work (GET, POST, DELETE)
   - How headers and request body are transmitted
   - How HTTP responses are formed

2. **Authentication and Authorization:**
   - Token working principles
   - Access rights checking
   - Session management

3. **WebSocket:**
   - HTTP connection upgrade
   - Real-time bidirectional communication
   - Multiple connection management

4. **Server Internal Work:**
   - Request processing
   - Operation logging
   - Thread safety

5. **Go Programming:**
   - HTTP server in Go
   - Working with goroutines and channels
   - Using mutexes
   - JSON serialization/deserialization

## 🔍 Usage Examples

### Testing with curl

```bash
# Registration
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret123"}'

# Login
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret123"}'

# Get profile (replace TOKEN with received token)
curl -X GET http://localhost:8080/profile \
  -H "Authorization: Bearer TOKEN"

# Delete profile
curl -X DELETE http://localhost:8080/profile \
  -H "Authorization: Bearer TOKEN"
```

### Testing WebSocket with JavaScript

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('Connected to WebSocket');
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};

ws.onclose = function() {
    console.log('WebSocket connection closed');
};

// Send message
ws.send(JSON.stringify({
    type: 'message',
    text: 'Hello, WebSocket!'
}));
```

## 📚 Additional Resources

- (https://golang.org/pkg/net/http/)
- (https://tools.ietf.org/html/rfc6455)
- (https://golang.org/x/net/websocket)
- (https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
