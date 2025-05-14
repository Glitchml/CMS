
Existing endpoints
Collecting workspace informationBased on your codebase, here's a simple description of your Flask-based Conference Management System backend:

1. **Core Features**:
- User authentication with login/signup
- Profile management
- Session handling for conferences
- Networking features for connecting users
- Analytics tracking

2. **Main Components**:
- app.py - Main application with routes and core logic
- user.py - User model for database
- config.py - Configuration settings

3. **Key Functionality**:
- JWT (JSON Web Token) authentication
- SQLite database using SQLAlchemy
- Protected routes requiring authentication
- Cookie-based session management
- CORS support for cross-origin requests

4. **API Endpoints**:
Currently implemented:
- `/api/auth/register` - Create new user account
- `/api/auth/login` - User login
- `/api/auth/logout` - User logout
- `/api/protected` - Test protected route

Planned (from comments):
- `/api/sessions` - Conference session management
- `/api/network` - User networking features
- `/api/profile` - User profile operations

The backend is built to support a conference management interface with real-time features via WebSocket support and secure user authentication.


# Dashboard Page

### ✅ Backend Endpoints Defined

| Feature                   | HTTP Method | Endpoint                         |
| ------------------------- | ----------- | -------------------------------- |
| Get User Profile          | GET         | `/api/user/{userId}`             |
| Get All Sessions          | GET         | `/api/sessions`                  |
| Get Specific Session      | GET         | `/api/sessions/{sessionId}`      |
| Join a Session            | POST        | `/api/sessions/{sessionId}/join` |
| Real-time Session Updates | WS          | `/ws/sessions`                   |

# Profile Page

### ✅ Backend Endpoints Defined

| Feature             | HTTP Method | Endpoint                |
| ------------------- | ----------- | ----------------------- |
| Get User Profile    | GET         | `/api/profile/{userId}` |
| Update User Profile | PUT         | `/api/profile/{userId}` |
| Upload Avatar       | POST        | `/api/profile/avatar`   |
| Get User Sessions   | GET         | `/api/profile/sessions` |
| Get User Statistics | GET         | `/api/profile/stats`    |

# Clicked-Profile Page

### ✅ Backend Endpoints Defined

| Feature             | HTTP Method | Endpoint                |
| ------------------- | ----------- | ----------------------- |
| Get User Profile    | GET         | `/api/profile/{userId}` |
| Get User Statistics | GET         | `/api/profile/stats`    |
| Get Session History | GET         | `/api/profile/sessions` |


# Networking Page

### ✅ Backend Endpoints Defined

| Feature                 | HTTP Method | Endpoint                           |
| ----------------------- | ----------- | ---------------------------------- |
| Get All Users           | GET         | `/api/network/users`               |
| Get Connection Requests | GET         | `/api/network/requests`            |
| Get Blocked Users       | GET         | `/api/network/blocked`             |
| Send Connection Request | POST        | `/api/network/connect/{userId}`    |
| Accept Connection       | POST        | `/api/network/accept/{requestId}`  |
| Decline Connection      | POST        | `/api/network/decline/{requestId}` |
| Block User              | POST        | `/api/network/block/{userId}`      |
| Unblock User            | DELETE      | `/api/network/unblock/{userId}`    |
| Search Users            | GET         | `/api/network/search?q={query}`    |




# Sessions Page

### ✅ Backend Endpoints Defined

| Feature                | HTTP Method | Endpoint                    |
| ---------------------- | ----------- | --------------------------- |
| Create Session         | POST        | `/api/sessions`             |
| Fetch Sessions         | GET         | `/api/sessions?search=...`  |
| Schedule Session       | POST        | `/api/sessions/schedule`    |
| Get Users              | GET         | `/api/users?search=...`     |
| Assign User To Session | POST        | `/api/sessions/assign-role` |

# Active Sessions Page


### ✅ Backend Endpoints Defined

| Feature                      | HTTP Method | Endpoint                         |
|-----------------------------|-------------|----------------------------------|
| Submit a Question           | POST        | `/api/session/question`          |
| Leave Session               | POST        | `/api/session/leave`             |
| Get Session Details         | GET         | `/api/session/{sessionId}`       |
| Real-time Session Updates   | WS          | `/ws/session/{sessionId}`        |


# Settings Page

### ✅ Backend Endpoints Defined

| Feature                 | HTTP Method | Endpoint                      |     |
| ----------------------- | ----------- | ----------------------------- | --- |
| Get User Settings       | GET         | `/api/settings/{userId}`      |     |
| Update Profile          | PUT         | `/api/settings/profile`       |     |
| Change Password         | PUT         | `/api/settings/password`      |     |
| Update Notifications    | PUT         | `/api/settings/notifications` |     |
| Update Theme Preference | PUT         | `/api/settings/theme`         |     |
| Sign Out                | POST        | `/api/auth/signout`           |     |


Don't forget to create the uploads directory when deploying:
```bash
mkdir -p instance/uploads
chmod 755 instance/uploads
```

