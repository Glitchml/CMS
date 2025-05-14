# Conference Management System Backend

This project is a backend implementation for a Conference Management System using Flask. It provides various features for managing user authentication, sessions, user profiles, networking, analytics, and more.

## Project Structure

```
conference-management-system
├── src
│   ├── api
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── sessions.py
│   │   ├── users.py
│   │   ├── connections.py
│   │   └── analytics.py
│   ├── models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── session.py
│   │   └── connection.py
│   ├── services
│   │   ├── __init__.py
│   │   ├── auth_service.py
│   │   └── websocket_service.py
│   ├── utils
│   │   ├── __init__.py
│   │   └── security.py
│   ├── config.py
│   └── app.py
├── tests
│   ├── __init__.py
│   ├── test_auth.py
│   └── test_sessions.py
├── requirements.txt
└── README.md
```

## Features

- **User Authentication**: Registration and login functionality with JWT token generation.
- **Session Management**: CRUD operations for managing conference sessions.
- **User Profiles**: Endpoints for retrieving and updating user information.
- **Networking**: Features for managing user connections and direct messaging.
- **Analytics**: Collection and reporting of user engagement and session attendance data.
- **Real-time Features**: WebSocket support for live interactions during sessions.

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd conference-management-system
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the application, execute the following command:

```bash
python src/app.py
```

## Testing

To run the tests, use:

```bash
pytest
```

## License

This project is licensed under the MIT License.