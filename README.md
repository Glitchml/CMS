# Conference Management System Backend

This project is a backend implementation for a Conference Management System using Flask. It provides various features for managing user authentication, sessions, user profiles, networking, analytics, and more.


## Features

- **User Authentication**: Registration and login functionality with JWT token generation.
- **Session Management**: CRUD operations for managing conference sessions.
- **User Profiles**: Endpoints for retrieving and updating user information.
- **Networking**: Features for managing user connections and direct messaging.
- **Analytics**: Collection and reporting of user engagement and session attendance data.
- **Real-time Features**: WebSocket support for live interactions during sessions.
- **Database Configuration**: SQLAlchemy ORM with Alembic for database migrations.
- **File Uploads**: Image upload support using Pillow library.

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd conference-management-system
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the root directory with the following contents:
   ```
   FLASK_APP=src/app.py
   FLASK_ENV=development
   DATABASE_URI=sqlite:///conference.db
   JWT_SECRET_KEY=your_secret_key_here
   SECRET_KEY=another_secret_key_here
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
