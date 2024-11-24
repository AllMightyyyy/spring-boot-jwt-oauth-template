
# Spring OAuth2 JWT Template

A ready-to-use Spring Boot template for implementing OAuth2 with JWT tokens, providing a solid foundation for secure authentication and authorization in web applications.

## Features

- **OAuth2 Integration**: Support for OAuth2 authentication with Google.
- **JWT Token Handling**: Generate and validate JWT access and refresh tokens.
- **User Management**: User registration, login, password reset, and account verification.
- **Role-Based Access Control**: Secure endpoints with role-based permissions.
- **Redis Integration**: Store temporary tokens and session data using Redis.
- **Email Notifications**: Send verification and password reset emails.
- **API Documentation**: Swagger/OpenAPI integration for API documentation.
- **Testing**: Comprehensive unit and integration tests.

- # **Why Did i create this ? **:
  - basically there isn't an example that is like a plug in easy setup project, so i m creating this to help startup my projects easily and just expand on them

## Technologies Used

- **Spring Boot**
- **Spring Security**
- **OAuth2**
- **JWT (JSON Web Tokens)**
- **Spring Data JPA**
- **MySQL**
- **Redis**
- **Lombok**
- **Swagger/OpenAPI**
- **JUnit & Mockito**

## Getting Started

### Prerequisites

- Java 17+
- Maven
- MySQL Database
- Redis Server

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/AllMightyyyy/spring-boot-jwt-oauth-template.git
   cd spring-boot-jwt-oauth-template
   ```

2. **Set Up Environment Variables:**

   Create a `.env` file in the root directory based on the provided `.env.example`.

   ```env
   # Application settings
   APPLICATION_NAME=groupgrubbnd
   SERVER_PORT=8081

   # Database configuration
   DB_URL=jdbc:mysql://localhost:3306/groupgrubdb?useSSL=false&serverTimezone=UTC
   DB_USERNAME=root
   DB_PASSWORD=your_db_password

   # Redis configuration
   REDIS_PORT=6379
   REDIS_HOST=localhost

   # Email configuration
   MAIL_HOST=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_email_password

   # Google OAuth2 configuration
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   GOOGLE_AUTH_URI=https://accounts.google.com/o/oauth2/v2/auth
   GOOGLE_REDIRECT_URI=http://localhost:8081/oauth2/callback/google
   GOOGLE_TOKEN_URI=https://oauth2.googleapis.com/token
   GOOGLE_USER_INFO_URI=https://www.googleapis.com/oauth2/v2/userinfo
   GOOGLE_USER_NAME_ATTRIBUTE=email

   # JWT configuration
   JWT_SECRET=your_jwt_secret
   JWT_EXPIRATION=3600000
   JWT_REFRESH_EXPIRATION=86400000

   # Logging configuration
   LOGGING_SECURITY_LEVEL=DEBUG
   LOGGING_APP_LEVEL=DEBUG
   ```

   **Important:** Replace placeholder values with your actual configurations. Ensure that `.env` is listed in `.gitignore` to prevent secrets from being committed.

3. **Build and Run the Application:**

   ```bash
   ./mvnw clean install
   ./mvnw spring-boot:run
   ```

   Alternatively, use your IDE to run the `GroupgrubbndApplication` class.

### Usage

#### **API Endpoints**

- **Authentication:**
  - `POST /api/auth/register` - Register a new user.
  - `POST /api/auth/login` - Login and receive JWT tokens.
  - `POST /api/auth/refresh` - Refresh access token using a refresh token.
  - `POST /api/auth/logout` - Logout the user by invalidating tokens.
  - `GET /api/auth/verify` - Verify user account using a token.
  - `POST /api/auth/set-password` - Set a new password using a token.
  - `POST /api/auth/reset-password/request` - Initiate password reset.
  - `POST /api/auth/reset-password/confirm` - Confirm password reset.
  - `POST /api/auth/resend-verification-email` - Resend account verification email.
  - 
- `localhost:8081/oauth2/authorization/google` -> this starts the OAuth2 flow

- **User Management:**
  - `GET /api/users/{id}` - Get user details (secured, users can only access their own data).

#### **Testing the APIs**

Use tools like [Postman](https://www.postman.com/) or [cURL](https://curl.se/) to interact with the APIs.

#### **Swagger/OpenAPI Documentation**

Access the API documentation at: `http://localhost:8081/swagger-ui/index.html`

### Contributing

Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### License

This project is licensed under the [MIT License](LICENSE).

### Contact

For any inquiries or support, please contact [zakariafarih142@gmail.com](mailto:your_email@example.com).
