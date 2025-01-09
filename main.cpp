#include "crow.h"
#include <cstdlib>
#include <fstream>
#include <string>
#include <filesystem>
#include <unistd.h>
#include <unordered_set>
#include <regex>
#include <algorithm>
#include <memory>
#include <random>
#include <chrono>
#include <optional>
#include <iomanip>
#include <jwt-cpp/jwt.h>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <bcrypt/BCrypt.hpp>
#include <laserpants/dotenv-0.9.3/dotenv.h>

// Constants
constexpr size_t MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB in bytes

// Helper functions
class FileUploadHelper {
public:
    static bool isAllowedFileType(const std::string& filename) {
        static const std::unordered_set<std::string> allowed_extensions = {
            ".jpg", ".jpeg", ".png", ".gif"
        };

        std::string ext = getFileExtension(filename);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        return allowed_extensions.find(ext) != allowed_extensions.end();
    }

    static std::string sanitizeFilename(const std::string& filename) {
        // Remove path traversal attempts and invalid characters
        std::string base = std::filesystem::path(filename).filename().string();

        // Replace potentially dangerous characters with underscores
        static const std::regex invalid_chars("[^a-zA-Z0-9._-]");
        base = std::regex_replace(base, invalid_chars, "_");

        // Ensure the filename isn't empty after sanitization
        if (base.empty() || base == "." || base == "..") {
            return "unnamed_file";
        }

        return base;
    }

    static std::string getFileExtension(const std::string& filename) {
        size_t pos = filename.find_last_of(".");
        if (pos == std::string::npos) return "";
        return filename.substr(pos);
    }

    static std::string generateUniqueFilename(const std::string& base_filename) {
        std::string dir = "uploads/";
        std::string sanitized = sanitizeFilename(base_filename);
        std::string name = sanitized;
        int counter = 1;

        while (std::filesystem::exists(dir + name)) {
            std::string ext = getFileExtension(sanitized);
            std::string base = sanitized.substr(0, sanitized.length() - ext.length());
            name = base + "_" + std::to_string(counter++) + ext;
        }

        return name;
    }
};

// Forward declarations
class DatabaseManager;
class AuthManager;
class SessionManager;

// User model
struct User {
    int id;
    std::string username;
    std::string email;
    std::string password_hash;
    std::string date_of_birth;
    std::string created_at;
};

// Database manager to handle MySQL operations
class DatabaseManager {
private:
    std::unique_ptr<sql::mysql::MySQL_Driver> driver;
    std::unique_ptr<sql::Connection> conn;

public:
    DatabaseManager(const std::string& host, const std::string& user, 
                   const std::string& password, const std::string& database) {
        try {
            driver.reset(sql::mysql::get_mysql_driver_instance());
            conn.reset(driver->connect(host, user, password));
            conn->setSchema(database);

            // Create users table if it doesn't exist
            std::unique_ptr<sql::Statement> stmt(conn->createStatement());
            stmt->execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "id INT AUTO_INCREMENT PRIMARY KEY,"
                "username VARCHAR(50) UNIQUE NOT NULL,"
                "email VARCHAR(100) UNIQUE NOT NULL,"
                "password_hash VARCHAR(255) NOT NULL,"
                "date_of_birth DATE NOT NULL,"
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                ")"
            );

            // Create sessions table if it doesn't exist
            stmt->execute(
                "CREATE TABLE IF NOT EXISTS sessions ("
                "id VARCHAR(64) PRIMARY KEY,"
                "user_id INT NOT NULL,"
                "expires_at TIMESTAMP NOT NULL,"
                "FOREIGN KEY (user_id) REFERENCES users(id)"
                ")"
            );
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error: " << e.what() << std::endl;
            throw;
        }
    }

    std::string createSession(int userId) {
        try {
            // Generate a random session ID
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 15);

            std::stringstream ss;
            for (int i = 0; i < 32; i++) {
                ss << std::hex << dis(gen);
            }
            std::string sessionId = ss.str();

            // Calculate expiration time (24 hours from now)
            auto now = std::chrono::system_clock::now();
            auto expiry = now + std::chrono::hours(24);
            auto expiry_time_t = std::chrono::system_clock::to_time_t(expiry);

            std::stringstream timeStr;
            timeStr << std::put_time(std::localtime(&expiry_time_t), "%Y-%m-%d %H:%M:%S");

            // Create the session in database
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
            ));

            stmt->setString(1, sessionId);
            stmt->setInt(2, userId);
            stmt->setString(3, timeStr.str());

            stmt->executeUpdate();

            return sessionId;
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error in createSession: " << e.what() << std::endl;
            throw;
        }
    }

    bool validateSession(const std::string& sessionId) {
        try {
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                "SELECT * FROM sessions WHERE id = ? AND expires_at > NOW()"
            ));

            stmt->setString(1, sessionId);
            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());

            return res->next();
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error in validateSession: " << e.what() << std::endl;
            return false;
        }
    }

    void deleteSession(const std::string& sessionId) {
        try {
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                "DELETE FROM sessions WHERE id = ?"
            ));

            stmt->setString(1, sessionId);
            stmt->executeUpdate();
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error in deleteSession: " << e.what() << std::endl;
        }
    }

    void cleanExpiredSessions() {
        try {
            std::unique_ptr<sql::Statement> stmt(conn->createStatement());
            stmt->execute("DELETE FROM sessions WHERE expires_at <= NOW()");
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error in cleanExpiredSessions: " << e.what() << std::endl;
        }
    }


    bool createUser(const User& user) {
        try {
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                "INSERT INTO users (username, email, password_hash, date_of_birth) "
                "VALUES (?, ?, ?, ?)"
            ));

            stmt->setString(1, user.username);
            stmt->setString(2, user.email);
            stmt->setString(3, user.password_hash);
            stmt->setString(4, user.date_of_birth);

            return stmt->executeUpdate() > 0;
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error: " << e.what() << std::endl;
            return false;
        }
    }

    std::optional<User> getUserByEmail(const std::string& email) {
        try {
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                "SELECT * FROM users WHERE email = ?"
            ));
            stmt->setString(1, email);

            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());

            if (res->next()) {
                User user;
                user.id = res->getInt("id");
                user.username = res->getString("username");
                user.email = res->getString("email");
                user.password_hash = res->getString("password_hash");
                user.date_of_birth = res->getString("date_of_birth");
                user.created_at = res->getString("created_at");
                return user;
            }
            return std::nullopt;
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error: " << e.what() << std::endl;
            return std::nullopt;
        }
    }
};

// Authentication manager to handle user operations
class AuthManager {
private:
    DatabaseManager& db;
    // const std::string jwt_secret = std::getenv("SECRET_KEY"); // Change this in production!
    const std::string jwt_secret = "my secret"; // Change this in production!

    std::string hashPassword(const std::string& password) {
        // In production, use a proper password hashing library like bcrypt
        // This is a simple example using SHA-256
        return BCrypt::generateHash(password);
    }

public:
    AuthManager(DatabaseManager& database) : db(database) {}

    struct LoginResult {
        bool success;
        std::string sessionId;
        std::string message;
    };

    std::string generateToken(const User& user) {
        auto token = jwt::create()
            .set_issuer("auth_service")
            .set_type("JWS")
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_payload_claim("user_id", jwt::claim(std::to_string(user.id)))
            .sign(jwt::algorithm::hs256{jwt_secret});
        return token;
    }

    bool verifyToken(const std::string& token) {
        try {
            auto decoded = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{jwt_secret})
                .with_issuer("auth_service");
            verifier.verify(decoded);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    bool registerUser(const std::string& username, const std::string& email,
                     const std::string& password, const std::string& dob) {
        User user;
        user.username = username;
        user.email = email;
        user.password_hash = hashPassword(password);
        user.date_of_birth = dob;
        
        return db.createUser(user);
    }

    LoginResult loginUser(const std::string& email, 
                          const std::string& password) {
        try{
            auto user = db.getUserByEmail(email);
            if (!user) return {false, "", "Invalid credentials"};
            if (BCrypt::validatePassword(password, user->password_hash)) {
                std::string sessionId = db.createSession(user->id);
                return {true, sessionId, "Login successful"};
            }
            return {false, "", "Invalid credentials"};
        } catch (const std::exception& e) {
            return {false, "", "login failed: " + std::string(e.what())};
        }
    }

    bool logoutUser(const std::string& sessionId) {
        try {
            db.deleteSession(sessionId);
            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }
};

// Middleware for authentication
struct AuthMiddleware {
    AuthManager& auth_manager;

    AuthMiddleware(AuthManager& am) : auth_manager(am) {}

    struct context {};

    void before_handle(crow::request& req, crow::response& res, context& ctx) {
        // Only protect specific routes
        static const std::unordered_set<std::string> protected_routes = {"/upload"};

        if (protected_routes.find(req.url) == protected_routes.end()) {
            return; // Skip middleware for unprotected routes
        }

        auto auth_header = req.get_header_value("Authorization");
        if (auth_header.empty() || !auth_header.starts_with("Bearer ")) {
            res.code = 401;
            res.end();
            return;
        }

        std::string token = auth_header.substr(7);
        if (!auth_manager.verifyToken(token)) {
            res.code = 401;
            res.end();
            return;
        }
    }
    void after_handle(crow::request& req, crow::response& res, context& ctx) {
        // Additional post-processing if needed
    }
};

int main() {
    // Initialize database connection
    dotenv::init();
    auto username = std::getenv("DB_USER");
    auto password = std::getenv("DB_PASSWORD");
    auto database = std::getenv("DB_NAME");
    DatabaseManager db("localhost", username, password, database);
    AuthManager auth_manager(db);

    // Initialize Crow app with middleware
    crow::App<AuthMiddleware> app{AuthMiddleware(auth_manager)};

    // Registration endpoint
    CROW_ROUTE(app, "/register")
        .methods("POST"_method)
        ([&](const crow::request& req) {
            auto body = crow::json::load(req.body);
            if (!body) {
                return crow::response(400, "Invalid JSON");
            }

            try {
                std::string username = body["username"].s();
                std::string email = body["email"].s();
                std::string password = body["password"].s();
                std::string dob = body["dob"].s();

                if (auth_manager.registerUser(username, email, password, dob)) {
                    return crow::response(201, "User registered successfully");
                } else {
                    return crow::response(400, "Failed to register user, possibly due to duplicate credentials");
                }
            } catch (const std::exception&) {
                return crow::response(400, "Invalid request data");
            }
        });

    // Login endpoint
    CROW_ROUTE(app, "/login")
        .methods("POST"_method)
        ([&](const crow::request& req) {
            auto body = crow::json::load(req.body);
            if (!body) {
                return crow::response(400, "Invalid JSON");
            }

            try {
                std::string email = body["email"].s();
                std::string password = body["password"].s();

                auto loginResult = auth_manager.loginUser(email, password);
                if (loginResult.success) {
                    crow::response resp = crow::response(200);
                    resp.add_header("Set-Cookie", "session=" + loginResult.sessionId + "; HttpOnly; Path=/; Max-Age=86400");

                // Also return the session ID in the response body
                crow::json::wvalue response_body({
                    {"status", "success"},
                    {"message", loginResult.message},
                    {"sessionId", loginResult.sessionId}
                });
                resp.write(response_body.dump());
                return resp;
                } else {
                    return crow::response(401, "Invalid credentials");
                }
            } catch (const std::exception&) {
                return crow::response(400, "Invalid request data");
            }
        });

    // Add a logout endpoint
    CROW_ROUTE(app, "/logout")
        .methods("POST"_method)
        ([&](const crow::request& req) {
            // Get session ID from cookie
            auto cookie = req.get_header_value("Cookie");
            size_t sessionStart = cookie.find("session=");
            if (sessionStart == std::string::npos) {
                return crow::response(401, "No session found");
            }

            sessionStart += 8; // length of "session="
            size_t sessionEnd = cookie.find(";", sessionStart);
            std::string sessionId = cookie.substr(sessionStart, 
                                                  sessionEnd == std::string::npos ? std::string::npos : sessionEnd - sessionStart);

            if (auth_manager.logoutUser(sessionId)) {
                crow::response resp = crow::response(200, "Logged out successfully");
                // Clear the session cookie
                resp.add_header("Set-Cookie", 
                                "session=; HttpOnly; Path=/; Max-Age=0");
                return resp;
            } else {
                return crow::response(500, "Logout failed");
            }
        });

    // Endpoint to handle file uploads
    CROW_ROUTE(app, "/upload")
        .methods("POST"_method)
        .middlewares<AuthMiddleware>()  // Apply authentication middleware
        ([](const crow::request& req) {
            try {
                // Verify content type
                std::string content_type = req.get_header_value("Content-Type");
                if (content_type.find("multipart/form-data") == std::string::npos) {
                    return crow::response(400, "Invalid Content-Type. Must be multipart/form-data");
                }

                // Extract boundary
                size_t boundary_pos = content_type.find("boundary=");
                if (boundary_pos == std::string::npos) {
                    return crow::response(400, "No boundary found in multipart/form-data");
                }
                std::string boundary = content_type.substr(boundary_pos + 9);

                // Get request body
                auto& body = req.body;

                // Check file size
                if (body.length() > MAX_FILE_SIZE) {
                    return crow::response(413, "File too large. Maximum size is 50MB");
                }

                // Find and extract filename
                size_t file_start = body.find("filename=");
                if (file_start == std::string::npos) {
                    return crow::response(400, "No file found in request");
                }

                file_start = body.find("\"", file_start) + 1;
                size_t file_end = body.find("\"", file_start);
                std::string original_filename = body.substr(file_start, file_end - file_start);

                // Validate file type
                if (!FileUploadHelper::isAllowedFileType(original_filename)) {
                    return crow::response(415, "File type not allowed. Allowed types: jpg, jpeg, png, gif");
                }

                // Generate secure filename
                std::string secure_filename = FileUploadHelper::generateUniqueFilename(original_filename);

                // Find file content
                size_t content_start = body.find("\r\n\r\n", file_end) + 4;
                if (content_start == std::string::npos) {
                    return crow::response(400, "Malformed request: couldn't find file content");
                }

                size_t content_end = body.find(boundary, content_start);
                if (content_end == std::string::npos) {
                    return crow::response(400, "Malformed request: couldn't find content boundary");
                }
                content_end -= 2; // Remove \r\n before boundary

                // Verify actual file content size
                size_t file_size = content_end - content_start;
                if (file_size > MAX_FILE_SIZE) {
                    return crow::response(413, "File too large. Maximum size is 50MB");
                }

                // Create uploads directory
                std::filesystem::create_directory("uploads");

                // Save file
                std::string filepath = "uploads/" + secure_filename;
                std::ofstream file(filepath, std::ios::binary);
                if (!file) {
                    return crow::response(500, "Failed to create file");
                }

                file.write(body.data() + content_start, content_end - content_start);
                file.close();

                // Prepare success response with details
                crow::json::wvalue response_data({
                    {"status", "success"},
                    {"message", "File uploaded successfully"},
                    {"original_filename", original_filename},
                    {"saved_filename", secure_filename},
                    {"size", file_size}
                });

                return crow::response(200, response_data);
            }
            catch (const std::exception& e) {
                return crow::response(500, std::string("Server error: ") + e.what());
            }
        });

    // Start the server
    app.port(8080).run();
    return 0;
}
