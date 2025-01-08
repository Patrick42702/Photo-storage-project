#include "crow.h"
#include <cstdlib>
#include <fstream>
#include <jwt-cpp/traits/kazuho-picojson/defaults.h>
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
#include <jwt-cpp/jwt.h>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <bcrypt/BCrypt.hpp>

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
    const std::string jwt_secret = std::getenv("SECRET_KEY"); // Change this in production!

    std::string hashPassword(const std::string& password) {
        // In production, use a proper password hashing library like bcrypt
        // This is a simple example using SHA-256
        return BCrypt::generateHash(password);
    }

public:
    AuthManager(DatabaseManager& database) : db(database) {}

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

    std::optional<std::string> loginUser(const std::string& email, 
                                       const std::string& password) {
        auto user = db.getUserByEmail(email);
        if (!user) return std::nullopt;
        
        if (user->password_hash == hashPassword(password)) {
            return generateToken(*user);
        }
        return std::nullopt;
    }
};

// Middleware for authentication
struct AuthMiddleware {
    AuthManager& auth_manager;

    AuthMiddleware(AuthManager& am) : auth_manager(am) {}

    struct context {};

    void before_handle(crow::request& req, crow::response& res, context& ctx) {
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
    crow::SimpleApp app;

    // Endpoint to handle file uploads
    CROW_ROUTE(app, "/upload")
        .methods("POST"_method)
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
