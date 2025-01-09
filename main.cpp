#include "crow.h"
#include "crow/app.h"
#include "crow/logging.h"
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
#include <laserpants/dotenv/dotenv.h>

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
            stmt->execute(
                "CREATE TABLE IF NOT EXISTS photos ("
                "id INT AUTO_INCREMENT PRIMARY KEY,"
                "user_id INT NOT NULL,"
                "filename VARCHAR(255) NOT NULL,"
                "size INT NOT NULL,"
                "uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
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

    bool createPhoto(int user_id, const std::string& filename, int size) {
        try {
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                "INSERT INTO photos (user_id, filename, size) VALUES (?, ?, ?)"
            ));

            stmt->setInt(1, user_id);
            stmt->setString(2, filename);
            stmt->setInt(3, size);

            return stmt->executeUpdate() > 0;
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error: " << e.what() << std::endl;
            return false;
        }
    }

    bool verifyPhoto(int user_id, const std::string& filename) {
        try {
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                "SELECT filename FROM photos WHERE user_id = ? AND user_id = ?"
            ));
            stmt->setInt(1, user_id);

            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());
            if (res->next()) {
                return true;
            } else {
                return false;
            }
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error: " << e.what() << std::endl;
        }
        return "";
    }

    std::vector<std::string> getPhotosByUserId(int user_id) {
        std::vector<std::string> photos;
        try {
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                "SELECT filename FROM photos WHERE user_id = ?"
            ));
            stmt->setInt(1, user_id);

            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());
            while (res->next()) {
                photos.push_back(res->getString("filename"));
            }
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error: " << e.what() << std::endl;
        }
        return photos;
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

    struct LoginResult {
        bool success;
        std::string token;
        std::string message;
    };

    std::string generateToken(const User& user) {
        auto token = jwt::create()
            .set_issuer("auth_service")
            .set_type("JWS")
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_payload_claim("user_id", jwt::claim(std::to_string(user.id)))
            .set_payload_claim("email", jwt::claim(user.email))
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
                std::string token = generateToken(*user);
                return {true, token, "Login successful"};
            }
            return {false, "", "Invalid credentials"};
        } catch (const std::exception& e) {
            return {false, "", "login failed: " + std::string(e.what())};
        }
    }
};

// Middleware for authentication
struct AuthMiddleware {
    AuthManager& auth_manager;

    AuthMiddleware(AuthManager& am) : auth_manager(am) {}

    struct context {
        std::string user_id;
        std::string email;
    };

    void before_handle(crow::request& req, crow::response& res, context& ctx) {
        auto url = req.url;
        bool is_protected = false;

        // Check if the URL starts with any of the protected route prefixes
        for (const auto& route : {"/upload", "/photos", "/media"}) {
            if (url.starts_with(route)) {
                is_protected = true;
                break;
            }
        }

        if (!is_protected) {
            return;
        }

        auto auth_header = req.get_header_value("Authorization");
        if (auth_header.empty() || !auth_header.starts_with("Bearer ")) {
            res.code = 401;
            res.end();
            return;
        }

        std::string token = auth_header.substr(7);
        try {
            auto decoded = jwt::decode(token);
            if (!auth_manager.verifyToken(token)) {
                res.code = 401;
                res.end();
                return;
            }

            // Store user information in context
            ctx.user_id = decoded.get_payload_claim("user_id").as_string();
            ctx.email = decoded.get_payload_claim("email").as_string();
        } catch (const std::exception&) {
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
    DatabaseManager db("127.0.0.1", username, password, database);
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
                    // Prepare success response with details
                    crow::json::wvalue response_data({
                        {"status", "success"},
                        {"message", "user registered successfully"},
                    });
                    return crow::response(200, response_data);
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
                    crow::json::wvalue response_body({
                        {"status", "success"},
                        {"message", loginResult.message},
                        {"token", loginResult.token}
                    });
                    return crow::response(200, response_body);
                } else {
                    return crow::response(401, "Invalid credentials");
                }
            } catch (const std::exception&) {
                return crow::response(400, "Invalid request data");
            }
        });

    // Endpoint to handle file uploads
    CROW_ROUTE(app, "/upload")
        .methods("POST"_method)
        ([&app, &db](const crow::request& req) {
            try {
                auto& ctx = app.get_context<AuthMiddleware>(req);

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

                db.createPhoto(std::stoi(ctx.user_id), secure_filename, file_size);

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

        CROW_ROUTE(app, "/photos")
        .methods("POST"_method)
        ([&app, &db](const crow::request& req) {
            try {
            auto& ctx = app.get_context<AuthMiddleware>(req);
            CROW_LOG_INFO << "User ID: " << ctx.user_id;
            auto photos = db.getPhotosByUserId(std::stoi(ctx.user_id));

            CROW_LOG_INFO << "Called photos";

            crow::json::wvalue response_data;
            response_data["photos"] = crow::json::wvalue();
            response_data["photos"] = (photos);
            response_data["status"] = "success";
            response_data["message"] = "Photos retrieved successfully";

            return crow::response(200, response_data);
            } catch (const std::exception& e) {
                return crow::response(500, std::string("Server error: ") + e.what());
            }
        });

    CROW_ROUTE(app, "/media/<string>")
        .methods("GET"_method)
        ([&app, &db](const crow::request& req, std::string filename) {
    try {
        // Sanitize filename for security
        filename = FileUploadHelper::sanitizeFilename(filename);

        // Get user ID from the middleware context
        auto& ctx = app.get_context<AuthMiddleware>(req);
        int user_id = std::stoi(ctx.user_id);

        // Verify that the user owns the photo
        if (!db.verifyPhoto(user_id, filename)) {
            return crow::response(403, "Access denied");
        }

        // File path
        std::string file_path = "uploads/" + filename;

        // Check if file exists
        if (!std::filesystem::exists(file_path)) {
            return crow::response(404, "File not found");
        }

        // Get file size
        std::uintmax_t size = std::filesystem::file_size(file_path);
        CROW_LOG_INFO << "File size: " << size;

        // Read the file
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return crow::response(500, "Failed to open file");
        }

        // Create response
        crow::response res;
        res.set_header("Content-Type", "image/" + FileUploadHelper::getFileExtension(filename).substr(1));
        res.set_header("Content-Length", std::to_string(size));

        // Read file content
        std::vector<char> buffer(size);
        file.read(buffer.data(), size);

        res.body = std::string(buffer.data(), size);
        return res;

    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Error in /media endpoint: " << e.what();
        return crow::response(500, "Internal server error");
    }
});


    // Start the server
    app.port(8080).run();
    return 0;
}
