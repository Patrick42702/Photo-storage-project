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
#include <cpp/opportunisticsecuresmtpclient.hpp>
#include <cpp/htmlmessage.hpp>

using namespace jed_utils::cpp;

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
class ResponseHelper;
class Sanitizer;
class EmailSender;

// User model
struct User {
    int id;
    std::string username;
    std::string email;
    std::string password_hash;
    std::string date_of_birth;
    std::string created_at;
    bool verified;
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
                "verified BOOLEAN DEFAULT TRUE,"
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                ")"
            );
            stmt->execute(
                "CREATE TABLE IF NOT EXISTS photos ("
                "id INT AUTO_INCREMENT PRIMARY KEY,"
                "user_id INT NOT NULL,"
                "filename VARCHAR(255) NOT NULL,"
                "title VARCHAR(255),"
                "description TEXT,"
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
                        "INSERT INTO users (username, email, password_hash, date_of_birth, verified) "
                        "VALUES (?, ?, ?, ?, ?)"
                    ));

            stmt->setString(1, user.username);
            stmt->setString(2, user.email);
            stmt->setString(3, user.password_hash);
            stmt->setString(4, user.date_of_birth);
            stmt->setBoolean(5, user.verified);

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
                user.verified = res->getBoolean("verified");
                user.created_at = res->getString("created_at");
                return user;
            }
            return std::nullopt;
        } catch (sql::SQLException &e) {
            std::cerr << "SQL Error: " << e.what() << std::endl;
            return std::nullopt;
        }
    }

    bool createPhoto(int user_id, const std::string& filename, const std::string& title, const std::string& description, int size) {
        try {
            std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
                        "INSERT INTO photos (user_id, filename, title, description, size) VALUES (?, ?, ?, ?, ?)"
                    ));

            stmt->setInt(1, user_id);
            stmt->setString(2, filename);
            stmt->setString(3, title);
            stmt->setString(4, description);
            stmt->setInt(5, size);

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
        user.verified = false;

        return db.createUser(user);
    }

    LoginResult loginUser(const std::string& email,
                          const std::string& password) {
        try {
            auto user = db.getUserByEmail(email);
            if (!user) return {false, "", "Invalid credentials"};
            if (BCrypt::validatePassword(password, user->password_hash) && user->verified) {
                std::string token = generateToken(*user);
                return {true, token, "Login successful"};
            }
            return {false, "", "Invalid credentials"};
        } catch (const std::exception& e) {
            return {false, "", "login failed: " + std::string(e.what())};
        }
    }
};

class ResponseHelper {
public:
    static crow::response json(crow::json::wvalue& data, int status = 200) {
        crow::response res;
        res.code = status;
        res.add_header("Content-Type", "application/json");
        res.body = std::string(data.dump());
        return res;
    }

    static crow::response format(const std::string& status, const std::string& message, int status_code) {
        crow::json::wvalue data;
        data["status"] = status;
        data["message"] = message;
        return json(data, status_code);
    }
};

class Sanitizer {
public:
    static std::string sanitizeTextField(const std::string& input) {
        std::string output;
        output.reserve(input.length());

        for (size_t i = 0; i < input.length(); ++i) {
            char c = input[i];

            // Replace or remove problematic characters
            if (c == '\r' || c == '\n' || c == '\0') {
                // Replace newlines and null bytes with spaces
                output += ' ';
            }
            else if (c < 32 && c != '\t') {
                // Remove other control characters except tab
                continue;
            }
            else {
                output += c;
            }
        }

        // Trim leading/trailing whitespace
        size_t start = output.find_first_not_of(" \t");
        size_t end = output.find_last_not_of(" \t");

        if (start == std::string::npos) {
            return ""; // String is all whitespace
        }

        return output.substr(start, end - start + 1);
    }

    static bool validateTextField(const std::string& input, size_t maxLength = 255) {
        if (input.empty() || input.length() > maxLength) {
            return false;
        }

        // Check for minimum printable character ratio (e.g., 80%)
        int printable = 0;
        for (char c : input) {
            if (isprint(c)) {
                printable++;
            }
        }

        return (static_cast<double>(printable) / input.length()) >= 0.8;
    }
};

class EmailSender {
private:
    // Private instance of SMTP client
    static std::unique_ptr<OpportunisticSecureSMTPClient> client;
    static std::once_flag init_flag;

    // Private constructor to prevent direct instantiation
    EmailSender() = default;

    // Initialize the SMTP client
    static void initializeClient() {
        auto smtp_host = std::getenv("SMTP_HOST");
        if (!smtp_host) {
            throw std::runtime_error("Missing SMTP configuration");
        }

        client = std::make_unique<OpportunisticSecureSMTPClient>(
                     smtp_host,
                     587
                 );
    }

    // Get the singleton instance of SMTP client
    static OpportunisticSecureSMTPClient& getClient() {
        std::call_once(init_flag, &EmailSender::initializeClient);
        return *client;
    }
public:
    static bool sendVerificationEmail(const std::string& user_email) {
        try {
            // Initialize SMTP client
            const MessageAddress from("no-reply@example.com", "Test Address Display");
            const auto to = { MessageAddress(user_email) };
            const auto subject = "Verify your photo storage account!";
            const auto body = "<html><body><h1>Hello,</h1><br/><br/><p>In order to verify that you own the email you provided, \
                              please click on the following link:</p><a href=></html>";
            HTMLMessage msg(from, to, subject, body);
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error sending email: " << e.what() << std::endl;
            return false;
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
        for (const auto& route : {
                    "/upload", "/photos", "/media"
                }) {
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
            res.body = std::string("Unauthorized: You must login before accessing this endpoint");
            res.end();
            return;
        }

        std::string token = auth_header.substr(7);
        try {
            auto decoded = jwt::decode(token);
            if (!auth_manager.verifyToken(token)) {
                res.code = 401;
                res.body = std::string("Unauthorized: You must login before accessing this endpoint");
                res.end();
                return;
            }

            // Store user information in context
            ctx.user_id = decoded.get_payload_claim("user_id").as_string();
            ctx.email = decoded.get_payload_claim("email").as_string();
        } catch (const std::exception&) {
            res.code = 401;
            res.body = std::string("Unauthorized: You must login before accessing this endpoint");
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
    ResponseHelper res_helper;
    // EmailSender::sendVerificationEmail("");

    // Initialize Crow app with middleware
    crow::App<AuthMiddleware> app{AuthMiddleware(auth_manager)};

    // Registration endpoint
    CROW_ROUTE(app, "/register")
    .methods("POST"_method)
    ([&](const crow::request& req) {
        auto body = crow::json::load(req.body);
        auto res_body = crow::json::wvalue();
        if (!body) {
            return res_helper.format("error", "Invalid JSON", 400);
        }

        try {
            std::string username = body["username"].s();
            std::string email = body["email"].s();
            std::string password = body["password"].s();
            std::string dob = body["dob"].s();

            if (auth_manager.registerUser(username, email, password, dob)) {
                return res_helper.format("success", "user registered successfully", 200);
            } else {
                return res_helper.format("error", "Failed to register user, possibly due to duplicate credentials", 400);
            }
        } catch (const std::exception&) {
            CROW_LOG_ERROR << "Error in /register endpoint";
            return crow::response(400, "Invalid request data");
        }
    });

    // Login endpoint
    CROW_ROUTE(app, "/login")
    .methods("POST"_method)
    ([&](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body) {
            return res_helper.format("error", "Invalid JSON", 400);
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
                CROW_LOG_INFO << "Login failed for email: " << email;
                return res_helper.format("error", loginResult.message, 401);
            }
        } catch (const std::exception&) {
            CROW_LOG_ERROR << "Error in /login endpoint";
            return res_helper.format("error", "Invalid request data", 400);
        }
    });

    // Endpoint to handle file uploads
    CROW_ROUTE(app, "/upload")
    .methods("POST"_method)
    ([&](const crow::request& req) {
        try {
            auto& ctx = app.get_context<AuthMiddleware>(req);

            // Verify content type
            std::string content_type = req.get_header_value("Content-Type");
            if (content_type.find("multipart/form-data") == std::string::npos) {
                return res_helper.format("error", "Invalid content type. Expected multipart/form-data", 400);
            }

            // Extract boundary
            size_t boundary_pos = content_type.find("boundary=");
            if (boundary_pos == std::string::npos) {
                return res_helper.format("error", "Invalid content type. Missing boundary", 400);
            }
            std::string boundary = content_type.substr(boundary_pos + 9);

            // Get request body
            auto& body = req.body;

            // Find and extract title
            size_t title_start = body.find("Content-Disposition: form-data; name=\"title\"");
            if (title_start == std::string::npos) {
                return res_helper.format("error", "Malformed request: couldn't find the title field", 400);
            }
            title_start = body.find("\r\n\r\n", title_start) + 4;
            size_t title_end = body.find(boundary, title_start) - 4; // -2 for \r\n
            std::string title = Sanitizer::sanitizeTextField(body.substr(title_start, title_end - title_start));

            // Find and extract description
            size_t desc_start = body.find("Content-Disposition: form-data; name=\"description\"");
            if (desc_start == std::string::npos) {
                return res_helper.format("error", "Malformed request: couldn't find the description field", 400);
            }
            desc_start = body.find("\r\n\r\n", desc_start) + 4;
            size_t desc_end = body.find(boundary, desc_start) - 4; // -2 for \r\n
            std::string description = Sanitizer::sanitizeTextField(body.substr(desc_start, desc_end - desc_start));

            // Validate the fields
            if (!Sanitizer::validateTextField(title, 255) || !Sanitizer::validateTextField(description, 1000)) {
                return res_helper.format("error", "Invalid title or description format", 400);
            }

            // Find and extract filename
            size_t file_start = body.find("filename=");
            if (file_start == std::string::npos) {
                return res_helper.format("error", "Malformed request: couldn't find the filename in request", 400);
            }

            file_start = body.find("\"", file_start) + 1;
            size_t file_end = body.find("\"", file_start);
            std::string original_filename = body.substr(file_start, file_end - file_start);

            // Validate file type
            if (!FileUploadHelper::isAllowedFileType(original_filename)) {
                return res_helper.format("error", "Invalid file type. Allowed types are jpg, jpeg, png, gif", 400);
            }

            // Generate secure filename
            std::string secure_filename = FileUploadHelper::generateUniqueFilename(original_filename);

            // Find file content
            size_t content_start = body.find("\r\n\r\n", file_end) + 4;
            if (content_start == std::string::npos) {
                return res_helper.format("error", "Malformed request: couldn't find file content", 400);
            }

            size_t content_end = body.find(boundary, content_start);
            if (content_end == std::string::npos) {
                return res_helper.format("error", "Malformed request: couldn't find end of file content", 400);
            }
            content_end -= 2; // Remove \r\n before boundary

            // Verify actual file content size
            size_t file_size = content_end - content_start;
            if (file_size > MAX_FILE_SIZE) {
                return res_helper.format("error", "File too large. Maximum size is 50MB", 413);
            }

            // Create uploads directory
            std::filesystem::create_directory("uploads");

            // Save file
            std::string filepath = "uploads/" + secure_filename;
            std::ofstream file(filepath, std::ios::binary);
            if (!file) {
                return res_helper.format("error", "Failed to save file", 500);
            }

            file.write(body.data() + content_start, content_end - content_start);
            file.close();

            db.createPhoto(std::stoi(ctx.user_id), secure_filename, title, description, file_size);

            // Prepare success response with details
            crow::json::wvalue response_data({
                {"status", "success"},
                {"message", "File uploaded successfully"},
                {"original_filename", original_filename},
                {"saved_filename", secure_filename},
                {"title", title},
                {"description", description},
                {"size", file_size}
            });

            return crow::response(200, response_data);
        }
        catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /upload endpoint: " << e.what();
            return res_helper.format("error", "Failed to upload file", 500);
        }
    });

    CROW_ROUTE(app, "/photos")
    .methods("POST"_method)
    ([&](const crow::request& req) {
        try {
            auto& ctx = app.get_context<AuthMiddleware>(req);
            auto photos = db.getPhotosByUserId(std::stoi(ctx.user_id));

            crow::json::wvalue response_data;
            response_data["photos"] = crow::json::wvalue();
            response_data["photos"] = (photos);
            response_data["status"] = "success";
            response_data["message"] = "Photos retrieved successfully";

            return crow::response(200, response_data);
        } catch (const std::exception& e) {
            CROW_LOG_ERROR << "Error in /photos endpoint: " << e.what();
            return crow::response(500, "Internal server error");
        }
    });

    CROW_ROUTE(app, "/media/<string>")
    .methods("GET"_method)
    ([&](const crow::request& req, std::string filename) {
        try {
            // Sanitize filename for security
            filename = FileUploadHelper::sanitizeFilename(filename);

            // Get user ID from the middleware context
            auto& ctx = app.get_context<AuthMiddleware>(req);
            int user_id = std::stoi(ctx.user_id);

            // Verify that the user owns the photo
            if (!db.verifyPhoto(user_id, filename)) {
                return crow::response(403, "Forbidden");
            }

            // File path
            std::string file_path = "uploads/" + filename;

            // Check if file exists
            if (!std::filesystem::exists(file_path)) {
                return res_helper.format("error", "File not found", 404);
            }

            // Get file size
            std::uintmax_t size = std::filesystem::file_size(file_path);

            // Read the file
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                return res_helper.format("error", "Failed to open file", 500);
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
            return res_helper.format("error", "Failed to retrieve file", 500);
        }
    });


    // Start the server
    app.port(8080).run();
    return 0;
}
