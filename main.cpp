#include "crow.h"
#include <fstream>
#include <string>
#include <filesystem>
#include <unordered_set>
#include <regex>
#include <algorithm>

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
