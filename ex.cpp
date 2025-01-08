#include <boost/beast/core.hpp>
#include <boost/beast/core/file.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <fstream>
#include <string>

namespace beast = boost::beast;       // from <boost/beast.hpp>
namespace http = beast::http;        // from <boost/beast/http.hpp>
namespace asio = boost::asio;        // from <boost/asio.hpp>
namespace filesystem = boost::filesystem;  // from <boost/filesystem.hpp>
using tcp = boost::asio::ip::tcp;    // from <boost/asio/ip/tcp.hpp>

// Save file content inside of ~/photo-images
bool save_file(const std::string& file_name, const std::string& file_content) {
    const char* home_dir = std::getenv("HOME");
    if (!home_dir) {
        std::cerr << "Error: Unable to get home directory." << std::endl;
        return false;
    }
    // Construct the full path to the target directory ~/photo-images/
    std::string home_dir_str(home_dir + std::string("/photo-images"));
    filesystem::path target_dir = filesystem::path(home_dir_str);

    // Ensure the directory exists, create it if necessary
    if (!filesystem::exists(target_dir)) {
        filesystem::create_directories(target_dir);
    }

    // Create the full file path
    filesystem::path file_path = target_dir / file_name;

    std::ofstream file(file_name, std::ios::binary);
    if (!file) {
        return false;
    }
    file.write(file_content.c_str(), file_content.size());
    return true;
}

// Function to parse multipart form-data
std::string extract_field(const std::string& body, const std::string& field_name) {
    std::string search_pattern = "name=\"" + field_name + "\"";
    auto pos = body.find(search_pattern);
    if (pos == std::string::npos) {
        return "";
    }

    auto value_start = body.find("\r\n\r\n", pos) + 4;
    auto value_end = body.find("\r\n--", value_start);
    return body.substr(value_start, value_end - value_start);
}

void handle_request(http::request<http::string_body> req, http::response<http::string_body>& res) {
    if (req.method() != http::verb::post || req.target() != "/upload") {
        res = http::response<http::string_body>(http::status::not_found, req.version());
        res.set(http::field::server, "Beast");
        res.set(http::field::content_type, "text/plain");
        res.body() = "Not Found";
        res.prepare_payload();
        return;
    }

    try {
        // Extract fields from the body
        std::string title = extract_field(req.body(), "title");
        std::string description = extract_field(req.body(), "description");
        std::string image_data = extract_field(req.body(), "image");

        if (title.empty() || description.empty() || image_data.empty()) {
            res = http::response<http::string_body>(http::status::bad_request, req.version());
            res.set(http::field::content_type, "text/plain");
            res.body() = "Missing title, description, or image";
            res.prepare_payload();
            return;
        }

        // Save the image
        std::string file_path = "/home/patrick/photo-images/" + title;
        if (!save_file(file_path, image_data)) {
            res = http::response<http::string_body>(http::status::internal_server_error, req.version());
            res.set(http::field::content_type, "text/plain");
            res.body() = "Failed to save the image";
            res.prepare_payload();
            return;
        }

        // Success response
        res = http::response<http::string_body>(http::status::ok, req.version());
        res.set(http::field::content_type, "text/plain");
        res.body() = "Upload successful";
        res.prepare_payload();
    } catch (const std::exception& e) {
        res = http::response<http::string_body>(http::status::internal_server_error, req.version());
        res.set(http::field::content_type, "text/plain");
        res.body() = std::string("Error: ") + e.what();
        res.prepare_payload();
    }
}

int main() {
    try {
        auto const address = asio::ip::make_address("127.0.0.1");
        unsigned short const port = 8080;

        asio::io_context ioc{1};

        tcp::acceptor acceptor{ioc, {address, port}};

        std::cout << "Server is running on http://127.0.0.1:8080" << std::endl;

        for (;;) {
            // Create a new socket for each new connection attempt
            tcp::socket socket{ioc};

            // Accept the new connection
            acceptor.accept(socket);

            beast::flat_buffer buffer;

            http::request<http::string_body> req;
            http::read(socket, buffer, req);

            http::response<http::string_body> res;
            handle_request(req, res);

            http::write(socket, res);
            socket.shutdown(tcp::socket::shutdown_send);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

