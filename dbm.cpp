// #include <>
// #include <memory>
// #include <random>
// #include <chrono>
// #include <jwt.h>
//
// // Forward declarations
// class DatabaseManager;
// class AuthManager;
// class SessionManager;
//
// // User model
// struct User {
//     int id;
//     std::string username;
//     std::string email;
//     std::string password_hash;
//     std::string date_of_birth;
//     std::string created_at;
// };
//
// // Database manager to handle MySQL operations
// class DatabaseManager {
// private:
//     std::unique_ptr<sql::mysql::MySQL_Driver> driver;
//     std::unique_ptr<sql::Connection> conn;
//
// public:
//     DatabaseManager(const std::string& host, const std::string& user, 
//                    const std::string& password, const std::string& database) {
//         try {
//             driver.reset(sql::mysql::get_mysql_driver_instance());
//             conn.reset(driver->connect(host, user, password));
//             conn->setSchema(database);
//             
//             // Create users table if it doesn't exist
//             std::unique_ptr<sql::Statement> stmt(conn->createStatement());
//             stmt->execute(
//                 "CREATE TABLE IF NOT EXISTS users ("
//                 "id INT AUTO_INCREMENT PRIMARY KEY,"
//                 "username VARCHAR(50) UNIQUE NOT NULL,"
//                 "email VARCHAR(100) UNIQUE NOT NULL,"
//                 "password_hash VARCHAR(255) NOT NULL,"
//                 "date_of_birth DATE NOT NULL,"
//                 "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
//                 ")"
//             );
//             
//             // Create sessions table if it doesn't exist
//             stmt->execute(
//                 "CREATE TABLE IF NOT EXISTS sessions ("
//                 "id VARCHAR(64) PRIMARY KEY,"
//                 "user_id INT NOT NULL,"
//                 "expires_at TIMESTAMP NOT NULL,"
//                 "FOREIGN KEY (user_id) REFERENCES users(id)"
//                 ")"
//             );
//         } catch (sql::SQLException &e) {
//             std::cerr << "SQL Error: " << e.what() << std::endl;
//             throw;
//         }
//     }
//
//     bool createUser(const User& user) {
//         try {
//             std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
//                 "INSERT INTO users (username, email, password_hash, date_of_birth) "
//                 "VALUES (?, ?, ?, ?)"
//             ));
//             
//             stmt->setString(1, user.username);
//             stmt->setString(2, user.email);
//             stmt->setString(3, user.password_hash);
//             stmt->setString(4, user.date_of_birth);
//             
//             return stmt->executeUpdate() > 0;
//         } catch (sql::SQLException &e) {
//             std::cerr << "SQL Error: " << e.what() << std::endl;
//             return false;
//         }
//     }
//
//     std::optional<User> getUserByEmail(const std::string& email) {
//         try {
//             std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
//                 "SELECT * FROM users WHERE email = ?"
//             ));
//             stmt->setString(1, email);
//             
//             std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());
//             
//             if (res->next()) {
//                 User user;
//                 user.id = res->getInt("id");
//                 user.username = res->getString("username");
//                 user.email = res->getString("email");
//                 user.password_hash = res->getString("password_hash");
//                 user.date_of_birth = res->getString("date_of_birth");
//                 user.created_at = res->getString("created_at");
//                 return user;
//             }
//             return std::nullopt;
//         } catch (sql::SQLException &e) {
//             std::cerr << "SQL Error: " << e.what() << std::endl;
//             return std::nullopt;
//         }
//     }
// };
//
// // Authentication manager to handle user operations
// class AuthManager {
// private:
//     DatabaseManager& db;
//     const std::string jwt_secret = "your-secret-key"; // Change this in production!
//
//     std::string hashPassword(const std::string& password) {
//         // In production, use a proper password hashing library like bcrypt
//         // This is a simple example using SHA-256
//         return crow::utility::base64encode(
//             crow::utility::sha256bin(password)
//         );
//     }
//
// public:
//     AuthManager(DatabaseManager& database) : db(database) {}
//
//     std::string generateToken(const User& user) {
//         auto token = jwt::create()
//             .set_issuer("auth_service")
//             .set_type("JWS")
//             .set_issued_at(std::chrono::system_clock::now())
//             .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
//             .set_payload_claim("user_id", jwt::claim(std::to_string(user.id)))
//             .sign(jwt::algorithm::hs256{jwt_secret});
//         return token;
//     }
//
//     bool verifyToken(const std::string& token) {
//         try {
//             auto decoded = jwt::decode(token);
//             auto verifier = jwt::verify()
//                 .allow_algorithm(jwt::algorithm::hs256{jwt_secret})
//                 .with_issuer("auth_service");
//             verifier.verify(decoded);
//             return true;
//         } catch (const std::exception&) {
//             return false;
//         }
//     }
//
//     bool registerUser(const std::string& username, const std::string& email,
//                      const std::string& password, const std::string& dob) {
//         User user;
//         user.username = username;
//         user.email = email;
//         user.password_hash = hashPassword(password);
//         user.date_of_birth = dob;
//         
//         return db.createUser(user);
//     }
//
//     std::optional<std::string> loginUser(const std::string& email, 
//                                        const std::string& password) {
//         auto user = db.getUserByEmail(email);
//         if (!user) return std::nullopt;
//         
//         if (user->password_hash == hashPassword(password)) {
//             return generateToken(*user);
//         }
//         return std::nullopt;
//     }
// };
//
// // Middleware for authentication
// struct AuthMiddleware {
//     AuthManager& auth_manager;
//
//     AuthMiddleware(AuthManager& am) : auth_manager(am) {}
//
//     struct context {};
//
//     void before_handle(crow::request& req, crow::response& res, context& ctx) {
//         auto auth_header = req.get_header_value("Authorization");
//         if (auth_header.empty() || !auth_header.starts_with("Bearer ")) {
//             res.code = 401;
//             res.end();
//             return;
//         }
//
//         std::string token = auth_header.substr(7);
//         if (!auth_manager.verifyToken(token)) {
//             res.code = 401;
//             res.end();
//             return;
//         }
//     }
//
//     void after_handle(crow::request& req, crow::response& res, context& ctx) {
//         // Additional post-processing if needed
//     }
// };
//
