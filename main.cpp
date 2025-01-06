#include "crow.h"

int main(int argc, char *argv[])
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/") ([]() {
        return "Hello world!";
    });

    // Start the server on port 8080
    app.port(8080).multithreaded().run();
    return 0;
}
