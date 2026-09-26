// Created by Rui MA on 26 Sep 2026

#include "UnlockServiceIpc.h"

#include <chrono>
#include <iostream>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

void require(const bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace

int main() {
    std::exception_ptr serverError;
    std::thread serverThread([&]() {
        try {
            unlock_windows::service::ipc::Server server;
            unlock_windows::service::ipc::Operation operation{};
            std::string payload;
            require(server.waitForRequest(operation, payload), "server did not receive request");
            require(
                operation == unlock_windows::service::ipc::Operation::verifyAssertion,
                "server received the wrong operation"
            );
            require(payload == "ipc-test-payload", "server received the wrong payload");
            require(
                server.respond(
                    unlock_windows::service::ipc::Status::success,
                    "ipc-test-response"
                ),
                "server response failed"
            );
        } catch (...) {
            serverError = std::current_exception();
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const auto response = unlock_windows::service::ipc::call(
        unlock_windows::service::ipc::Operation::verifyAssertion,
                "ipc-test-payload"
            );
    serverThread.join();
    if (serverError) {
        std::rethrow_exception(serverError);
    }

    require(
        response.status == unlock_windows::service::ipc::Status::success,
        "client received an IPC failure"
    );
    require(response.payload == "ipc-test-response", "client received the wrong response");
    std::cout << "UnlockService IPC tests passed\n";
    return 0;
}
