// Created by Rui MA on 26 Sep 2026
// Modified by Rui MA on 26 Sep 2026

#include "UnlockServiceIpc.h"

#include <chrono>
#include <iostream>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

constexpr wchar_t kTestPipeName[] = L"\\\\.\\pipe\\unlock-windows-with-iphone-ipc-test-v1";

void require(const bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace

int main() {
    try {
        std::exception_ptr serverError;
        std::thread serverThread([&]() {
            try {
                unlock_windows::service::ipc::Server server(kTestPipeName);
                for (int round = 0; round < 2; ++round) {
                    unlock_windows::service::ipc::Operation operation{};
                    std::string payload;
                    require(server.waitForRequest(operation, payload), "server did not receive request");
                    if (round == 0) {
                        require(
                            operation == unlock_windows::service::ipc::Operation::verifyAssertion,
                            "server received the wrong first operation"
                        );
                        require(payload == "ipc-test-payload", "server received the wrong first payload");
                        require(
                            server.respond(
                                unlock_windows::service::ipc::Status::success,
                                "ipc-test-response"
                            ),
                            "first server response failed"
                        );
                    } else {
                        require(
                            operation == unlock_windows::service::ipc::Operation::consumeUnlockApproval,
                            "server received the wrong second operation"
                        );
                        require(payload.empty(), "consume approval request had an unexpected payload");
                        const std::string binaryResponse("\x01\x00", 2);
                        require(
                            server.respond(
                                unlock_windows::service::ipc::Status::success,
                                binaryResponse
                            ),
                            "second server response failed"
                        );
                    }
                }
            } catch (...) {
                serverError = std::current_exception();
            }
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        const auto response = unlock_windows::service::ipc::callOnPipe(
            kTestPipeName,
            unlock_windows::service::ipc::Operation::verifyAssertion,
            "ipc-test-payload"
        );
        const auto approvalResponse = unlock_windows::service::ipc::callOnPipe(
            kTestPipeName,
            unlock_windows::service::ipc::Operation::consumeUnlockApproval,
            {}
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
        require(
            approvalResponse.status == unlock_windows::service::ipc::Status::success &&
                approvalResponse.payload.size() == 2 &&
                approvalResponse.payload[0] == '\x01' &&
                approvalResponse.payload[1] == '\x00',
            "client did not preserve the binary approval response"
        );
        std::cout << "UnlockService IPC tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "UnlockService IPC tests failed: " << error.what() << "\n";
        return 1;
    }
}
