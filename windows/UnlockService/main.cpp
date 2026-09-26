// Created by Rui MA on 26 Sep 2026

#include "UnlockServiceCore.h"
#include "UnlockServiceIpc.h"

#include <winrt/base.h>

#include <Windows.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

namespace {

std::int64_t nowMilliseconds() {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = now.dwLowDateTime;
    ticks.HighPart = now.dwHighDateTime;
    constexpr std::uint64_t kUnixEpochOffset100Nanoseconds = 116444736000000000ULL;
    return static_cast<std::int64_t>(
        (ticks.QuadPart - kUnixEpochOffset100Nanoseconds) / 10000ULL
    );
}

std::string makeResult(const unlock_windows::service::AssertionResult result) {
    std::ostringstream output;
    output << "{\"authenticated\":"
           << (result.authenticated() ? "true" : "false")
           << ",\"status\":\""
           << unlock_windows::service::assertionCodeName(result.code)
           << "\"}";
    return output.str();
}

} // namespace

int main() {
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);

        unlock_windows::service::UnlockServiceCore service;
        unlock_windows::service::ipc::Server server;
        std::cout << "[UnlockService] listening on "
                  << winrt::to_string(unlock_windows::service::ipc::kPipeName)
                  << "\n"
                  << "[UnlockService] no enrollment key is installed; valid assertions will return key_not_enrolled\n";

        for (;;) {
            unlock_windows::service::ipc::Operation operation{};
            std::string payload;
            if (!server.waitForRequest(operation, payload)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }

            auto status = unlock_windows::service::ipc::Status::success;
            std::string response;
            try {
                if (operation == unlock_windows::service::ipc::Operation::issueChallenge) {
                    const auto issued = service.issueChallenge(nowMilliseconds());
                    response = issued.json;
                    std::cout << "[UnlockService] issued challenge requestID="
                              << service.requestIdString(issued.challenge) << "\n";
                } else if (operation == unlock_windows::service::ipc::Operation::verifyAssertion) {
                    const auto result = service.verifyAssertion(payload, nowMilliseconds());
                    response = makeResult(result);
                    std::cout << "[UnlockService] assertion result="
                              << unlock_windows::service::assertionCodeName(result.code) << "\n";
                } else {
                    status = unlock_windows::service::ipc::Status::invalidRequest;
                    response = "unsupported IPC operation";
                }
            } catch (const std::exception& error) {
                status = unlock_windows::service::ipc::Status::serviceRejected;
                response = error.what();
                std::cerr << "[UnlockService] request failed: " << error.what() << "\n";
            }

            if (!server.respond(status, response)) {
                std::cerr << "[UnlockService] response write failed\n";
            }
        }
    } catch (const winrt::hresult_error& error) {
        std::cerr << "[UnlockService] startup failed: "
                  << winrt::to_string(error.message()) << "\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "[UnlockService] startup failed: " << error.what() << "\n";
        return 1;
    }
}
