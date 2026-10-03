// Created by Rui MA on 03 Oct 2026

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace unlock_windows::gatt {

class TransportReadiness final {
public:
    static constexpr std::uint8_t readyRequest = 0x04;

    static bool validRequestId(std::string_view id) noexcept {
        if (id.size() != 36) return false;
        for (std::size_t i = 0; i < id.size(); ++i) {
            if (i == 8 || i == 13 || i == 18 || i == 23) { if (id[i] != '-') return false; }
            else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return false;
        }
        return true;
    }

    bool prepare(const std::string& request, const std::wstring& peer, std::uint64_t generation,
        std::uint64_t deadline, std::uint64_t now) {
        if (!validRequestId(request) || peer.empty() || deadline <= now) { clear(); return false; }
        if (request != request_ || peer != peer_ || generation != generation_ || deadline != deadline_) {
            clear();
            request_ = request;
            peer_ = peer;
            generation_ = generation;
            deadline_ = deadline;
        }
        return true;
    }

    bool probeDue(std::uint64_t now) const noexcept {
        return !request_.empty() && !ready_ && now < deadline_ && now >= nextProbe_;
    }
    void probeAttempted(std::uint64_t now, bool sent) noexcept {
        nextProbe_ = now + 1000;
        if (sent && !sent_) firstProbeAt_ = now;
        sent_ = sent_ || sent;
    }
    bool acknowledge(const std::vector<std::uint8_t>& frame, const std::wstring& peer,
        std::uint64_t generation, std::uint64_t now, std::uint64_t receivedAt) noexcept {
        if (!sent_ || frame.size() != 37 || frame.front() != readyRequest ||
            peer != peer_ || generation != generation_ || now >= deadline_ ||
            receivedAt < firstProbeAt_ || receivedAt > now ||
            std::string_view(reinterpret_cast<const char*>(frame.data() + 1), 36) != request_) return false;
        ready_ = true;
        return true;
    }
    bool ready(std::uint64_t now) const noexcept { return ready_ && now < deadline_; }
    const std::string& request() const noexcept { return request_; }
    void clear() noexcept {
        request_.clear(); peer_.clear(); generation_ = 0; deadline_ = 0;
        nextProbe_ = 0; firstProbeAt_ = 0; sent_ = false; ready_ = false;
    }

private:
    std::string request_;
    std::wstring peer_;
    std::uint64_t generation_ = 0;
    std::uint64_t deadline_ = 0;
    std::uint64_t nextProbe_ = 0;
    std::uint64_t firstProbeAt_ = 0;
    bool sent_ = false;
    bool ready_ = false;
};

}
