// Created by Rui MA on 03 Oct 2026

#pragma once

#include <cstdint>

namespace unlock_windows::gatt {

class AdvertisingLifecycle final {
public:
    enum class Action { none, start, stop };
    enum class Failure { none, startTimeout, startException, aborted, incomplete, stopException };
    static constexpr std::uint64_t operationLifetime = 5000;

    void desire(bool enabled) noexcept {
        if (desired_ == enabled) return;
        desired_ = enabled;
        refresh();
    }

    void refresh() noexcept {
        retries_ = 0;
        retryAt_ = 0;
        exhausted_ = false;
        stopFailed_ = false;
        failure_ = Failure::none;
    }

    Action advance(std::uint64_t now, int observed) noexcept {
        const bool running = observed == 2 || observed == 4;
        if (pending_ == Action::start) {
            if (!stopAccepted_ && observed == 2) {
                pending_ = Action::none;
                confirmed_ = true;
                refresh();
            } else if (now < deadline_) return Action::none;
            else fail(now, observed == 4 ? Failure::incomplete : Failure::startTimeout);
        } else if (pending_ == Action::stop) return Action::none;

        if (!desired_) {
            confirmed_ = false;
            return !stopAccepted_ && running && !stopFailed_ ? begin(Action::stop, now) : Action::none;
        }
        if (stopAccepted_)
            return exhausted_ || now < retryAt_ ? Action::none : begin(Action::start, now);
        if (stopFailed_ && running) return Action::none;
        if (!running) stopFailed_ = false;
        if (observed == 2) {
            confirmed_ = true;
            refresh();
            return Action::none;
        }
        if (confirmed_) {
            confirmed_ = false;
            fail(now, observed == 4 ? Failure::incomplete : Failure::aborted);
        } else if (observed == 4 && failure_ == Failure::none) fail(now, Failure::incomplete);
        if (running) return begin(Action::stop, now);
        if (exhausted_ || now < retryAt_) return Action::none;
        return begin(Action::start, now);
    }

    void commandSucceeded(Action action) noexcept {
        if (action == Action::start) stopAccepted_ = false;
        else if (action == Action::stop) {
            pending_ = Action::none;
            stopAccepted_ = true;
            confirmed_ = false;
            stopFailed_ = false;
        }
    }

    void commandFailed(std::uint64_t now, Action action) noexcept {
        if (action == Action::start) fail(now, Failure::startException);
        else {
            pending_ = Action::none;
            stopFailed_ = true;
            note(Failure::stopException);
        }
    }

    bool desired() const noexcept { return desired_; }
    bool started() const noexcept { return !stopAccepted_ && confirmed_ && pending_ == Action::none; }
    bool stopped() const noexcept { return stopAccepted_ && pending_ == Action::none; }
    Action pending() const noexcept { return pending_; }
    Failure failure() const noexcept { return failure_; }
    bool exhausted() const noexcept { return exhausted_ || stopFailed_; }
    unsigned retries() const noexcept { return retries_; }
    std::uint64_t retryAt() const noexcept { return retryAt_; }
    std::uint64_t failures() const noexcept { return failures_; }

private:
    Action begin(Action action, std::uint64_t now) noexcept {
        pending_ = action;
        deadline_ = now + operationLifetime;
        return action;
    }
    void note(Failure failure) noexcept { failure_ = failure; ++failures_; }
    void fail(std::uint64_t now, Failure failure) noexcept {
        pending_ = Action::none;
        note(failure);
        if (!desired_) return;
        if (retries_ == 3) { exhausted_ = true; retryAt_ = 0; return; }
        retryAt_ = now + (std::uint64_t{1000} << retries_);
        ++retries_;
    }
    bool desired_ = false;
    bool confirmed_ = false;
    bool exhausted_ = false;
    bool stopFailed_ = false;
    bool stopAccepted_ = true;
    Action pending_ = Action::none;
    Failure failure_ = Failure::none;
    unsigned retries_ = 0;
    std::uint64_t deadline_ = 0;
    std::uint64_t retryAt_ = 0;
    std::uint64_t failures_ = 0;
};

}
