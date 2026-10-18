#include "prx/libSceAgcDriver/Execution/include/Driver/Driver.hpp"
#include "prx/libSceAgcDriver/Execution/include/DisplayBuffer.hpp"
#include "prx/libSceAgcDriver/Execution/include/Driver/Diagnostics.hpp"
#include "prx/libSceAgcDriver/Execution/include/Driver/Shaders/ShaderRegistry.hpp"
#include "prx/libSceAgcDriver/Execution/include/GuestMemory.hpp"
#include "prx/libSceAgcDriver/Execution/include/WorkerSampler.hpp"
#include "prx/libSceAgcDriver/Execution/include/ProfileOutput.hpp"
#include "prx/libSceAgcDriver/Graphics/include/GuestBufferMemory.hpp"
#include "prx/libc/include/GuestAllocations.hpp"
#include <chrono>
#include <cstdio>
#include <thread>

namespace AgcDriver::DriverDetail {

Driver& Driver::Get() {
    static Driver driver;
    return driver;
}

Driver::~Driver() {
    GuestAllocations::GuestAllocationsSetGpuMapObserver_nid_postfix(nullptr);
    stop();
}

void Driver::Shutdown() {
    stop();
    if (LibcHostShutdownAbandoned_nid_no_patch()) LibcTerminate_nid_no_patch(LibcExitCode_nid_no_patch());
    std::lock_guard lock(mutex);
    rethrowFailure();
}

namespace {

template <typename Mutex>
void LockOrEndIfAbandoned(Mutex& mutex) {
    while (!mutex.try_lock()) {
        if (LibcHostShutdownAbandoned_nid_no_patch()) LibcTerminate_nid_no_patch(LibcExitCode_nid_no_patch());
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

}

void Driver::stop() {
    if (LibcHostShutdownAbandoned_nid_no_patch()) LibcTerminate_nid_no_patch(LibcExitCode_nid_no_patch());
    require(!onWorkerThread(), "worker cannot stop itself");
    LockOrEndIfAbandoned(shutdownMutex);
    std::lock_guard shutdownLock(shutdownMutex, std::adopt_lock);
    if (stopped) return;
    LibcRequestShutdown_nid_postfix();
    LockOrEndIfAbandoned(mutex);
    {
        std::lock_guard lock(mutex, std::adopt_lock);
        stopping = true;
        for (auto& [queue, worker] : workers) {
            worker.pending.clear();
            worker.unfinishedWrites.clear();
            worker.queued.store(0, std::memory_order_release);
        }
    }
    changed.notify_all();
    for (auto& [queue, worker] : workers) {
        if (!worker.thread.joinable()) continue;
        while (!worker.exited.load(std::memory_order_acquire)) {
            if (LibcHostShutdownAbandoned_nid_no_patch()) {
                worker.thread.detach();
                LibcTerminate_nid_no_patch(LibcExitCode_nid_no_patch());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        worker.thread.join();
    }
    if (LibcHostShutdownAbandoned_nid_no_patch()) LibcTerminate_nid_no_patch(LibcExitCode_nid_no_patch());
    StopWorkerSampler();
    CloseRegistrationPreparation();
    LockOrEndIfAbandoned(GuestMemory::GpuMutex());
    std::lock_guard gpuLock(GuestMemory::GpuMutex(), std::adopt_lock);
    device.Reset();
    replacedDevices.clear();
    Graphics::ShutdownGuestBufferWorkers();
    StopProfileOutput_nid_no_patch();
    stopped = true;
}

Driver::Driver() {
    static_cast<void>(GuestMemory::TrackerGeneration());
    ShaderMemory::SetWaitedMsProvider(&Graphics::Recorder::ThreadWaitedMs);
    try {
        LibcRegisterShutdown_nid_postfix([] { Driver::Get().Shutdown(); });
        LibcRegisterProcessExitFlush_nid_postfix(AgcDriverDrainFrameDumps_nid_no_patch);
    } catch (...) {
        stop();
        throw;
    }
    GuestAllocations::GuestAllocationsSetGpuMapObserver_nid_postfix([](const GuestAllocations::Mapped& ranges, std::uint64_t generation) {
        try {
            const auto current = Driver::Get().device.Load();
            if (current == nullptr || current->ImportGuestMemory(ranges, generation, false)) return;
            std::lock_guard lock(GuestMemory::GpuMutex());
            if (Driver::Get().device.Load() == current) current->ImportGuestMemory(ranges, generation, true);
        } catch (const std::exception& error) {
            std::fprintf(stderr, "[gpu] import of GPU memory at its mapping failed: %s\n", error.what());
        }
    });
}

void Driver::WaitIdle() {
    require(!onWorkerThread(), "worker cannot wait for itself");
    std::unique_lock lock(mutex);
    const auto target = accepted;
    ++idleWaiters;
    changed.wait(lock, [&] { return failure != nullptr || stopping || completed >= target; });
    --idleWaiters;
    rethrowFailure();
    checkStopping();
}

void Driver::CheckFailure() {
    if (failed.load(std::memory_order_acquire)) {
        std::lock_guard lock(mutex);
        rethrowFailure();
    }
    checkStopping();
}

void Driver::ReportFailure(std::exception_ptr error) {
    require(error != nullptr, "null asynchronous failure");
    {
        std::lock_guard lock(mutex);
        if (!failure) failure = error;
        failed.store(true, std::memory_order_release);
        for (const auto& [handle, output] : outputs) output->Fail(failure);
        for (auto& [queue, worker] : workers) {
            for (const auto& item : worker.pending) {
                for (const auto& [offset, flip] : item.flips) flip->Fail(failure);
            }
            worker.pending.clear();
            worker.unfinishedWrites.clear();
            worker.queued.store(0, std::memory_order_release);
        }
    }
    changed.notify_all();
}

void Driver::rethrowFailure() const {
    if (failure != nullptr) {
        std::rethrow_exception(failure);
    }
}

void Driver::checkStopping() const {
    if (stopping.load(std::memory_order_acquire) || shutdownToken.stop_requested()) throw ProcessShutdown{};
}

bool& Driver::onWorkerThread() {
    static thread_local bool worker = false;
    return worker;
}

}
