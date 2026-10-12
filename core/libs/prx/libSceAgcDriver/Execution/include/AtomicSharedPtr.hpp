#ifndef CORE_LIBS_PRX_LIBSCEAGCDRIVER_EXECUTION_INCLUDE_ATOMICSHAREDPTR_HPP
#define CORE_LIBS_PRX_LIBSCEAGCDRIVER_EXECUTION_INCLUDE_ATOMICSHAREDPTR_HPP

#include <atomic>
#include <memory>
#if defined(__APPLE__)
#include <mutex>
#endif

#if !defined(__APPLE__)
template<class T>
using AtomicSharedPtr = std::atomic<std::shared_ptr<T>>;
#else
template<class T>
class AtomicSharedPtr {
public:
    AtomicSharedPtr() = default;
    AtomicSharedPtr(const AtomicSharedPtr&) = delete;
    AtomicSharedPtr& operator=(const AtomicSharedPtr&) = delete;

    std::shared_ptr<T> load(std::memory_order = std::memory_order_seq_cst) const {
        std::lock_guard lock(mutex);
        return value;
    }

    void store(std::shared_ptr<T> next, std::memory_order = std::memory_order_seq_cst) {
        std::lock_guard lock(mutex);
        value = std::move(next);
    }

    std::shared_ptr<T> exchange(std::shared_ptr<T> next, std::memory_order = std::memory_order_seq_cst) {
        std::lock_guard lock(mutex);
        value.swap(next);
        return next;
    }

private:
    mutable std::mutex mutex;
    std::shared_ptr<T> value;
};
#endif

#endif
