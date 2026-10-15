#include "SceTypes.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
int APS5_VABI scePthreadCreate(Pthread* thread, const PthreadAttr* attr, PthreadEntry entry, void* arg, const char* name);
int APS5_VABI scePthreadJoin(Pthread thread, void** retval);
int APS5_VABI scePthreadDetach(Pthread thread);
int APS5_VABI pthread_join_nid_postfix(Pthread thread, void** value);
int APS5_VABI pthread_detach_nid_postfix(Pthread thread);
void APS5_VABI scePthreadExit(void* retval);
Pthread APS5_VABI scePthreadSelf();
int APS5_VABI scePthreadGetthreadid(void);
int APS5_VABI pthread_getthreadid_np_nid_postfix(void);
void APS5_VABI scePthreadTestcancel();
void APS5_VABI pthread_testcancel_nid_postfix(void);
int APS5_VABI scePthreadSetcancelstate(int state, int* old_state);
int APS5_VABI scePthreadSetcanceltype(int type, int* old_type);
void APS5_VABI pthread_set_name_np_nid_postfix(Pthread thread, const char* name);
int APS5_VABI scePthreadGetname(Pthread thread, char* name);
int APS5_VABI scePthreadMutexattrInit(PthreadMutexattr* attr);
int APS5_VABI scePthreadMutexattrDestroy(PthreadMutexattr* attr);
int APS5_VABI scePthreadMutexattrSettype(PthreadMutexattr* attr, int type);
int APS5_VABI scePthreadMutexInit(PthreadMutex* mutex, const PthreadMutexattr* attr, const char* name);
int APS5_VABI scePthreadMutexDestroy(PthreadMutex* mutex);
int APS5_VABI scePthreadMutexLock(PthreadMutex* mutex);
int APS5_VABI scePthreadMutexUnlock(PthreadMutex* mutex);
int APS5_VABI scePthreadAttrInit(PthreadAttr* attr);
int APS5_VABI scePthreadAttrDestroy(PthreadAttr* attr);
int APS5_VABI scePthreadAttrGet(Pthread thread, PthreadAttr* attr);
int APS5_VABI scePthreadAttrGetstackaddr(const PthreadAttr* attr, void** stack_addr);
int APS5_VABI scePthreadAttrGetstacksize(const PthreadAttr* attr, size_t* stack_size);
}

static bool StackContains(Pthread thread, const void* address, std::uintptr_t* beginOut = nullptr, std::size_t* sizeOut = nullptr) {
    PthreadAttr attr = nullptr;
    void* stack = nullptr;
    size_t size = 0;
    const bool queried = scePthreadAttrInit(&attr) == 0 && scePthreadAttrGet(thread, &attr) == 0 &&
        scePthreadAttrGetstackaddr(&attr, &stack) == 0 && scePthreadAttrGetstacksize(&attr, &size) == 0;
    if (attr) scePthreadAttrDestroy(&attr);
    const auto begin = reinterpret_cast<std::uintptr_t>(stack);
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    if (beginOut) *beginOut = begin;
    if (sizeOut) *sizeOut = size;
    return queried && stack != nullptr && size != 0 && value >= begin && value - begin < size;
}

static constexpr int SCE_OK = 0;
static constexpr int SCE_KERNEL_ERROR_EINVAL = 0x80020016;
static constexpr int SCE_KERNEL_ERROR_EPERM = 0x80020001;
static constexpr int SCE_KERNEL_ERROR_EDEADLK = 0x8002000b;
static constexpr int GUEST_EDEADLK = 11;
static constexpr int GUEST_EINVAL = 22;
static constexpr int MUTEX_TYPE_RECURSIVE = 2;
static constexpr int PTHREAD_CANCEL_ENABLE = 0;
static constexpr int PTHREAD_CANCEL_ASYNCHRONOUS = 2;
static constexpr std::intptr_t WorkerRetval = 0x1234;

static void Require(bool value, const char* check) {
    if (value) return;
    std::fprintf(stderr, "guest_thread_self: require failed: %s\n", check);
    std::fflush(nullptr);
    std::abort();
}

#define RequireCheck(expression) Require(static_cast<bool>(expression), #expression)

static std::int64_t ThreadIdField(Pthread thread) {
    std::int64_t tid = 0;
    std::memcpy(&tid, static_cast<const void*>(thread), sizeof(tid));
    return tid;
}

struct WorkerContext {
    Pthread thread = nullptr;
    Pthread selfFromWorker = nullptr;
    std::int64_t workerTid = 0;
    int workerThreadId = 0;
    int workerPosixThreadId = 0;
    bool workerStackReported = false;
    std::uintptr_t workerLocal = 0;
    std::uintptr_t workerStackBegin = 0;
    std::size_t workerStackBytes = 0;
    PthreadMutex* mutex = nullptr;
    int unlockResult = 0;
    bool testcancelReturned = false;
    int sceJoinSelf = 0;
    int posixJoinSelf = 0;
};

static void* APS5_VABI Worker(void* arg) {
    auto& context = *static_cast<WorkerContext*>(arg);
    context.selfFromWorker = scePthreadSelf();
    context.workerTid = ThreadIdField(context.selfFromWorker);
    context.workerThreadId = scePthreadGetthreadid();
    context.workerPosixThreadId = pthread_getthreadid_np_nid_postfix();
    int local = 0;
    context.workerLocal = reinterpret_cast<std::uintptr_t>(&local);
    context.workerStackReported = StackContains(context.selfFromWorker, &local, &context.workerStackBegin, &context.workerStackBytes);
    context.unlockResult = scePthreadMutexUnlock(context.mutex);
    context.sceJoinSelf = scePthreadJoin(context.selfFromWorker, nullptr);
    context.posixJoinSelf = pthread_join_nid_postfix(context.selfFromWorker, nullptr);
    int oldState = -1;
    int oldType = -1;
    context.testcancelReturned = scePthreadSetcancelstate(PTHREAD_CANCEL_ENABLE, &oldState) == SCE_OK &&
        scePthreadSetcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldType) == SCE_OK;
    scePthreadTestcancel();
    pthread_testcancel_nid_postfix();
    context.testcancelReturned = context.testcancelReturned && oldState == PTHREAD_CANCEL_ENABLE;
    scePthreadExit(reinterpret_cast<void*>(WorkerRetval));
    return nullptr;
}

int main() {
    const Pthread mainSelf = scePthreadSelf();
    RequireCheck(mainSelf != nullptr);
    RequireCheck(scePthreadSelf() == mainSelf);
    const std::int64_t mainTid = ThreadIdField(mainSelf);
    RequireCheck(mainTid != 0);
    RequireCheck(scePthreadGetthreadid() == static_cast<int>(mainTid));
    RequireCheck(pthread_getthreadid_np_nid_postfix() == static_cast<int>(mainTid));
    int local = 0;
    RequireCheck(StackContains(mainSelf, &local));
    RequireCheck(scePthreadJoin(mainSelf, nullptr) == SCE_KERNEL_ERROR_EINVAL);
    RequireCheck(scePthreadDetach(mainSelf) == SCE_KERNEL_ERROR_EINVAL);
    RequireCheck(scePthreadJoin(nullptr, nullptr) == SCE_KERNEL_ERROR_EINVAL);
    RequireCheck(scePthreadDetach(nullptr) == SCE_KERNEL_ERROR_EINVAL);
    RequireCheck(pthread_join_nid_postfix(nullptr, nullptr) == GUEST_EINVAL);
    RequireCheck(pthread_detach_nid_postfix(nullptr) == GUEST_EINVAL);

    PthreadMutexattr attr = nullptr;
    RequireCheck(scePthreadMutexattrInit(&attr) == SCE_OK);
    RequireCheck(scePthreadMutexattrSettype(&attr, MUTEX_TYPE_RECURSIVE) == SCE_OK);
    PthreadMutex mutex = nullptr;
    RequireCheck(scePthreadMutexInit(&mutex, &attr, nullptr) == SCE_OK);
    RequireCheck(scePthreadMutexattrDestroy(&attr) == SCE_OK);

    RequireCheck(scePthreadMutexLock(&mutex) == SCE_OK);

    WorkerContext context;
    context.mutex = &mutex;
    RequireCheck(scePthreadCreate(&context.thread, nullptr, Worker, &context, nullptr) == SCE_OK);
    RequireCheck(context.thread != nullptr);
    RequireCheck(context.thread != mainSelf);

    void* result = nullptr;
    RequireCheck(scePthreadJoin(context.thread, &result) == SCE_OK);
    std::fprintf(stderr,
        "guest_thread_self: after join result=0x%llx self=%p thread=%p main=%p tid=%lld workerTid=%lld workerThreadId=%d posixTid=%d unlock=0x%x sceJoin=0x%x posixJoin=%d stack=%d local=0x%llx begin=0x%llx size=0x%zx testcancel=%d\n",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(result)),
        static_cast<void*>(context.selfFromWorker),
        static_cast<void*>(context.thread),
        static_cast<void*>(mainSelf),
        static_cast<long long>(mainTid),
        static_cast<long long>(context.workerTid),
        context.workerThreadId,
        context.workerPosixThreadId,
        static_cast<unsigned>(context.unlockResult),
        static_cast<unsigned>(context.sceJoinSelf),
        context.posixJoinSelf,
        context.workerStackReported ? 1 : 0,
        static_cast<unsigned long long>(context.workerLocal),
        static_cast<unsigned long long>(context.workerStackBegin),
        context.workerStackBytes,
        context.testcancelReturned ? 1 : 0);
    std::fflush(nullptr);
    RequireCheck(reinterpret_cast<std::intptr_t>(result) == WorkerRetval);
    RequireCheck(context.selfFromWorker != nullptr);
    RequireCheck(context.selfFromWorker == context.thread);
    RequireCheck(context.selfFromWorker != mainSelf);
    RequireCheck(context.workerTid != 0 && context.workerTid != mainTid);
    RequireCheck(context.workerThreadId == static_cast<int>(context.workerTid));
    RequireCheck(context.workerPosixThreadId == context.workerThreadId && context.workerPosixThreadId != static_cast<int>(mainTid));
    RequireCheck(context.unlockResult == SCE_KERNEL_ERROR_EPERM);
    RequireCheck(context.sceJoinSelf == SCE_KERNEL_ERROR_EDEADLK);
    RequireCheck(context.posixJoinSelf == GUEST_EDEADLK);
    RequireCheck(context.workerStackReported);
    RequireCheck(context.testcancelReturned);

    scePthreadTestcancel();
    pthread_testcancel_nid_postfix();

    RequireCheck(scePthreadMutexUnlock(&mutex) == SCE_OK);
    RequireCheck(scePthreadMutexDestroy(&mutex) == SCE_OK);

    char name[32] = {'x'};
    pthread_set_name_np_nid_postfix(mainSelf, "q2-main");
    RequireCheck(scePthreadGetname(mainSelf, name) == SCE_OK && std::strcmp(name, "q2-main") == 0);
    pthread_set_name_np_nid_postfix(mainSelf, nullptr);
    RequireCheck(scePthreadGetname(mainSelf, name) == SCE_OK && name[0] == '\0');
    pthread_set_name_np_nid_postfix(nullptr, "ignored");

}
