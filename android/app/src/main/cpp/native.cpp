#include <jni.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include "core.hpp"

static std::string text(JNIEnv* env, jstring value) {
    const char* raw = env->GetStringUTFChars(value, nullptr);
    if (!raw) return {};
    std::string result(raw);
    env->ReleaseStringUTFChars(value, raw);
    return result;
}
extern "C" JNIEXPORT jstring JNICALL Java_dz_timo_bounty_NativeEngine_reviewSql(JNIEnv* env, jobject, jstring value) {
    auto lines = sql_lines(text(env, value));
    std::string result;
    for (auto line : lines) result += std::to_string(line) + "\n";
    return env->NewStringUTF(result.c_str());
}
extern "C" JNIEXPORT jstring JNICALL Java_dz_timo_bounty_NativeEngine_tcpConnect(JNIEnv* env, jobject, jstring value, jint port) {
    std::string ip = text(env, value);
    if (port != 80 && port != 443 && port != 8000 && port != 8080 && port != 8443) return env->NewStringUTF("blocked");
    sockaddr_storage storage{};
    socklen_t length;
    int family;
    auto* ipv4 = reinterpret_cast<sockaddr_in*>(&storage);
    auto* ipv6 = reinterpret_cast<sockaddr_in6*>(&storage);
    if (inet_pton(AF_INET, ip.c_str(), &ipv4->sin_addr) == 1) {
        family = AF_INET; ipv4->sin_family = AF_INET; ipv4->sin_port = htons(port); length = sizeof(sockaddr_in);
    } else if (inet_pton(AF_INET6, ip.c_str(), &ipv6->sin6_addr) == 1) {
        family = AF_INET6; ipv6->sin6_family = AF_INET6; ipv6->sin6_port = htons(port); length = sizeof(sockaddr_in6);
    } else return env->NewStringUTF("invalid-address");
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) return env->NewStringUTF("socket-error");
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) { close(fd); return env->NewStringUTF("socket-error"); }
    int status = connect(fd, reinterpret_cast<sockaddr*>(&storage), length);
    const char* result = "closed-or-filtered";
    if (status == 0) result = "open";
    else if (errno == EINPROGRESS) {
        pollfd descriptor{fd, POLLOUT, 0};
        int ready = poll(&descriptor, 1, 4000);
        int error = 1;
        socklen_t size = sizeof(error);
        if (ready > 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0) result = "open";
        else if (ready == 0) result = "timeout";
    }
    close(fd);
    return env->NewStringUTF(result);
}
