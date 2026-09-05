#include <android/log.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "native-target", __VA_ARGS__)

/* Known exported symbol for Module.findExportByName tests. */
__attribute__((visibility("default")))
int goauld_target_add(int a, int b) {
    return a + b;
}

int main(void) {
    LOGI("native-target up, pid=%d", getpid());
    const char *msgs[] = {"hello", "goauld", "strlen-probe", NULL};
    for (;;) {
        for (int i = 0; msgs[i]; i++) {
            size_t n = strlen(msgs[i]);
            LOGI("strlen(%s) = %zu; add(1,2)=%d", msgs[i], n, goauld_target_add(1, 2));
        }
        sleep(2);
    }
    return 0;
}
