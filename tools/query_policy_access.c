/* Offline access-vector query. Loads a policy into libsepol, never the kernel. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb/services.h>

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: policy source-context target-context class permission\n");
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f || fseek(f, 0, SEEK_END)) return 2;
    long length = ftell(f);
    if (length <= 0 || length > 64*1024*1024 || fseek(f, 0, SEEK_SET)) return 2;
    void *data = malloc((size_t)length);
    if (!data || fread(data, 1, (size_t)length, f) != (size_t)length) return 2;
    fclose(f);
    if (sepol_load_policy(data, (size_t)length)) return 2;
    sepol_security_id_t source, target;
    sepol_security_class_t cls;
    sepol_access_vector_t requested;
    struct sepol_av_decision decision;
    unsigned reason = 0;
    if (sepol_context_to_sid(argv[2], strlen(argv[2])+1, &source) ||
        sepol_context_to_sid(argv[3], strlen(argv[3])+1, &target) ||
        sepol_string_to_security_class(argv[4], &cls) ||
        sepol_string_to_av_perm(cls, argv[5], &requested) ||
        sepol_compute_av_reason(source, target, cls, requested, &decision, &reason)) return 2;
    int allowed = (decision.allowed & requested) == requested;
    printf("source=%s target=%s class=%s permission=%s allowed=%d reason=%u\n",
           argv[2], argv[3], argv[4], argv[5], allowed, reason);
    free(data);
    return 0; /* A denied query is a valid result, not a tool failure. */
}
