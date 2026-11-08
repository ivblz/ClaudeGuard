/* Touch only ClaudeGuard's root anchor call, never reload the root ruleset.
 * DIOCCHANGERULE compares the ruleset ticket under the kernel lock: a concurrent
 * Internet Sharing/VPN change fails the operation instead of deleting a rule
 * that has moved into the old index. See Apple's bsd/net/pf_ioctl.c.
 */
#include "vendor/pf_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CG_ANCHOR "com.claudeguard"
#define CG_LABEL "ClaudeGuard anchor"

_Static_assert(sizeof(struct pf_rule) == 1040, "Unexpected macOS PF rule ABI");
_Static_assert(sizeof(struct pfioc_rule) == 3104, "Unexpected macOS PF ioctl ABI");

struct snapshot {
    struct pfioc_rule *rules;
    unsigned count;
    unsigned ticket;
};

static int read_rules(int fd, struct snapshot *s) {
    struct pfioc_rule request = {0};
    request.rule.action = PF_PASS;
    if (ioctl(fd, DIOCGETRULES, &request) < 0) return -1;
    if (request.nr > 100000) { errno = EOVERFLOW; return -1; }
    s->count = request.nr;
    s->ticket = request.ticket;
    s->rules = calloc(s->count ? s->count : 1, sizeof(*s->rules));
    if (!s->rules) return -1;
    for (unsigned i = 0; i < s->count; i++) {
        struct pfioc_rule *r = &s->rules[i];
        r->rule.action = PF_PASS;
        r->ticket = s->ticket;
        r->nr = i;
        if (ioctl(fd, DIOCGETRULE, r) < 0) {
            free(s->rules);
            s->rules = NULL;
            return -1;
        }
    }
    return 0;
}

static int ours(const struct pfioc_rule *r) {
    return strcmp(r->anchor_call, CG_ANCHOR) == 0 &&
           strcmp(r->rule.label, CG_LABEL) == 0;
}

static int remove_rule(int fd, const struct snapshot *s, unsigned index) {
    struct pfioc_rule request = {0};
    request.rule.action = PF_PASS;
    request.action = PF_CHANGE_REMOVE;
    request.ticket = s->ticket;
    request.nr = index;
    return ioctl(fd, DIOCCHANGERULE, &request);
}

static int insert_anchor(int fd, unsigned ticket) {
    struct pfioc_pooladdr pool = {0};
    if (ioctl(fd, DIOCBEGINADDRS, &pool) < 0) return -1;
    struct pfioc_rule request = {0};
    request.action = PF_CHANGE_ADD_HEAD;
    request.ticket = ticket;
    request.pool_ticket = pool.ticket;
    request.rule.action = PF_PASS;
    request.rule.direction = PF_OUT;
    request.rule.quick = 1;
    strlcpy(request.anchor_call, CG_ANCHOR, sizeof(request.anchor_call));
    strlcpy(request.rule.label, CG_LABEL, sizeof(request.rule.label));
    return ioctl(fd, DIOCCHANGERULE, &request);
}

static int retryable(void) { return errno == EBUSY || errno == EINVAL; }

static int sync_anchor(int fd, int present) {
    for (int attempt = 0; attempt < 32; attempt++) {
        struct snapshot s = {0};
        if (read_rules(fd, &s) < 0) {
            if (errno == EBUSY) continue;
            return -1;  /* includes unsupported kernel ABI: never fall back to -f */
        }
        int found = -1, duplicate = -1;
        for (unsigned i = 0; i < s.count; i++) {
            if (ours(&s.rules[i])) {
                if (found < 0) found = (int)i;
                else duplicate = (int)i;
            } else if (strcmp(s.rules[i].anchor_call, CG_ANCHOR) == 0) {
                free(s.rules);
                errno = EEXIST; /* same name without our label is not ours */
                return -1;
            }
        }
        int result;
        if (present && found != 0) {
            // Insert before all foreign rules. If our older call moved down,
            // add the new call first and then remove only our duplicate.
            result = insert_anchor(fd, s.ticket);
        } else if (present && duplicate >= 0) {
            result = remove_rule(fd, &s, (unsigned)duplicate);
        } else if (!present && found >= 0) {
            result = remove_rule(fd, &s, (unsigned)found);
        } else {
            free(s.rules);
            return 0;
        }
        int saved = errno;
        free(s.rules);
        errno = saved;
        if (result < 0 && !retryable()) return -1;
    }
    errno = EBUSY;
    return -1;
}

static int legacy_rule(const struct pfioc_rule *r) {
    const struct pf_rule *p = &r->rule;
    struct pf_rule_addr any = {0};
    return !r->anchor_call[0] && !p->label[0] && !p->owner[0] &&
           p->action == PF_DROP && p->direction == PF_OUT && p->quick == 1 &&
           (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) && p->af == 0 &&
           !p->ifname[0] && !p->tagname[0] && !p->match_tagname[0] &&
           !p->uid.op && !p->gid.op && !p->prob && !p->keep_state &&
           memcmp(&p->src, &any, sizeof(any)) == 0 &&
           p->dst.addr.type == 3 /* PF_ADDR_TABLE */ &&
           strcmp(p->dst.addr.v.tblname, "claude_guard") == 0 &&
           !p->dst.neg && !p->dst.xport.range.op;
}

/* Invoked only after Python recognises the exact old two-rule text. Recheck
 * binary selectors too, and remove one old rule at a time by snapshot ticket. */
static int migrate_legacy(int fd) {
    for (int attempt = 0; attempt < 32; attempt++) {
        struct snapshot s = {0};
        if (read_rules(fd, &s) < 0) return -1;
        int target = -1;
        for (unsigned i = 0; i < s.count; i++) {
            if (ours(&s.rules[i])) continue;
            if (!legacy_rule(&s.rules[i])) {
                free(s.rules);
                errno = EPERM;
                return -1;
            }
            target = (int)i;
        }
        if (target < 0) { free(s.rules); return 0; }
        int result = remove_rule(fd, &s, (unsigned)target);
        int saved = errno;
        free(s.rules);
        errno = saved;
        if (result < 0 && !retryable()) return -1;
    }
    errno = EBUSY;
    return -1;
}

#ifndef CLAUDEGUARD_ANCHOR_TEST
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "ensure") && strcmp(argv[1], "remove") &&
                      strcmp(argv[1], "check") && strcmp(argv[1], "migrate-legacy"))) {
        fprintf(stderr, "usage: pf-anchor ensure|remove|check|migrate-legacy\n");
        return 2;
    }
    int check = strcmp(argv[1], "check") == 0;
    int fd = open("/dev/pf", check ? O_RDONLY : O_RDWR);
    if (fd < 0) { perror("pf-anchor: /dev/pf"); return 1; }
    int result;
    if (check) {
        struct snapshot s = {0};
        result = read_rules(fd, &s);
        if (result == 0) {
            printf("PF ABI readable; %u filter rules; rule size %zu\n", s.count, sizeof(struct pf_rule));
            free(s.rules);
        }
    } else if (strcmp(argv[1], "migrate-legacy") == 0) {
        result = migrate_legacy(fd);
    } else {
        result = sync_anchor(fd, strcmp(argv[1], "ensure") == 0);
    }
    if (result < 0) perror("pf-anchor: scoped rule operation failed");
    close(fd);
    return result < 0 ? 1 : 0;
}
#endif
