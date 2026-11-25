/* Native single-rule regression tests: no /dev/pf access and no root needed. */
#include "../src/vendor/pf_abi.h"
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

static int fake_ioctl(int fd, unsigned long op, void *arg);
#define ioctl fake_ioctl
#define CLAUDEGUARD_ANCHOR_TEST
#include "../src/pf_anchor.c"

static struct pfioc_rule rules[32];
static unsigned count, ticket, mutations;
static int race, incompatible;

static void reset(void) {
    memset(rules, 0, sizeof(rules));
    count = 1; ticket = 10; mutations = 0; race = 0; incompatible = 0;
    strlcpy(rules[0].anchor_call, "com.apple.internet-sharing", sizeof(rules[0].anchor_call));
    rules[0].rule.evaluations = 1234;
    rules[0].rule.packets[0] = 99;
    rules[0].rule.action = PF_PASS;
}

static int fake_ioctl(int fd, unsigned long op, void *arg) {
    (void)fd;
    struct pfioc_rule *r = arg;
    if (incompatible) { errno = ENOTTY; return -1; }
    if (op == DIOCGETRULES) { r->nr = count; r->ticket = ticket; return 0; }
    if (op == DIOCGETRULE) {
        if (r->ticket != ticket || r->nr >= count) { errno = EBUSY; return -1; }
        unsigned index = r->nr;
        *r = rules[index]; r->nr = index; r->ticket = ticket;
        return 0;
    }
    if (op == DIOCBEGINADDRS) { ((struct pfioc_pooladdr *)arg)->ticket = 42; return 0; }
    assert(op == DIOCCHANGERULE);
    if (race) {
        race = 0;
        memmove(rules + 1, rules, count++ * sizeof(*rules));
        memset(rules, 0, sizeof(*rules));
        strlcpy(rules[0].anchor_call, "foreign-concurrent-vpn", sizeof(rules[0].anchor_call));
        ticket++;
    }
    if (r->ticket != ticket) { errno = EINVAL; return -1; }
    if (r->action == PF_CHANGE_ADD_HEAD) {
        assert(r->pool_ticket == 42);
        assert(ours(r));
        memmove(rules + 1, rules, count++ * sizeof(*rules));
        rules[0] = *r;
    } else {
        assert(r->action == PF_CHANGE_REMOVE && r->nr < count);
        assert(ours(&rules[r->nr]) || legacy_rule(&rules[r->nr]));
        memmove(rules + r->nr, rules + r->nr + 1, (count - r->nr - 1) * sizeof(*rules));
        count--;
    }
    ticket++; mutations++;
    return 0;
}

int main(void) {
    reset();
    struct pfioc_rule sharing = rules[0];
    assert(sync_anchor(0, 1) == 0 && count == 2 && ours(&rules[0]));
    assert(memcmp(&rules[1], &sharing, sizeof(sharing)) == 0);
    assert(sync_anchor(0, 1) == 0 && mutations == 1); /* idempotent */
    assert(sync_anchor(0, 0) == 0 && count == 1);
    assert(memcmp(&rules[0], &sharing, sizeof(sharing)) == 0);
    assert(sync_anchor(0, 0) == 0 && mutations == 2);

    reset();
    assert(sync_anchor(0, 1) == 0);
    race = 1; /* foreign insertion between our read and removal */
    assert(sync_anchor(0, 0) == 0 && count == 2);
    assert(strcmp(rules[0].anchor_call, "foreign-concurrent-vpn") == 0);
    assert(memcmp(&rules[1], &sharing, sizeof(sharing)) == 0);

    reset();
    race = 1;
    assert(sync_anchor(0, 1) == 0 && count == 3 && ours(&rules[0]));
    assert(strcmp(rules[1].anchor_call, "foreign-concurrent-vpn") == 0);
    assert(memcmp(&rules[2], &sharing, sizeof(sharing)) == 0);

    reset();
    strlcpy(rules[0].anchor_call, CG_ANCHOR, sizeof(rules[0].anchor_call));
    assert(sync_anchor(0, 1) == -1 && errno == EEXIST && mutations == 0);
    assert(sync_anchor(0, 0) == -1 && mutations == 0);

    reset(); incompatible = 1;
    assert(sync_anchor(0, 1) == -1 && mutations == 0);

    reset();
    memset(rules, 0, sizeof(rules)); count = 2;
    for (unsigned i = 0; i < 2; i++) {
        rules[i].rule.action = PF_DROP;
        rules[i].rule.direction = PF_OUT;
        rules[i].rule.quick = 1;
        rules[i].rule.proto = i ? IPPROTO_UDP : IPPROTO_TCP;
        rules[i].rule.dst.addr.type = 3;
        strlcpy(rules[i].rule.dst.addr.v.tblname, "claude_guard", PF_TABLE_NAME_SIZE);
    }
    assert(sync_anchor(0, 1) == 0 && count == 3);
    assert(migrate_legacy(0) == 0 && count == 1 && ours(&rules[0]));
    assert(migrate_legacy(0) == 0 && count == 1);
    reset();
    assert(migrate_legacy(0) == -1 && errno == EPERM && mutations == 0);
    puts("Native PF tests passed: foreign rule bytes/counters preserved, races rejected, scoped migration/cleanup");
    return 0;
}
