/*
 * test_tags.c — Tests for pool tag tracking system
 *
 * Verifies:
 *   INV-TAG-1: alloc_count >= free_count
 *   INV-TAG-2: active_count == alloc_count - free_count
 *   INV-TAG-3: At shutdown, active_count == 0 (no leaks)
 *   INV-TAG-4: peak_count >= active_count
 *
 * Author: G.H. Murray
 * Date:   2026-02-17
 */

#define _GNU_SOURCE
#include "slab.h"
#include "slab_tags.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

static void test_basic_tracking(void)
{
    printf("  test_basic_tracking...");

    slab_tags_init();

    struct slab_cache *cache = slab_cache_create("tag_test", 64, 0, 0, NULL, NULL);
    assert(cache);

    /* Allocate 10 objects with tag "Test" */
    void *objs[10];
    for (int i = 0; i < 10; i++) {
        objs[i] = slab_alloc_tagged(cache, "Test");
        assert(objs[i]);
    }

    /* Check stats */
    const struct slab_tag_stats *s = slab_tag_lookup(SLAB_TAG('T','e','s','t'));
    assert(s);
    assert(s->alloc_count == 10);
    assert(s->free_count == 0);
    assert(s->active_count == 10);
    assert(s->peak_count == 10);

    /* Free 5 */
    for (int i = 0; i < 5; i++)
        slab_free_tagged(cache, objs[i], "Test");

    assert(s->alloc_count == 10);
    assert(s->free_count == 5);
    assert(s->active_count == 5);
    assert(s->peak_count == 10);  /* peak unchanged */

    /* Free remaining */
    for (int i = 5; i < 10; i++)
        slab_free_tagged(cache, objs[i], "Test");

    assert(s->active_count == 0);
    assert(s->peak_count == 10);

    slab_cache_destroy(cache);
    slab_tags_fini();  /* Should print "no leaks" */

    printf(" OK\n");
}

static void test_multiple_tags(void)
{
    printf("  test_multiple_tags...");

    slab_tags_init();

    struct slab_cache *cache = slab_cache_create("multi_tag", 128, 0, 0, NULL, NULL);
    assert(cache);

    void *creatures[5], *items[3];

    for (int i = 0; i < 5; i++)
        creatures[i] = slab_alloc_tagged(cache, "Crea");
    for (int i = 0; i < 3; i++)
        items[i] = slab_alloc_tagged(cache, "Item");

    const struct slab_tag_stats *crea = slab_tag_lookup(SLAB_TAG('C','r','e','a'));
    const struct slab_tag_stats *item = slab_tag_lookup(SLAB_TAG('I','t','e','m'));
    assert(crea && crea->active_count == 5);
    assert(item && item->active_count == 3);

    for (int i = 0; i < 5; i++)
        slab_free_tagged(cache, creatures[i], "Crea");
    for (int i = 0; i < 3; i++)
        slab_free_tagged(cache, items[i], "Item");

    assert(crea->active_count == 0);
    assert(item->active_count == 0);

    slab_cache_destroy(cache);
    slab_tags_fini();

    printf(" OK\n");
}

struct mt_args {
    struct slab_cache *cache;
    int count;
    const char *tag;
};

static void *mt_alloc_free(void *arg)
{
    struct mt_args *a = arg;
    void *objs[100];

    for (int iter = 0; iter < 50; iter++) {
        int n = (iter % a->count) + 1;
        for (int i = 0; i < n; i++) {
            objs[i] = slab_alloc_tagged(a->cache, a->tag);
            assert(objs[i]);
        }
        for (int i = 0; i < n; i++)
            slab_free_tagged(a->cache, objs[i], a->tag);
    }

    return NULL;
}

static void test_mt_tags(void)
{
    printf("  test_mt_tags...");

    slab_tags_init();

    struct slab_cache *cache = slab_cache_create("mt_tag", 64, 0, 0, NULL, NULL);
    assert(cache);

    pthread_t threads[4];
    struct mt_args args[4];
    const char *tags[] = {"Net1", "Net2", "Comp", "DBase"};

    for (int i = 0; i < 4; i++) {
        args[i] = (struct mt_args){cache, 20, tags[i]};
        pthread_create(&threads[i], NULL, mt_alloc_free, &args[i]);
    }
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);

    /* All freed — every tag should have active_count == 0 */
    for (int i = 0; i < 4; i++) {
        slab_tag_t t = SLAB_TAG(tags[i][0], tags[i][1], tags[i][2], tags[i][3]);
        const struct slab_tag_stats *s = slab_tag_lookup(t);
        assert(s);
        assert(s->active_count == 0);
        assert(s->alloc_count == s->free_count);
        /* INV-TAG-4: peak >= 0 (always true but verify peak was recorded) */
        assert(s->peak_count >= 1);
    }

    slab_tag_report(true);

    slab_cache_destroy(cache);
    slab_tags_fini();

    printf(" OK\n");
}

int main(void)
{
    printf("=== Pool Tag Tracking Tests ===\n");
    slab_system_init();

    test_basic_tracking();
    test_multiple_tags();
    test_mt_tags();

    slab_system_fini();
    printf("All tag tests passed.\n");
    return 0;
}
