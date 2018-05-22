/**
 * tc-classifier.h
 *
 * Toke Høiland-Jørgensen
 * 2018-05-21
 */

#ifndef TC_CLASSIFIER_H
#define TC_CLASSIFIER_H

#include <sys/types.h>
#include <stdint.h>
typedef uint8_t  u8;			/* Unsigned types of an exact size */
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

#endif
