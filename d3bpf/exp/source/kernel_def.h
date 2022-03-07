#ifndef _KERNEL_DEF_H_
#define _KERNEL_DEF_H_
#include <sys/types.h>

/* dummy define for some kernel struct */

static inline void *xa_mk_internal(unsigned long v)
{
	return (void *)((v << 2) | 2);
}

#define __rcu

#define CONFIG_BASE_SMALL   0
#define radix_tree_root		xarray
#define radix_tree_node		xa_node

#ifndef XA_CHUNK_SHIFT
#define XA_CHUNK_SHIFT		(CONFIG_BASE_SMALL ? 4 : 6)
#endif
#define XA_CHUNK_SIZE		(1UL << XA_CHUNK_SHIFT)
#define XA_CHUNK_MASK		(XA_CHUNK_SIZE - 1)
#define XA_MAX_MARKS		3
#define XA_MARK_LONGS		DIV_ROUND_UP(XA_CHUNK_SIZE, BITS_PER_LONG)
#define RADIX_TREE_MAP_SHIFT XA_CHUNK_SHIFT

#define RADIX_TREE_RETRY XA_RETRY_ENTRY
#define XA_RETRY_ENTRY		xa_mk_internal(256)
#define RADIX_TREE_MAP_SIZE	(1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK (RADIX_TREE_MAP_SIZE-1)

/*
 * @count is the count of every non-NULL element in the ->slots array
 * whether that is a value entry, a retry entry, a user pointer,
 * a sibling entry or a pointer to the next level of the tree.
 * @nr_values is the count of every element in ->slots which is
 * either a value entry or a sibling of a value entry.
 */
struct xa_node {
	unsigned char	shift;		/* Bits remaining in each slot */
	unsigned char	offset;		/* Slot offset in parent */
	unsigned char	count;		/* Total entry count */
	unsigned char	nr_values;	/* Value entry count */
	struct xa_node __rcu *parent;	/* NULL at top of tree */
	struct xarray	*array;		/* The array we belong to */
    char filler[0x10];
	void __rcu	*slots[XA_CHUNK_SIZE];
};

struct xarray {
    int32_t    xa_lock;
    int32_t    xa_flags;
    void __rcu *xa_head;
};

struct idr {
	struct radix_tree_root	idr_rt;
	unsigned int		idr_base;
	unsigned int		idr_next;
};

struct pid_namespace 
{
    struct idr idr;
};

#endif