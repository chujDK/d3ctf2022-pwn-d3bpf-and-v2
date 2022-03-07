#ifndef _TASK_STRUCT_SEARCH_H_
#define _TASK_STRUCT_SEARCH_H_
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include "kernel_def.h"

uint64_t find_task_struct_by_pid_ns(int oob_map_fd, int store_map_fd, pid_t nr, struct pid_namespace *ns);

void read_kernel(int oob_map_fd, int store_map_fd, uint64_t start_addr, uint64_t len, void* buf);

#endif