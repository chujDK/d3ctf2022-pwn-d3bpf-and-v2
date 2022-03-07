#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include "bpf_def.h"

int bpf(int cmd, union bpf_attr *attrs)
{
    return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int create_map(union bpf_attr *map_attrs)
{
    return bpf(BPF_MAP_CREATE, map_attrs);
}

int update_map_element(int fd, uint64_t key, void *value, uint64_t flags)
{
    union bpf_attr attr = {};
    attr.map_fd = fd;
    attr.key = (uint64_t)&key;
    attr.value = (uint64_t)value;
    attr.flags = flags;
    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

int lookup_map_element(int fd, uint64_t key, void *value)
{
    union bpf_attr attr = {};
    attr.map_fd = fd;
    attr.key = (uint64_t)&key;
    attr.value = (uint64_t)value;
    return bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

int obj_get_info_by_fd(union bpf_attr *attrs)
{
    return bpf(BPF_OBJ_GET_INFO_BY_FD, attrs);
}

int map_get_next_key(union bpf_attr* attrs)
{
    return bpf(BPF_MAP_GET_NEXT_KEY, attrs);
}

int run_bpf_prog(struct bpf_insn* insn, uint32_t cnt, int* prog_fd_out, char* write_buf, size_t write_nbytes)
{
    int ret = -1;
    int prog_fd = -1;
    char verifier_log_buff[0x200000] = {0};
    int socks[2] = {0};
    union bpf_attr prog_attrs =
    {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = cnt,
        .insns = (uint64_t)insn,
        .license = (uint64_t)"",
        .log_level = 2,
        .log_size = sizeof(verifier_log_buff),
        .log_buf = (uint64_t)verifier_log_buff
    };

    if(NULL != prog_fd_out)
    {
        prog_fd = *prog_fd_out;
    }

    if(0 >= prog_fd)
    {
        prog_fd = bpf(BPF_PROG_LOAD, &prog_attrs);
    }

    if(0 > prog_fd)
    {
        puts(verifier_log_buff);
        goto done;
    }

    if(0 != socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    {
        goto done;
    }

    if(0 != setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(int)))
    {
        goto done;
    }

    if(write_nbytes != write(socks[1], write_buf, write_nbytes))
    {
        printf("[!] write not so good\n");
        goto done;
    }

    if(NULL != prog_fd_out)
    {
        *prog_fd_out = prog_fd;
    }

    else
    {
        close(prog_fd);
    }

    ret = 0;

done:
    close(socks[0]);
    close(socks[1]);
    return ret;
}