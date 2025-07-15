#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>

// Para incluir os syscall especificos do sistema usado.
const char* syscall_names[] = {
    #include "syscall_names.h"
};

#define MAX_SYSCALL 548  // Número máximo de syscalls conhecidas no x86_64


//lista os processos baseado no diretorio /proc do linux.
void listar_processos() {
    DIR* proc = opendir("/proc");
    struct dirent* ent;

    printf("\nProcessos em execução:\n");
    printf("PID\tComando\n");

    while ((ent = readdir(proc)) != NULL) {
        if (!isdigit(ent->d_name[0]))
            continue;

        int pid = atoi(ent->d_name);
        char cmdline[256] = {0};
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

        FILE* f = fopen(path, "r");
        if (f) {
            fread(cmdline, 1, sizeof(cmdline), f);
            fclose(f);
            if (strlen(cmdline) > 0)
                printf("%d\t%s\n", pid, cmdline);
        }
    }

    closedir(proc);
}

//funcao para cumprir a exigencia de timestamp
char* get_timestamp() {
    static char buffer[32];
    time_t rawtime;
    struct tm* timeinfo;
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    rawtime = ts.tv_sec;
    timeinfo = localtime(&rawtime);

    snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d.%03ld",
             timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, ts.tv_nsec / 1000000);

    return buffer;
}

//funcao que pega os syscall do processo realmente utilizando do ptrace
void monitorar_pid(pid_t pid) {
    FILE* logfile = fopen("log.txt", "w");
    if (!logfile) {
        perror("fopen");
        exit(1);
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        fclose(logfile);
        exit(1);
    }

    waitpid(pid, NULL, 0);
    fprintf(logfile, "Monitorando PID: %d\n\n", pid);
    printf("Monitorando PID: %d\n\n", pid);

    int in_syscall = 0;
    struct user_regs_struct regs;

    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        waitpid(pid, NULL, 0);

        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) break;

        if (!in_syscall) {
            long syscall_num = regs.orig_rax;
            if (syscall_num < 0 || syscall_num >= MAX_SYSCALL) continue;

            const char* name = syscall_names[syscall_num];
            char* timestamp = get_timestamp();

            fprintf(logfile, "[%s] PID %d - %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
                    timestamp, pid, name,
                    regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
            printf( "[%s] PID %d - %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
                    timestamp, pid, name,
                    regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
            fflush(logfile);
        } else {
            char* timestamp = get_timestamp();
            fprintf(logfile, "[%s] PID %d - Retorno: 0x%llx\n", timestamp, pid, regs.rax);
            printf( "[%s] PID %d - Retorno: 0x%llx\n", timestamp, pid, regs.rax);
            fflush(logfile);
        }

        in_syscall = 1 - in_syscall;
    }

    fclose(logfile);
    printf("Monitoramento encerrado.\n");
}

// funcao que usa as funcoes.
int main() {
    listar_processos();

    printf("\nDigite o PID do processo que deseja monitorar: ");
    int pid;
    scanf("%d", &pid);

    if (kill(pid, 0) == -1 && errno == ESRCH) {
        fprintf(stderr, "Erro: processo com PID %d não existe.\n", pid);
        return 1;
    }

    printf("Iniciando monitoramento do processo %d...\n", pid);
    monitorar_pid(pid);

    return 0;
}
