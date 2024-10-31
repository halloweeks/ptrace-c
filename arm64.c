#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <linux/ptrace.h>
#include <linux/elf.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <stdint.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <stdbool.h>

ssize_t read_memory(pid_t pid, void *address, void *value, size_t size) {
    struct iovec local[1];
    struct iovec remote[1];
    
    local[0].iov_base = value;
    local[0].iov_len = size;
    remote[0].iov_base = address;
    remote[0].iov_len = size;

    return syscall(__NR_process_vm_readv, pid, local, 1, remote, 1, 0);
}

ssize_t write_memory(pid_t pid, void *address, void *value, size_t size) {
    struct iovec local[1];
    struct iovec remote[1];
    
    local[0].iov_base = value;
    local[0].iov_len = size;
    remote[0].iov_base = address;
    remote[0].iov_len = size;

    return syscall(__NR_process_vm_writev, pid, local, 1, remote, 1, 0);
}

pid_t find_pid(const char *process_name) {
	DIR *dir = opendir("/proc");
	struct dirent *entry = NULL;
	char cmdline_path[256];
	char cmdline[256];
	int fd;
	
	if (dir == NULL) {
		return -1;
	}
	
	while ((entry = readdir(dir)) != NULL) {
		if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0) || (entry->d_type != DT_DIR) || (strspn(entry->d_name, "0123456789") != strlen(entry->d_name))) {
			continue;
		}
		snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
		fd = open(cmdline_path, O_RDONLY);
		read(fd, cmdline, 256);
		close(fd);
		
		/*
		if (strstr(cmdline, process_name) != NULL) {
			closedir(dir);
			return atoi(entry->d_name);
		}*/
		
		if (strncmp(cmdline, process_name, strlen(process_name)) == 0) {
			closedir(dir);
			return atoi(entry->d_name);
		}
	}
	closedir(dir);
	return -1;
}

const char *__symlink(pid_t pid, int fd) {
	static char symbolic_name[4096];
	char path[256];
	int len = -1;
	
	snprintf(path, 256,"/proc/%u/fd/%d", pid, fd);
	
	if ((len = readlink(path, symbolic_name, sizeof(symbolic_name))) > 0) {
		symbolic_name[len] = '\0';
	} else {
		symbolic_name[0] = '\0';
	}
	
	return symbolic_name;
}

void read_string(int pid, long addr, char *buffer) {
	unsigned int i = 0;
	char ch = 0;
	
	while (read_memory(pid, (void*)addr + i, &ch, 1) == 1) {
		if (ch == '\0') break;
		buffer[i++] = ch;
	}
	
	buffer[i] = '\0';
}


void trace_syscalls(pid_t target_pid) {
	int status;
	
	// Attach to the target process
	if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
		perror("ptrace(PTRACE_ATTACH)");
		exit(EXIT_FAILURE);
	}
	
	// Wait for the target process to stop
	waitpid(target_pid, &status, 0);
	printf("Tracing process %d\n", target_pid);
	
	struct iovec iov;
	struct user_pt_regs regs;
	
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	
	long syscall = -1;
	char filename[4096] = {0};
	
	while (1) {
		if (ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL) == -1) {
			perror("ptrace(PTRACE_SYSCALL)");
			break;
		}
		
		waitpid(target_pid, &status, 0);
		
		// Check if the target process has exited
		if (WIFEXITED(status)) {
			printf("Target process exited with status: %d\n", WEXITSTATUS(status));
			break;
		}
		
		// onEnter
		if (ptrace(PTRACE_GETREGSET, target_pid, NT_PRSTATUS, &iov) == -1) {
			perror("ptrace(PTRACE_GETREGSET)");
			break;
		}
		
		// Check the syscall number (x8 on ARM64)
		syscall = regs.regs[8]; // x8 contains the syscall number
		
		// intercept syscall read function 
		if (syscall == __NR_openat) {
			printf("\n\n\tonEnter\n\n");
			
			printf("file descriptor: %llu\n", regs.regs[0]);
			read_string(target_pid, regs.regs[1], filename);
			printf("file name: %s\n", filename);
			
			// printf("syscall entry!\n");
			// printf("syslink: %s\n", __symlink(target_pid, regs.regs[0]));
			// printf("file descriptor: %llu\n", regs.regs[0]);
			// printf("buff address: 0x%llx\n", regs.regs[1]);
			// printf("buff count: %llu\n\n\n", regs.regs[2]);
		}
		
		// Continue 
		ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);
		waitpid(target_pid, &status, 0);
		
		// onLeave
		
		// Get the register set to find out which syscall is being called
		if (ptrace(PTRACE_GETREGSET, target_pid, NT_PRSTATUS, &iov) == -1) {
			perror("ptrace(PTRACE_GETREGSET)");
			break;
		}
		
		// intercept syscall read function 
		if (syscall == __NR_openat) {
			printf("\n\n\tonLeave\n\n");
			printf("file descriptor: %llu\n", regs.regs[0]);
			read_string(target_pid, regs.regs[1], filename);
			printf("file name: %s\n", filename);
			
			// printf("syscall entry!\n");
			// printf("syslink: %s\n", __symlink(target_pid, regs.regs[0]));
			// printf("file descriptor: %llu\n", regs.regs[0]);
			// printf("buff address: 0x%llx\n", regs.regs[1]);
			// printf("buff count: %llu\n\n\n", regs.regs[2]);
		}
		
	}
	
	// Detach from the target process
	ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
}

/*
			// modify file descriptor it's an return value because read function entry time is an file descriptor but exit time is return number of bytes read.
			regs.regs[0] = -1;  // Set file descriptor to 0
                
               // Use PTRACE_SETREGSET to modify the registers in the target
               iov.iov_base = &regs;
                iov.iov_len = sizeof(regs);

                if (ptrace(PTRACE_SETREGSET, target_pid, NT_PRSTATUS, &iov) == -1) {
                    perror("ptrace(PTRACE_SETREGSET)");
				}
				*/

// cc /sdcard/AppProjects/halloweeks/app/src/main/assets/main.c -o /sdcard/AppProjects/halloweeks/app/src/main/assets/main -static -ffunction-sections -fdata-sections -Wl,--gc-sections

int main(int argc, const char *argv[]) {
	setbuf(stdout, NULL);
	
	if (argc != 2) {
		printf("usage: %s <process_name>\n", argv[0]);
		return 0;
	}
	
	// fflush(stdout);
	const char *process_name = argv[1];
    
	pid_t pid = -1;
	
	printf("[INFO] Waiting for opening '%s' process\n", process_name);
	
	while (pid == -1) {
		pid = find_pid(process_name);
	}
	
	printf("[INFO] Process '%s' is now open pid %d\n", process_name, pid);
	
	trace_syscalls(pid);
	
	return EXIT_SUCCESS;
}