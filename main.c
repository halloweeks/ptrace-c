/***
detect when target program perform any system call for 'read' file descriptor 
***/

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


FILE *log_file;

/*
#ifndef process_vm_readv
	#include <sys/syscall.h>
	#include <asm/unistd.h>
	
	ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
		return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
	}
#endif
*/

#if !defined(process_vm_readv) && !defined(__USE_GNU) 
	extern ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
#endif


ssize_t read_memory(pid_t pid, void *address, void *value, size_t size) {
	struct iovec local[1];
	struct iovec remote[1];
	local[0].iov_base = value;
	local[0].iov_len = size;
	remote[0].iov_base = address;
	remote[0].iov_len = size;
	
	return process_vm_readv(pid, local, 1, remote, 1, 0);
}

void print_file_flags(int flags) {
    printf("Flags: ");
    
    fprintf(log_file, "Flags: ");
    
    if (flags == O_RDONLY) {
    	printf("O_RDONLY ");
        fprintf(log_file, "O_RDONLY ");
    }
    
    if (flags & O_WRONLY) {
    	printf("O_WRONLY ");
        fprintf(log_file, "O_WRONLY ");
    }
    
    if (flags & O_RDWR) {
    	printf("O_RDWR ");
        fprintf(log_file, "O_RDWR ");
    }
    
    if (flags & O_APPEND) {
    	printf("O_APPEND ");
        fprintf(log_file, "O_APPEND ");
    }
    
    if (flags & O_NONBLOCK) {
    	printf("O_NONBLOCK ");
        fprintf(log_file, "O_NONBLOCK ");
    }
    
    if (flags & O_CREAT) {
    	printf("O_CREAT ");
        fprintf(log_file, "O_CREAT ");
    }
    
    if (flags & O_EXCL) {
    	printf("O_EXCL ");
        fprintf(log_file, "O_EXCL ");
    }
    
    if (flags & O_TRUNC) {
    	printf("O_TRUNC ");
        fprintf(log_file, "O_TRUNC ");
    }
    
    if (flags & O_DIRECTORY) {
    	printf("O_DIRECTORY ");
        fprintf(log_file, "O_DIRECTORY ");
    }
    
    if (flags & O_NOCTTY) {
    	printf("O_NOCTTY ");
        fprintf(log_file, "O_NOCTTY ");
    }
    
    if (flags & O_SYNC) {
    	printf("O_SYNC ");
        fprintf(log_file, "O_SYNC ");
    }
    
    if (flags & O_DSYNC) {
    	printf("O_DSYNC ");
        fprintf(log_file, "O_DSYNC ");
    }
    
    if (flags & O_RSYNC) {
    	printf("O_RSYNC ");
        fprintf(log_file, "O_RSYNC ");
    }
    // Add any additional flags as needed
    
    printf("\n");
    fprintf(log_file, "\n");
}

void read_string(int pid, long addr, char *buffer) {
	unsigned int i = 0;
	char ch = 0;
	
	while (1) {
		if (read_memory(pid, (void*)addr + i, &ch, 1) == -1) break;
		
		if (ch == '\0') break;
		
		buffer[i++] = ch;
	}
	
	buffer[i] = '\0';
	
}

void print_fd_info(pid_t pid, int fd) {
	char link[1024];
	char path[1024];
	
	snprintf(link, 1024,"/proc/%u/fd/%d", pid, fd);
	
	ssize_t len = readlink(link, path, sizeof(path) - 1);
	
	
    if (len == -1) {
        perror("readlink");
        return; // Error occurred
    }

    path[len] = '\0'; // Null-terminate the string
    printf("The symbolic link points to: %s\n", path);
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
	
	len = readlink(path, symbolic_name, sizeof(symbolic_name));
	
	if (len > 0) {
		symbolic_name[len] = '\0';
	} else {
		symbolic_name[0] = '\0';
	}
	
	return symbolic_name;
}

void trace_syscalls(pid_t target_pid) {
	int status;
	
	// Attach to the target process
	if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
		fprintf(log_file, "ptrace(PTRACE_ATTACH)");
		perror("ptrace(PTRACE_ATTACH)");
		exit(EXIT_FAILURE);
	}
	
	// Wait for the target process to stop
	waitpid(target_pid, &status, 0);
	printf("Tracing process %d\n", target_pid);
	fprintf(log_file, "Tracing process %d\n", target_pid);
	
	struct iovec iov;
	struct user_pt_regs regs;
	
	
	long syscall = -1;
	long file_descriptor = -1;
	long data_address = -1;
	long data_length = -1;
	char *data = NULL;
	
	
	while (1) {
		if (ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL) == -1) {
			perror("ptrace(PTRACE_SYSCALL)");
			fprintf(log_file, "ptrace(PTRACE_SYSCALL)");
			exit(EXIT_FAILURE);
		}
		
		waitpid(target_pid, &status, 0);
		
		// Check if the target process has exited
		if (WIFEXITED(status)) {
			printf("Target process exited with status: %d\n", WEXITSTATUS(status));
			fprintf(log_file, "Target process exited.\n");
			break;
		}
		
		if (WIFSIGNALED(status)) {
			printf("Target process was killed by signal: %d\n", WTERMSIG(status));
			break;
		}
		
		// Check if the target is stopped (due to a syscall)
		if (WIFSTOPPED(status)) {
			// Get the register set to find out which syscall is being called
			iov.iov_base = &regs;
			iov.iov_len = sizeof(regs);
			
			if (ptrace(PTRACE_GETREGSET, target_pid, NT_PRSTATUS, &iov) == -1) {
				perror("ptrace(PTRACE_GET_SYSCALL_INFO)");
				break;
			}
			
			// Check the syscall number (x8 on ARM64)
			syscall = regs.regs[8]; // x8 contains the syscall number
			
			if (syscall == __NR_read) {
				printf("\n\nTarget called read syscall!\n");
				
				file_descriptor = regs.regs[0];
				
				const char *name = __symlink(target_pid, file_descriptor);
				
				if (strstr(name, "test.txt") != NULL) {
					data_address = regs.regs[1];
					data_length = regs.regs[2];
					
					if (data_length > 0 && data_length < 65536) {
						data = (char*)malloc(data_length);
						
						if (data == NULL) {
							printf("memory allocation failed!\n");
						}
					}
					
					printf("file descriptor: %ld\n", file_descriptor);
					printf("file name: %s\n", __symlink(target_pid, file_descriptor));
					printf("size: %lu\n", data_length);
					
					ptrace(PTRACE_SYSCALL, target_pid, NULL, NULL);
					waitpid(target_pid, &status, 0);
					
					if (data != NULL) {
						if (read_memory(target_pid, (void*)data_address, data, data_length) != data_length) {
							printf("can't read memory!\n");
						}
						
						printf("addr: %p\n", (void*) data_address);
						printf("data: %s\n\n", data);
						free(data);
						data = NULL;
					}
				}
			}
		}
	}
	
	// Detach from the target process
	ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
}


int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <process_name>\n", argv[0]);
		return EXIT_FAILURE;
	}
	
	mkdir("/sdcard/dump/", 0755);
	
	const char *process_name = argv[1]; 
	
	log_file = fopen("/sdcard/dump/log.txt", "w");
	
	if (log_file == NULL) {
		printf("Error opening log file!\n");
		return 1;
	}
    
	pid_t pid = -1;
	
	printf("[INFO] Waiting for opening '%s' process\n", process_name);
	fprintf(log_file, "[INFO] Waiting for opening '%s' process\n", process_name);
	
	
	while (pid == -1) {
		pid = find_pid(process_name);
	}
	
	printf("[INFO] Process '%s' is now open pid %d\n", process_name, pid);
	
	fprintf(log_file, "[INFO] Process '%s' is now open pid %d\n", process_name, pid);
	
	trace_syscalls(pid);
	
	fclose(log_file);
	return EXIT_SUCCESS;
}