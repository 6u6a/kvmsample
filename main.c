/*
 * KVM API Sample.
 * author: Xu He Jie xuhj@cn.ibm.com
 */
#include <stdio.h>
#include <memory.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>

#define KVM_DEVICE "/dev/kvm"
#define RAM_SIZE 512000000
#define CODE_START 0x0000
#define BINARY_FILE "test.bin"

struct kvm {
   int dev_fd;	
   int vm_fd;
   __u64 ram_size;
   __u64 ram_start;
   int kvm_version;
   struct kvm_userspace_memory_region mem;

   struct vcpu *vcpus;
   int vcpu_number;
};

struct vcpu {
    int vcpu_id;
    int vcpu_fd;
    pthread_t vcpu_thread; //线程标识符
    struct kvm_run *kvm_run;
    int kvm_run_mmap_size;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    void *(*vcpu_thread_func)(void *);//线程执行体
};

void kvm_reset_vcpu (struct vcpu *vcpu) {
	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &(vcpu->sregs)) < 0) {//获取当前 vcpu 的状态
		perror("can not get sregs\n");
		exit(1);
	}

	vcpu->sregs.cs.selector = CODE_START;
	vcpu->sregs.cs.base = CODE_START * 16;
	vcpu->sregs.ss.selector = CODE_START;
	vcpu->sregs.ss.base = CODE_START * 16;
	vcpu->sregs.ds.selector = CODE_START;
	vcpu->sregs.ds.base = CODE_START *16;
	vcpu->sregs.es.selector = CODE_START;
	vcpu->sregs.es.base = CODE_START * 16;
	vcpu->sregs.fs.selector = CODE_START;
	vcpu->sregs.fs.base = CODE_START * 16;
	vcpu->sregs.gs.selector = CODE_START;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0) {//设置当前 vcpu 的状态
		perror("can not set sregs");
		exit(1);
	}

	vcpu->regs.rflags = 0x0000000000000002ULL;
	vcpu->regs.rip = 0;
	vcpu->regs.rsp = 0xffffffff;//栈顶
	vcpu->regs.rbp= 0;//栈底

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &(vcpu->regs)) < 0) {//设置相关寄存器的值
		perror("KVM SET REGS\n");
		exit(1);
	}
}

void *kvm_cpu_thread(void *data) {
	struct kvm *kvm = (struct kvm *)data;
	int ret = 0;
	kvm_reset_vcpu(kvm->vcpus);//设置 vcpu 以及 相关寄存器 的状态

	while (1) {
		printf("KVM start run\n");
		ret = ioctl(kvm->vcpus->vcpu_fd, KVM_RUN, 0);//从当前 vcpu 状态开始运行
	
		if (ret < 0) {
			fprintf(stderr, "KVM_RUN failed\n");
			exit(1);
		}

		switch (kvm->vcpus->kvm_run->exit_reason) {
		case KVM_EXIT_UNKNOWN:
			printf("KVM_EXIT_UNKNOWN\n");
			break;
		case KVM_EXIT_DEBUG:
			printf("KVM_EXIT_DEBUG\n");
			break;
		case KVM_EXIT_IO:
			printf("KVM_EXIT_IO\n");
			printf("out port: %d, data: %d\n", 
				kvm->vcpus->kvm_run->io.port,  
				*(int *)((char *)(kvm->vcpus->kvm_run) + kvm->vcpus->kvm_run->io.data_offset)
				);
			sleep(1);
			break;
		case KVM_EXIT_MMIO:
			printf("KVM_EXIT_MMIO\n");
			break;
		case KVM_EXIT_INTR:
			printf("KVM_EXIT_INTR\n");
			break;
		case KVM_EXIT_SHUTDOWN:
			printf("KVM_EXIT_SHUTDOWN\n");
			goto exit_kvm;
			break;
		default:
			printf("KVM PANIC\n");
			goto exit_kvm;
		}
	}

exit_kvm:
	return 0;
}

void load_binary(struct kvm *kvm) {
    int fd = open(BINARY_FILE, O_RDONLY);//打开二进制文件

    if (fd < 0) {
        fprintf(stderr, "can not open binary file\n");
        exit(1);
    }

    int ret = 0;
    char *p = (char *)kvm->ram_start;//指向刚刚分配的虚拟地址空间的起始地址

    while(1) {
        ret = read(fd, p, 4096);//将二进制文件的内容写入到 刚刚分配的地址空间中
        if (ret <= 0) {
            break;
        }
        printf("read size: %d", ret);
        p += ret;
    }
}

struct kvm *kvm_init(void) {
    struct kvm *kvm = malloc(sizeof(struct kvm));
    kvm->dev_fd = open(KVM_DEVICE, O_RDWR);//以读写权限打开 /dev/kvm，将句柄存放于 kvm 结构体中

    if (kvm->dev_fd < 0) {
        perror("open kvm device fault: ");
        return NULL;
    }

    kvm->kvm_version = ioctl(kvm->dev_fd, KVM_GET_API_VERSION, 0); //得到 kvm 的版本号，存储于一个int类型的变量中

    return kvm;
}

void kvm_clean(struct kvm *kvm) {
    assert (kvm != NULL);
    close(kvm->dev_fd);//关闭打开的设备句柄
    free(kvm);//释放 kvm 结构体
}

int kvm_create_vm(struct kvm *kvm, int ram_size) {
    int ret = 0;
    kvm->vm_fd = ioctl(kvm->dev_fd, KVM_CREATE_VM, 0); //创建 vm，返回虚拟机操作句柄

    if (kvm->vm_fd < 0) {
        perror("can not create vm");
        return -1;
    }

    kvm->ram_size = ram_size;
    kvm->ram_start =  (__u64)mmap(NULL, kvm->ram_size, 
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 
                -1, 0);//创建对应的虚拟地址空间

    if ((void *)kvm->ram_start == MAP_FAILED) {
        perror("can not mmap ram");
        return -1;
    }
    
    kvm->mem.slot = 0;//slot id
    kvm->mem.guest_phys_addr = 0;//对应的起始客户机物理地址
    kvm->mem.memory_size = kvm->ram_size;//大小
    kvm->mem.userspace_addr = kvm->ram_start;//对应的虚拟地址空间的起始地址
	printf("6u6a: kvm->mem.userspace_addr = 0x%llx\t kvm->mem.memory_size = 0x%llx\n", kvm->mem.userspace_addr, kvm->mem.memory_size);
    ret = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &(kvm->mem));//提交memory_region给kvm，更新客户机的物理地址空间

    if (ret < 0) {
        perror("can not set user memory region");
        return ret;
    }

    return ret;
}

void kvm_clean_vm(struct kvm *kvm) {
    close(kvm->vm_fd);//关闭 vm
    munmap((void *)kvm->ram_start, kvm->ram_size);//释放vm的内存
}

struct vcpu *kvm_init_vcpu(struct kvm *kvm, int vcpu_id, void *(*fn)(void *)) {
    struct vcpu *vcpu = malloc(sizeof(struct vcpu));//创建 vcpu 结构体
    vcpu->vcpu_id = 0;//设定当前结构体为0号cpu
    vcpu->vcpu_fd = ioctl(kvm->vm_fd, KVM_CREATE_VCPU, vcpu->vcpu_id);//创建 vcpu，传入 vm的句柄 和 vcpu的id

    if (vcpu->vcpu_fd < 0) {
        perror("can not create vcpu");
        return NULL;
    }

    vcpu->kvm_run_mmap_size = ioctl(kvm->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0);//得到当前 kvm 支持的vcpu映射内存的大小

    if (vcpu->kvm_run_mmap_size < 0) {
        perror("can not get vcpu mmsize");
        return NULL;
    }

    printf("%d\n", vcpu->kvm_run_mmap_size);
    vcpu->kvm_run = mmap(NULL, vcpu->kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu->vcpu_fd, 0);//建立共享存储内存映射，映射文件句柄为 vm 的0号vcpu
	printf("6u6a: vcpu->kvm_run = 0x%lx\tvcpu->kvm_run_mmap_size = 0x%x\n", (unsigned long)(vcpu->kvm_run), vcpu->kvm_run_mmap_size);
    if (vcpu->kvm_run == MAP_FAILED) {
        perror("can not mmap kvm_run");
        return NULL;
    }

    vcpu->vcpu_thread_func = fn;//注册vcpu的线程
    return vcpu;
}

void kvm_clean_vcpu(struct vcpu *vcpu) {
    munmap(vcpu->kvm_run, vcpu->kvm_run_mmap_size);//释放 vcpu 对应的内存
    close(vcpu->vcpu_fd);//关闭 vcpu
}

void kvm_run_vm(struct kvm *kvm) {
    int i = 0;

    for (i = 0; i < kvm->vcpu_number; i++) {//遍历每个 vcpu 对应的线程
        if (pthread_create(&(kvm->vcpus->vcpu_thread), (const pthread_attr_t *)NULL, kvm->vcpus[i].vcpu_thread_func, kvm) != 0) {//启动线程体的执行，传入参数为 kvm 结构体
            perror("can not create kvm thread");
            exit(1);
        }
    }
	for(i = 0; i < kvm->vcpu_number; i ++){
		pthread_join(kvm->vcpus->vcpu_thread, NULL);//等待线程结束
	}
}

int main(int argc, char **argv) {
    int ret = 0;
    struct kvm *kvm = kvm_init();//打开设备，获取 kvm 版本号

    if (kvm == NULL) {
        fprintf(stderr, "kvm init fauilt\n");
        return -1;
    }

    if (kvm_create_vm(kvm, RAM_SIZE) < 0) {//创建 vm，创建了一块虚拟地址空间，然后提交到 kvm
        fprintf(stderr, "create vm fault\n");
        return -1;
    }

    load_binary(kvm);//将二进制文件的内容写入vm的虚拟地址空间开头

    // only support one vcpu now
    kvm->vcpu_number = 1;
    kvm->vcpus = kvm_init_vcpu(kvm, 0, kvm_cpu_thread);//创建 vm 的vcpu，为该vcpu分配映射内存空间，然后注册对应的线程句柄

    kvm_run_vm(kvm);//执行 vcpu 对应的线程

    kvm_clean_vm(kvm);
    kvm_clean_vcpu(kvm->vcpus);
    kvm_clean(kvm);
}
