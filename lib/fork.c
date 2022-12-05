// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>
#include <inc/memlayout.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;    //发生异常的时候的地址
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	//通过这个uvpt能够取得这个虚拟地址对应的页表项，这个页表项的后12位是用来标记它指定的页的权限
	//https://blog.csdn.net/weixin_43344725/article/details/89382013
	if((err & FEC_WR)==0 || (uvpt[PGNUM(addr)] & PTE_COW)==0){
		panic("pgfault: it's not writable or attempt to access a non-cow page!");
	}
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.
	//获取这个进程的id
	envid_t envid = sys_getenvid();
	//申请一个页面，然后将物理地址映射到PFTEMP去了
	if((r = sys_page_alloc(envid,(void *)PFTEMP,PTE_P|PTE_W|PTE_U))<0){
		panic("pgfault: page allocation failed %e", r);
	}
	//addr就是发生缺页中断时的地址，将这个addr取整，获取到这个页的地址
	addr = ROUNDDOWN(addr,PGSIZE);
	//然后将这个页的内容复制到刚才申请的PFTEMP中去
	memmove(PFTEMP,addr,PGSIZE);
	//解除这个addr和指定物理地址的映射
	if((r - sys_page_unmap(envid,addr))<0){
		panic("pgfault: page unmap failed %e", r);
	}
	//因为上面我们解除了addr和物理页面的映射，现在我们想将addr映射到PFTEMP对应的物理地址去，这样下次再访问addr是，找到的物理地址就是新的物理地址
	//并且这个新的物理页可读可写了已经，之前访问的都是父进程的，可读不可写
	if((r = sys_page_map(envid,PFTEMP,envid,addr,PTE_P|PTE_W|PTE_U))<0){
		panic("pgfault: page map failed %e", r);
	}
	//经过上面，我们现在有两块虚拟页映射到了同一块新申请的物理地址
	//接下来我们将解除PFTEMP虚拟地址和物理地址的映射关系
	if((r = sys_page_unmap(envid,PFTEMP))<0){
		panic("pgfault: page unmap failed %e", r);
	}
	//这样我们就完成了缺页异常处理的全部功能：就是将父进程的物理页内容重新赋值一份出来，然后更改子进程的页表映射关系，将子进程相同的虚拟地址映射
	//到不同的物理页面上，这样就完成了子进程和父进程的隔离

	// panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//这个函数就是将父进程页表给赋值到子进程的页表中，并且把子进程的页表项的权限修改一下，因为他不能修改父进程的页面
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	void *addr;
	pte_t pte;
	int perm;
	addr = (void *)((uint32_t)pn * PGSIZE);
	pte = uvpt[pn];
	if(pte & PTE_SHARE){
		////对于标识为PTE_SHARE的页，拷贝映射关系，并且两个进程都有读写权限  这里不是复制了，是文件进程和对应进程共享这个区域
		if((r = sys_page_map(sys_getenvid(),addr,envid,addr,pte&PTE_SYSCALL)) < 0){
			panic("duppage: page mapping failed %e", r);
			return r;
		}
	}else{
		perm = PTE_P | PTE_U;
		//把可写或者写时复制页面标记为COW和不可写
		if((pte & PTE_W) || (pte & PTE_COW)){
			perm |= PTE_COW;
			// perm &= ~PTE_W;
		}
		//将父进程的页面映射复制到子进程地址空间，实际上就是父进程和子进程共享一个物理页面，所以虚
		//拟地址同一个。
		if((r = sys_page_map(thisenv->env_id,addr,envid,addr,perm))<0){
			panic("duppage: page remapping failed %e", r);
			return r;
		}
		//更新一下父进程页面映射的权限。
		if (perm & PTE_COW) {
			if ((r = sys_page_map(thisenv->env_id, addr, thisenv->env_id, addr, perm)) < 0) {
					panic("duppage: page remapping failed %e", r);
					return r;
			}
		}
		// panic("duppage not implemented");
	}
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	extern void _pgfault_upcall(void);
	
	set_pgfault_handler(pgfault); //设置真正的缺页异常处理函数，这设置的是父进程的


	envid_t envid = sys_exofork(); //系统调用，只是简单创建一个Env结构，并返回子进程id复制当前用户环境寄存器状态，UTOP以下的页目录还没有建立
	if(envid ==0){  //子进程走这里
		thisenv = &envs[ENVX(sys_getenvid())]; //获取这个env结构
		return 0;
	}
	if(envid < 0){
		panic("sys_exofork: %e",envid);
	}
	uint32_t addr;
	//将父进程的页表复制到子进程的页表中
	for(addr =0;addr<USTACKTOP;addr +=PGSIZE){
		//uvpd可以找到虚拟地址对应的页目录项，uvpt可以找到addr对应的页表项
		if((uvpd[PDX(addr)] & PTE_P) && (uvpt[PGNUM(addr)] & PTE_P) && (uvpt[PGNUM(addr)] & PTE_U)){
			duppage(envid,PGNUM(addr));//拷贝当前进程映射关系到子进程
		}
	}
	int r;
	//为子进程分配异常栈，为子进程申请一个异常栈页面，这个是为子进程申请一个异常栈
	if(( r = sys_page_alloc(envid,(void *)(UXSTACKTOP - PGSIZE),PTE_P|PTE_W|PTE_U))<0){
		panic("sys_page_alloc: %e", r);
	}
	//父进程的异常栈不会复制给子进程，所以子进程需要自己初始化异常栈
	//因为子进程不会赋值UXSTACKTOP虚拟地址给子进程，这个虚拟地址就是异常栈，所以需要给子进程的异常栈设置_pgfault_upcall函数
	sys_env_set_pgfault_upcall(envid,_pgfault_upcall); //为子进程设置_pgfault_upcall，缺页处理函数入口
	
	if((r = sys_env_set_status(envid,ENV_RUNNABLE))<0){ //设置这个子进程的状态为RUNNABLE
		panic("sys_env_set_status: %e", r);
	}
	return envid;
	// panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
