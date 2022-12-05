/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.
	
	// LAB 3: Your code here.
	user_mem_assert(curenv, s, len, 0);
	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
//创建一个新的env，并返回子进程的id
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	// LAB 4: Your code here.
	int ret;
	struct Env *env;
	//在envs中获取一个env，并将这个env对应的页表申请完成
	ret = env_alloc(&env,sys_getenvid());
	if(ret <0){
		return ret;
	}
	//设置这个env的状态 为不可运行
	env->env_status = ENV_NOT_RUNNABLE;
	//设置父进程的Trapflame为子进程的tf
	env->env_tf = curenv->env_tf;
	env->env_tf.tf_regs.reg_eax =0;//新的进程从sys_exofork()的返回值应该为0
	//创建完成返回子进程的id
	return env->env_id;
	// panic("sys_exofork not implemented");
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
//将envid对应的进程状态设置成status  ENV_NOT_RUNNABLE或者ENV_RUNNABLE
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.

	// LAB 4: Your code here.
	if(status != ENV_NOT_RUNNABLE && status != ENV_RUNNABLE)
		return -E_INVAL;
	struct Env *env;
	int ret = envid2env(envid,&env,1);
	if(ret <0 ){
		return ret;
	}
	env->env_status = status;
	return 0;
	// panic("sys_env_set_status not implemented");
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3), interrupts enabled, and IOPL of 0.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// LAB 5: Your code here.
	// Remember to check whether the user has supplied us with a good
	// address!
	struct Env *env;
	int r =0;
	if(( r = envid2env(envid,&env,true)) < 0){
		return -E_BAD_ENV;
	}
	// env->env_tf = *tf;
	// env->env_tf.tf_cs |= 3;//设置用户模式
	// env->env_tf.tf_eflags |= FL_IF;//// Interrupt Flag
	tf->tf_eflags |= FL_IF;
	tf->tf_eflags &= ~FL_IOPL_MASK;
	tf->tf_cs |= 3;
	env->env_tf = *tf;
	return 0;
	// panic("sys_env_set_trapframe not implemented");
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//这个函数是设置用户自己的pagefault处理函数，这个func就是_pgfault_upcall，就是缺页中断的总入口，位于pfentry.S文件中
//也就是这个函数设置进程缺页异常的入口
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	struct Env *env;
	int ret;
	ret = envid2env(envid,&env,1);
	if(ret <0 ){
		return -E_BAD_ENV;
	}
	//这个是执行用户进程自己的处理函数,所以设置成用户提供的函数func
	//最后就是在这里设置了用户缺页入口程序
	env->env_pgfault_upcall = func;
	return 0;
	// panic("sys_env_set_pgfault_upcall not implemented");
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
//给某个进程申请一个页，并在页表中建立完成页表映射，这个虚拟地址va从哪里来的？
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!

	// LAB 4: Your code here.
	struct Env *env;
	int ret = envid2env(envid,&env,1);
	if(ret <0){
		return -E_BAD_ENV;
	}
	//判断虚拟地址是否超过UTOP，判断地址是否是页对齐的
	if((va >= (void *)UTOP) ||(ROUNDDOWN(va, PGSIZE) != va))
		return -E_INVAL;
	int flag = PTE_U | PTE_P;
	//判断权限是否正常
	if((perm & flag) != flag) return E_INVAL;
	//申请一页内存
	struct PageInfo *pg = page_alloc(1);
	//判断页面是否申请成功
	if(!pg) return -E_NO_MEM;
	//插入到自己的页表中,也就是做好虚拟地址和物理地址的映射
	ret = page_insert(env->env_pgdir,pg,va,perm);
	if(ret){
		//进入这里表示建立映射失败，需要将刚才申请的页给释放掉
		page_free(pg);
		return ret;
	}
	return 0;
	// panic("sys_page_alloc not implemented");
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.

	// LAB 4: Your code here.
	struct Env *se, *de;
	int ret = envid2env(srcenvid,&se,1);
	if(ret) return ret;
	ret = envid2env(dstenvid,&de,1);
	if(ret) return ret;
	//判断虚拟地址是否超过了UTOP，判断srcva和dstva是否是页对其的
	if(srcva >=(void *)UTOP || dstva >= (void *)UTOP ||
		ROUNDDOWN(srcva,PGSIZE) != srcva|| ROUNDDOWN(dstva,PGSIZE) !=dstva){
			return -E_INVAL;
		}
	pte_t *pte;
	//这个函数是返回虚拟地址srcva对应的实际物理页，保存在pte指向的地址中
	struct PageInfo *pg = page_lookup(se->env_pgdir,srcva,&pte);
	//这个是判断src进程对应的虚拟地址是否有物理页存在（是否完成映射，因为后面要将dst的虚拟地址映射到这个物理地址）
	if(!pg){
		return -E_INVAL;
	}
	int flag = PTE_U|PTE_P;
	//判断权限是否正确
	if((perm & flag) !=flag) return -E_INVAL;
	//判断这个页面是否可写，srcva对应的页面一般read_only
	//将子进程的页表中的对应的父进程的页的权限都改成只读的（权限设置在页表项的低12位）----这个很重要，因为这样在子进程想要修改父进程的页的时候，就会触发pagefault
	if((*pte & PTE_W) == 0 && (perm & PTE_W)) return -E_INVAL;

	//经过上面的一些列判断后，我们将de进程的虚拟地址dstva映射到srcva对应的物理地址去
	ret = page_insert(de->env_pgdir,pg,dstva,perm);
	return 0;
	// panic("sys_page_map not implemented");
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().

	// LAB 4: Your code here.
	struct Env *env;
	int ret = envid2env(envid,&env,1);
	if(ret){
		return ret;
	}
	if(va >= (void *)UTOP || ROUNDDOWN(va,PGSIZE) != va){
		return -E_INVAL;
	}
	page_remove(env->env_pgdir,va);
	return 0;
	// panic("sys_page_unmap not implemented");
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.
	int r;
	pte_t *pte;
	struct PageInfo *pp;
	struct Env *env; //目标进程
	if((r = envid2env(envid,&env,0))<0){
		//如果不存在这个env
		return -E_BAD_ENV;
	}
	if(env->env_ipc_recving !=true || env->env_ipc_from != 0){
		//判读目标进程是否处于接收状态，并且之前没人发送消息给他
		return -E_IPC_NOT_RECV;
	}
	if(srcva <(void *)UTOP && PGOFF(srcva)){
		//如果srcva<UTOP，那么说明是页传送，那么srcva必须是页对齐的
		return -E_INVAL;
	}
	//下面是表示页传送
	if(srcva< (void *) UTOP){
		//这个表示传送的页不存在，或者不是用户页
		if((perm & PTE_P) == 0 || (perm & PTE_U) == 0){
			return -E_INVAL;
		}

		if((perm & ~(PTE_P | PTE_U | PTE_W | PTE_AVAIL)) != 0){
			return -E_INVAL;
		}
	}
	//看看这个物理页是否存在
	if(srcva < (void *)UTOP && (pp = page_lookup(curenv->env_pgdir,srcva,&pte)) == NULL){
		return -E_INVAL;
	}
	//查看这个页是不是两个同时拥有可写的权限
	if(srcva < (void *)UTOP && (perm & PTE_W) !=0  && (*pte & PTE_W) ==0){
		return -E_INVAL;
	}
	//如果发送的是页，并且目标进程的所要映射的地址不等于0，那么就可以将这个物理页插入到目标进程的页表中，完成映射
	if(srcva < (void *)UTOP && env->env_ipc_dstva !=0){
		if(( r = page_insert(env->env_pgdir,pp,env->env_ipc_dstva,perm)) < 0){
			//表示没有足够的内存进程映射，就是无法申请新的页表之类的
			return -E_NO_MEM;
		}
		
		env->env_ipc_perm = perm;
	}

	//上面完成了消息的发送           ========================全都是在发送进程中完成的
	//接下来就是恢复目标进程的状态


	env->env_ipc_from = curenv->env_id; //设置进程消息来源进程id
	env->env_ipc_recving = false;       //设置目标进程不在处于接收状态
	env->env_ipc_value = value;         //设置这个要传送的消息---value
	env->env_status = ENV_RUNNABLE;     //设置进程状态为可运行状态
	env->env_tf.tf_regs.reg_eax =0;
	return 0;
	// panic("sys_ipc_try_send not implemented");
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	//看看这个dstva是不是小于UTOP，如果小于，则是发送页，并且dstva必须是起始页地址（页对齐）
	if(dstva < (void *)UTOP && dstva != ROUNDDOWN(dstva,PGSIZE)){
		return -E_INVAL;
	}
	curenv->env_ipc_recving = true; //设置正在接受数据
	curenv->env_ipc_dstva = dstva; //设置虚拟地址
	curenv->env_status = ENV_NOT_RUNNABLE;//设置不可运行状态
	curenv->env_ipc_from = 0;  //envid of the sender
	// panic("sys_ipc_recv not implemented");
	sched_yield();//交出cpu的使用权
	return 0;
}

// Dispatches to the correct kernel function, passing the arguments.
//这个syscall是内核的方法
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.
	int32_t ret;
	// panic("syscall not implemented");

	switch (syscallno) {
		case SYS_cputs:
			sys_cputs((char *)a1,(size_t)a2);
			ret =0;
			break;
		case SYS_cgetc:
			ret = sys_cgetc();
			break;
		case SYS_env_destroy:
			ret = sys_env_destroy((envid_t)a1);
			break;
		case SYS_getenvid:
			ret = sys_getenvid();
			break;
		case SYS_yield:  //进程唤醒
			ret =0;
			sys_yield();
			break;
		case SYS_exofork:  //创建进程
			ret = sys_exofork();
			break;
		case SYS_env_set_status:
			ret = sys_env_set_status((envid_t)a1, (int)a2);
			break;
		case SYS_page_alloc:
			ret = sys_page_alloc((envid_t)a1, (void *)a2, (int)a3);
			break;
		case SYS_page_map:
			ret = sys_page_map((envid_t)a1, (void *)a2,
	     (envid_t)a3, (void *)a4, (int)a5);
			break;
		case SYS_page_unmap:
			ret = sys_page_unmap((envid_t)a1, (void *)a2);
			break; 
		case SYS_env_set_pgfault_upcall:
			return sys_env_set_pgfault_upcall((envid_t) a1, (void *) a2);
		case SYS_ipc_recv:
			return sys_ipc_recv((void *)a1);
		case SYS_ipc_try_send:
			return sys_ipc_try_send((envid_t)a1,(uint32_t)a2,(void *)a3,(int)a4);
		case SYS_env_set_trapframe:
			return sys_env_set_trapframe((envid_t)a1,(struct Trapframe *)a2);
		default:
			return -E_INVAL;
	}
	return ret;
}

