#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/spinlock.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>

void sched_halt(void);

// Choose a user environment to run and run it.
//调度函数，选择一个可运行的用户进程来运行，调度算法是轮询算法
//全局变量curenv变量就是代表的正在此cpu上运行的用户进程
void
sched_yield(void)
{
	struct Env *idle;

	// Implement simple round-robin scheduling.
	//
	// Search through 'envs' for an ENV_RUNNABLE environment in
	// circular fashion starting just after the env this CPU was
	// last running.  Switch to the first such environment found.
	//
	// If no envs are runnable, but the environment previously
	// running on this CPU is still ENV_RUNNING, it's okay to
	// choose that environment.
	//
	// Never choose an environment that's currently running on
	// another CPU (env_status == ENV_RUNNING). If there are
	// no runnable environments, simply drop through to the code
	// below to halt the cpu.

	// LAB 4: Your code here.
	// uint32_t i,nextid,startid;
	// //curenv 也是表示thiscpu->cpu_env;
	// idle = curenv;
	// //通过env_id来定位每个env的
	// startid = (idle == NULL) ? ENVX(idle->env_id):0;
	// //遍历envs，看看有没有RUNABLE的env，有的话就启动这个env
	// for(i=0;i<NENV;i++){
	// 	nextid = (startid + i)%NENV;
	// 	if(envs[nextid].env_status == ENV_RUNNABLE){
	// 		env_run(&envs[nextid]);
	// 		return;
	// 	}
	// }
	// //这里保证的是如果上面没有找到可执行的env，那就继续执行自己，但是这个时候要看一下这个env运行的cpu是不是就是此cpu，不能一个env运行在不同的cpu上
	// if(envs[startid].env_status == ENV_RUNNING && envs[startid].env_cpunum == cpunum()){
	// 	env_run(&envs[startid]);
	// 	return;
	// }
	int start = 0;
	int j;
	if (curenv) {
		start = ENVX(curenv->env_id) + 1;	//从当前Env结构的后一个开始
	}
	for (int i = 0; i < NENV; i++) {		//遍历所有Env结构
		j = (start + i) % NENV;
		if (envs[j].env_status == ENV_RUNNABLE) {
			env_run(&envs[j]);
		}
	}
	if (curenv && curenv->env_status == ENV_RUNNING) {
		env_run(curenv);
	}

	// sched_halt never returns
	sched_halt();
}

// Halt this CPU when there is nothing to do. Wait until the
// timer interrupt wakes it up. This function never returns.
//
void
sched_halt(void)
{
	int i;

	// For debugging and testing purposes, if there are no runnable
	// environments in the system, then drop into the kernel monitor.
	for (i = 0; i < NENV; i++) {
		if ((envs[i].env_status == ENV_RUNNABLE ||
		     envs[i].env_status == ENV_RUNNING ||
		     envs[i].env_status == ENV_DYING))
			break;
	}
	if (i == NENV) {
		cprintf("No runnable environments in the system!\n");
		while (1)
			monitor(NULL);
	}

	// Mark that no environment is running on this CPU
	curenv = NULL;
	lcr3(PADDR(kern_pgdir));

	// Mark that this CPU is in the HALT state, so that when
	// timer interupts come in, we know we should re-acquire the
	// big kernel lock
	xchg(&thiscpu->cpu_status, CPU_HALTED);

	// Release the big kernel lock as if we were "leaving" the kernel
	unlock_kernel();

	// Reset stack pointer, enable interrupts and then halt.
	asm volatile (
		"movl $0, %%ebp\n"
		"movl %0, %%esp\n"
		"pushl $0\n"
		"pushl $0\n"
		// Uncomment the following line after completing exercise 13
		"sti\n"  //该指令的作用是允许中断发生，在STI起效之后，所有外部中断都被恢复
		"1:\n"
		"hlt\n"
		"jmp 1b\n"
	: : "a" (thiscpu->cpu_ts.ts_esp0));
}

