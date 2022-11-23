#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

static struct Taskstate ts;  //TSS

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };

struct Pseudodesc idt_pd = {  //6位IDT表的基址和limit
	sizeof(idt) - 1, 
	(uint32_t) idt
};

//trapno代表异常或者中断号
static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < ARRAY_SIZE(excnames))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}

/*初始化IDT中断描述符表*/
void
trap_init(void)
{
	//全局描述表
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	//这些函数都是在trapentry.S中定义的，也就是所谓的trapHandler
	void th0();
	void th1();
	void th3();
	void th4();
	void th5();
	void th6();
	void th7();
	void th8();
	void th9();
	void th10();
	void th11();
	void th12();
	void th13();
	void th14();
	void th16();
	void th_syscall();

	void timer_handler();
	void kbd_handler();
	void serial_handler();
	void spurious_handler();
	void ide_handler();
	void error_handler();
	//下面就是初始化idt表，段选择子都是内核代码段，因为这些函数都是定在内核态的，这里dpl哦有些设置为0，是因为就是在
	SETGATE(idt[0], 0, GD_KT, th0, 0);		//格式如下：SETGATE(gate, istrap, sel, off, dpl)，定义在inc/mmu.h中
	SETGATE(idt[1], 0, GD_KT, th1, 0);  //设置idt[1]，段选择子为内核代码段，段内偏移为th1
	SETGATE(idt[3], 0, GD_KT, th3, 3);
	SETGATE(idt[4], 0, GD_KT, th4, 0);
	SETGATE(idt[5], 0, GD_KT, th5, 0);
	SETGATE(idt[6], 0, GD_KT, th6, 0);
	SETGATE(idt[7], 0, GD_KT, th7, 0);
	SETGATE(idt[8], 0, GD_KT, th8, 0);
	SETGATE(idt[9], 0, GD_KT, th9, 0);
	SETGATE(idt[10], 0, GD_KT, th10, 0);
	SETGATE(idt[11], 0, GD_KT, th11, 0);
	SETGATE(idt[12], 0, GD_KT, th12, 0);
	SETGATE(idt[13], 0, GD_KT, th13, 0);
	SETGATE(idt[14], 0, GD_KT, th14, 0);
	SETGATE(idt[16], 0, GD_KT, th16, 0);

	SETGATE(idt[T_SYSCALL], 0, GD_KT, th_syscall, 3);		//为什么门的DPL要定义为3，参考《x86汇编语言-从实模式到保护模式》p345
															//我这里猜测的是因为门相当于跳板，用户使用系统调用的时候，肯定要门的特权级低于用户级，只能为3    
	// IRQ
	SETGATE(idt[IRQ_OFFSET + IRQ_TIMER],    0, GD_KT, timer_handler, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_KBD],      0, GD_KT, kbd_handler,     0);
	SETGATE(idt[IRQ_OFFSET + IRQ_SERIAL],   0, GD_KT, serial_handler,  0);
	SETGATE(idt[IRQ_OFFSET + IRQ_SPURIOUS], 0, GD_KT, spurious_handler, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_IDE],      0, GD_KT, ide_handler,     0);
	SETGATE(idt[IRQ_OFFSET + IRQ_ERROR],    0, GD_KT, error_handler,   0);
	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
//每个CPU都有自己的TSS，用来存储一些特权级转换时的新栈的地址
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//   - Initialize cpu_ts.ts_iomb to prevent unauthorized environments
	//     from doing IO (0 is not the correct value!)
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - cpunum() * (KSTKGAP + KSTKSIZE);
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	
	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3)+cpunum()] = SEG16(STS_T32A, (uint32_t) (&thiscpu->cpu_ts),sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3)+cpunum()].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0 + sizeof(struct Segdesc) * cpunum());

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

//根据中断号来执行相应的中断处理程序
static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	//通过他的中断向量号，来确定中断处理函数
	// LAB 3: Your code here.


	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.

	

	switch(tf->tf_trapno){
		case T_PGFLT:
			page_fault_handler(tf);
			break;
		case T_BRKPT:
			monitor(tf);
			break;
		case T_SYSCALL:
			tf->tf_regs.reg_eax = syscall(tf->tf_regs.reg_eax, //这个是系统调用号，下面的都是参数
					tf->tf_regs.reg_edx,
					tf->tf_regs.reg_ecx,
					tf->tf_regs.reg_ebx,
					tf->tf_regs.reg_edi,
					tf->tf_regs.reg_esi);
			break;
		case IRQ_OFFSET + IRQ_TIMER:
			lapic_eoi();  //设置中断响应
			sched_yield(); //进程调度
			return;
		default:
			// Unexpected trap: The user process or the kernel has a bug.
			print_trapframe(tf);
			if (tf->tf_cs == GD_KT)
				panic("unhandled trap in kernel");
			else {
				env_destroy(curenv);
				return;
			}
	}
	
}

//在_alltraps中我们调用了这个trap函数，处理异常或中断事件
void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc"); //cld指令功能: 将标志寄存器flag的方向标志位df清零

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));
	// cprintf("this trap num ========%x",tf->tf_trapno);
	// cprintf(" this tf->tf_cs = %x",tf->tf_cs);
	// cprintf("Incoming TRAP frame at %p\n", tf);
	//查看产生中断或异常的程序的特权级

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		lock_kernel();
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}

//这个tf是在内核栈中的，保存了一些进程进入中断时的一些信息
//这个函数时页面异常处理程序，好像是通过UTrapframe进行直接中断返回，而不是从Tramframe回去的（这一点需要关注）
void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	//cr2寄存器是用来存储发生page fault 时的线性地址
	fault_va = rcr2();
	// panic("page_fault in kernel mode, fault address %d\n", fault_va);
	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if((tf->tf_cs & 0x3) == 0) {
        panic("page_fault in kernel mode, fault address %d\n", fault_va);
    }
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// It is convenient for our code which returns from a page fault
	// (lib/pfentry.S) to have one word of scratch space at the top of the
	// trap-time stack; it allows us to more easily restore the eip/esp. In
	// the non-recursive case, we don't have to worry about this because
	// the top of the regular user stack is free.  In the recursive case,
	// this means we have to leave an extra word between the current top of
	// the exception stack and the new stack frame because the exception
	// stack _is_ the trap-time stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
	struct UTrapframe *utf;
	if(curenv->env_pgfault_upcall){
		//这一步是判断是不是之前已经在异常栈中了，（也就是上面说的递归陷入了）
		//如果之前没有在异常栈中，那么UTrapframe结构从UXSTACKTOP这里开始
		//如果之前在异常栈中，那么就紧接着一个UTrapframe 再加一字节空位 开始
		//也就是这里的stacktop位置
		if (UXSTACKTOP - PGSIZE <= tf->tf_esp && tf->tf_esp <= UXSTACKTOP - 1)
            utf = (struct UTrapframe *)(tf->tf_esp - sizeof(struct UTrapframe) - 4);
        else
            utf = (struct UTrapframe *)(UXSTACKTOP - sizeof(struct UTrapframe));
		user_mem_assert(curenv, (void *)utf, sizeof(struct UTrapframe), PTE_U | PTE_W);

		//初始化这个异常栈，直接从这里回去了用户模式，所以要用tf中的值来初始化utf
		utf->utf_fault_va = fault_va;
		utf->utf_err = tf->tf_err;
		utf->utf_regs = tf->tf_regs;
		utf->utf_eflags = tf->tf_eflags;
		utf->utf_eip = tf->tf_eip;   //这个tf_eip应该是用户程序发生中断时的eip
		utf->utf_esp = tf->tf_esp;   //这个tf_esp应该是用户的用户栈esp          ////UXSTACKTOP栈上需要保存发生缺页异常时的%esp和%eip

		//设置进程eip指向页异常用户处理程序
		tf->tf_eip = (uint32_t)curenv->env_pgfault_upcall;  //这个会在执行env_pop_tf这个函数的时候，开开始执行这个函数，在pfentry.S文件
		//使用的栈就是UXSTACKTOP，从utf下面开始，
		tf->tf_esp = (uint32_t)utf;
		//回到用户模式，经过一系列的pop，记忆最后的iret命令，到了env_pgfault_upcall这里，并且此时栈变成了异常栈utf（并不是用户栈，所以这里完成了从内核栈->异常栈的转换）
		env_run(curenv); //此时的栈还是内核栈，后面env_pop_tf的pop都是pop的Trapframe结构，然后完成内核栈->异常栈，并执行pgfault_upcall函数
	}
	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

