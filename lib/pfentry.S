#include <inc/mmu.h>
#include <inc/memlayout.h>

// Page fault upcall entrypoint.

// This is where we ask the kernel to redirect us to whenever we cause
// a page fault in user space (see the call to sys_set_pgfault_handler
// in pgfault.c).
//
// When a page fault actually occurs, the kernel switches our ESP to
// point to the user exception stack if we're not already on the user
// exception stack, and then it pushes a UTrapframe onto our user
// exception stack:
//
//	trap-time esp
//	trap-time eflags
//	trap-time eip
//	utf_regs.reg_eax
//	...
//	utf_regs.reg_esi
//	utf_regs.reg_edi
//	utf_err (error code)
//	utf_fault_va            <-- %esp
//
// If this is a recursive fault, the kernel will reserve for us a
// blank word above the trap-time esp for scratch work when we unwind
// the recursive call.
//
// We then have call up to the appropriate page fault handler in C
// code, pointed to by the global variable '_pgfault_handler'.

.text
.globl _pgfault_upcall  //这个函数是从异常栈转换为用户栈，执行env_run()函数的时候，有一个env_pop_tf()函数将eip设置成这个函数入口，栈变成异常栈
_pgfault_upcall:        //1. 现在我们是在异常栈下，并且是用户态
	// Call the C page fault handler.
	pushl %esp			// function argument: pointer to UTF
	movl _pgfault_handler, %eax   //这个_pgfault_handler函数就是用户自定义的函数，也是实际的缺页异常处理函数
	call *%eax           //调用页处理函数
	addl $4, %esp			// pop function argument
	
	//下面就是从异常栈切换到用户栈

	// Now the C page fault handler has returned and you must return
	// to the trap time state.
	// Push trap-time %eip onto the trap-time stack.
	//
	// Explanation:
	//   We must prepare the trap-time stack for our eventual return to
	//   re-execute the instruction that faulted.
	//   Unfortunately, we can't return directly from the exception stack:
	//   We can't call 'jmp', since that requires that we load the address
	//   into a register, and all registers must have their trap-time
	//   values after the return.
	//   We can't call 'ret' from the exception stack either, since if we
	//   did, %esp would have the wrong value.
	//   So instead, we push the trap-time %eip onto the *trap-time* stack!
	//   Below we'll switch to that stack and call 'ret', which will
	//   restore %eip to its pre-fault value.
	//
	//   In the case of a recursive fault on the exception stack,
	//   note that the word we're pushing now will fit in the
	//   blank word that the kernel reserved for us.
	//
	// Throughout the remaining code, think carefully about what
	// registers are available for intermediate calculations.  You
	// may find that you have to rearrange your code in non-obvious
	// ways as registers become unavailable as scratch space.
	//参考这个https://blog.csdn.net/wysiwygo/article/details/104459969
	// LAB 4: Your code here.
	movl 48(%esp), %ebp
    subl $4, %ebp
    movl %ebp, 48(%esp)
    movl 40(%esp), %eax
    movl %eax, (%ebp)


	// Restore the trap-time registers.  After you do this, you
	// can no longer modify any general-purpose registers.
	// LAB 4: Your code here.
	addl $8,%esp
	popal
	// Restore eflags from the stack.  After you do this, you can
	// no longer use arithmetic operations or anything else that
	// modifies eflags.
	// LAB 4: Your code here.
	addl $4,%esp
	popfl
	// Switch back to the adjusted trap-time stack.
	// LAB 4: Your code here.
	popl %esp //这个esp指向的是eip
	// Return to re-execute the instruction that faulted.
	// LAB 4: Your code here.
	ret  //这里十分巧妙， ret会读取esp指向的第一个内容， 也就是我们第一步写入的eip,这样就返回了，这个eip指的是什么呢？进入中断是的地址
