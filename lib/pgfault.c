// User-level page fault handler support.
// Rather than register the C page fault handler directly with the
// kernel as the page fault handler, we register the assembly language
// wrapper in pfentry.S, which in turns calls the registered C
// function.

#include <inc/lib.h>


// Assembly language pgfault entrypoint defined in lib/pfentry.S.
extern void _pgfault_upcall(void);

// Pointer to currently installed C-language pgfault handler.
void (*_pgfault_handler)(struct UTrapframe *utf);

//
// Set the page fault handler function.
// If there isn't one yet, _pgfault_handler will be 0.
// The first time we register a handler, we need to
// allocate an exception stack (one page of memory with its top
// at UXSTACKTOP), and tell the kernel to call the assembly-language
// _pgfault_upcall routine when a page fault occurs.
//
//参数是一个函数指针，这个函数的参数是个UTrapframe  这个传入的参数就是在pfentry.S中的_pgfault_handler()函数
//这个函数在用户程序中调用
void
set_pgfault_handler(void (*handler)(struct UTrapframe *utf))
{
	int r;

	if (_pgfault_handler == 0) {
		// First time through!
		// LAB 4: Your code here.
		//分配一个异常栈
		// First time through!
		//如果是第一次进入这个函数，那么我们先申请一个异常页作为我们的异常栈
		if ((r = sys_page_alloc(thisenv->env_id, (void *)(UXSTACKTOP - PGSIZE), PTE_P | PTE_W | PTE_U)) < 0)
			panic("set_pgfault_handler: %e", r);
			//申请完成异常页之后，我们设置这个env的缺页异常处理函数入口，也就是pfentry.S中的那个函数（他会去调用真正的缺页处理函数--也就是上面那个参数handler）
		sys_env_set_pgfault_upcall(thisenv->env_id, _pgfault_upcall);
		// if(r<0){
		// 	panic("set_pgfault_handler: sys_env_set_pgfault_upcall() failed");
		// }
	}
	// Save handler pointer for assembly to call.
	//真正处理缺页异常的函数
	_pgfault_handler = handler;
}
