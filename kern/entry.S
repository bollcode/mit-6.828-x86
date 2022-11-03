/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>

# Shift Right Logical 
#define SRL(val, shamt)		(((val) >> (shamt)) & ~(-1 << (32 - (shamt))))


###################################################################
# The kernel (this code) is linked at address ~(KERNBASE + 1 Meg), 
# but the bootloader loads it at address ~1 Meg.
#	
# RELOC(x) maps a symbol x from its link address to its actual
# location in physical memory (its load address).	 
###################################################################

#define	RELOC(x) ((x) - KERNBASE)

#define MULTIBOOT_HEADER_MAGIC (0x1BADB002)
#define MULTIBOOT_HEADER_FLAGS (0)
#define CHECKSUM (-(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS))

###################################################################
# entry point
###################################################################

.text

# The Multiboot header
.align 4
.long MULTIBOOT_HEADER_MAGIC
.long MULTIBOOT_HEADER_FLAGS
.long CHECKSUM

# '_start' specifies the ELF entry point.  Since we haven't set up
# virtual memory when the bootloader enters this code, we need the
# bootloader to jump to the *physical* address of the entry point.
.globl		_start
# 因为还没有开启分页，所以要用RELOC来映射地址
_start = RELOC(entry)


# 我们现在正式进入内核了，下面就是内核的程序。之前的bootloader程序已经任务完成。

.globl entry
entry:
	movw	$0x1234,0x472			# warm boot

	# We haven't set up virtual memory yet, so we're running from
	# the physical address the boot loader loaded the kernel at: 1MB
	# (plus a few bytes).  However, the C code is linked to run at
	# KERNBASE+1MB.  Hence, we set up a trivial page directory that
	# translates virtual addresses [KERNBASE, KERNBASE+4MB) to
	# physical addresses [0, 4MB).  This 4MB region will be
	# sufficient until we set up our real page table in mem_init
	# in lab 2.

	# Load the physical address of entry_pgdir into cr3.  entry_pgdir
	# is defined in entrypgdir.c.
	# 通过反汇编我们知道了$(RELOC(entry_pgdir)) = $0x111000   entry_pgdir在0xf0111000
	# 也就是我们的页目录表的地址是$0x111000，这个就是物理地址 ，这个时候还没有开启分页模式，所以使用RELOC来映射物理地址

	# 取出页目录表的地址，并放进cr3寄存器中 这个时候我们就设定好了页目录表
	movl	$(RELOC(entry_pgdir)), %eax  
	movl	%eax, %cr3
	# Turn on paging. 
	# 开启分页模式，这个时候指令的地址都是虚拟地址了，需要进行映射，映射的过程交给MMU来完成，
	# 因为我们已经设置好了页目录表和页表，并把页目录表的地址给了cr03，MMU会自动将寻址时的地址转化为对应的物理地址，然后交给总线去寻址
	movl	%cr0, %eax  
	orl	$(CR0_PE|CR0_PG|CR0_WP), %eax
	movl	%eax, %cr0

	# Now paging is enabled, but we're still running at a low EIP
	# (why is this okay?).  Jump up above KERNBASE before entering
	# C code.
	mov	$relocated, %eax
	jmp	*%eax
relocated:


	# 从这里开始我们就正式进入了分页模式

	# Clear the frame pointer register (EBP)
	# so that once we get into debugging C code,
	# stack backtraces will be terminated properly.
	movl	$0x0,%ebp			# nuke frame pointer

	# Set the stack pointer 
	# 通过反汇编我们知道 0xf0110000 是栈顶
	movl	$(bootstacktop),%esp


	# 从这里我们就进入了C语言代码
	# now to C code
	call	i386_init

	# Should never get here, but in case we do, just spin.
spin:	jmp	spin


.data
###################################################################
# boot stack
###################################################################
	.p2align	PGSHIFT		# force page alignment
	.globl		bootstack
bootstack:
	.space		KSTKSIZE
	.globl		bootstacktop   
bootstacktop:

