#include <inc/x86.h>
#include <inc/elf.h>

/**********************************************************************
 * This a dirt simple boot loader, whose sole job is to boot
 * an ELF kernel image from the first IDE hard disk.
 *
 * DISK LAYOUT
 *  * This program(boot.S and main.c) is the bootloader.  It should
 *    be stored in the first sector of the disk.
 *
 *  * The 2nd sector onward holds the kernel image.
 *
 *  * The kernel image must be in ELF format.
 *
 * BOOT UP STEPS
 *  * when the CPU boots it loads the BIOS into memory and executes it
 *
 *  * the BIOS intializes devices, sets of the interrupt routines, and
 *    reads the first sector of the boot device(e.g., hard-drive)
 *    into memory and jumps to it.
 *
 *  * Assuming this boot loader is stored in the first sector of the
 *    hard-drive, this code takes over...
 *
 *  * control starts in boot.S -- which sets up protected mode,
 *    and a stack so C code then run, then calls bootmain()
 *
 *  * bootmain() in this file takes over, reads in the kernel and jumps to it.
 **********************************************************************/

#define SECTSIZE	512
#define ELFHDR		((struct Elf *) 0x10000) // scratch space

void readsect(void*, uint32_t);
void readseg(uint32_t, uint32_t, uint32_t);


//从boot.s跳转过来了，在那里我们完成了从实模式到保护模式的转换，并设置了代码段和数据段的起始地址和段界限都是从0x00000000到4G
void
bootmain(void)
{

	//Proghdr  程序头：描述这个程序段的信息，一个程序头一般32字节大小，这个尺寸在ELF header中也有指定
	struct Proghdr *ph, *eph;

	// read 1st page off disk
	// 512b * 8 = 4kb = 1 page
	//这个完成了将内核文件（ELF格式的文件）的前 4096（1 page）个字节读进到0x10000处
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);

	// is this a valid ELF?
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// load each program segment (ignores ph flags)
	//ELFHDR->e_phoff这个代表的是第一个程序头在elf文件内的偏移量
	//ph此时就代表指向了第一个程序头在内存中的位置
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	//ELFHDR->e_phnum表示有几个程序头，eph指向最后一个程序头；
	eph = ph + ELFHDR->e_phnum;
	//开始加载每个程序段
	for (; ph < eph; ph++)
		// p_pa is the load address of this segment (as well
		// as the physical address)
		//ph->p_offset表示在文件内的偏移字节数，ph->p_memsz表示在内存中的大小，ph->p_pa表示在内存中的地址
		// 第一个段 p_pa == 0x100000      p_memsz = 0x7c96 p_offset = 0x1000 正好对应的4096开始，和刚才elf header读进来后面的保持一致 
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);
	// call the entry point from the ELF header
	// note: does not return!
	//ELFHDR->e_entry表示程序（内核程序）的入口地址，段的加载地址是0x100000 ,程序的起始地址在0x10000c
	//以上的都是bootloader程序，还没有开启虚拟地址，等下会进入内核程序，进入之后，指令的寻址方式都是采用的虚拟地址，
	//内核程序在编址的时候设置的起始地址是0xf0100000  也就是4G内存下的256M空间
	((void (*)(void)) (ELFHDR->e_entry))();

bad:
	outw(0x8A00, 0x8A00);
	outw(0x8A00, 0x8E00);
	while (1)
		/* do nothing */;
}

// Read 'count' bytes at 'offset' from kernel into physical address 'pa'.
// Might copy more than asked
//实现了将内核文件的elf header 读进到内存0x10000处
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
	uint32_t end_pa;

	end_pa = pa + count;

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);

	// translate from bytes to sectors, and kernel starts at sector 1  内核在扇区1
	offset = (offset / SECTSIZE) + 1;

	// If this is too slow, we could read lots of sectors at a time.
	// We'd write more to memory than asked, but it doesn't matter --
	// we load in increasing order.
	while (pa < end_pa) {
		// Since we haven't enabled paging yet and we're using
		// an identity segment mapping (see boot.S), we can
		// use physical addresses directly.  This won't be the
		// case once JOS enables the MMU.
		//将offset扇区的内核文件读到pa指向的地址
		readsect((uint8_t*) pa, offset);
		pa += SECTSIZE;
		offset++;
	}
}

void
waitdisk(void)
{
	// wait for disk reaady
	while ((inb(0x1F7) & 0xC0) != 0x40)
		/* do nothing */;
}

void
readsect(void *dst, uint32_t offset)
{
	// wait for disk to be ready
	waitdisk();

	outb(0x1F2, 1);		// count = 1
	outb(0x1F3, offset);
	outb(0x1F4, offset >> 8);
	outb(0x1F5, offset >> 16);
	outb(0x1F6, (offset >> 24) | 0xE0);
	outb(0x1F7, 0x20);	// cmd 0x20 - read sectors

	// wait for disk to be ready
	waitdisk();

	// read a sector
	insl(0x1F0, dst, SECTSIZE/4);
}

