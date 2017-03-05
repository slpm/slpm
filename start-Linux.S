# vim: ts=8:
	.text
	.globl	_start

#if __i386__
_start:
	xorl	%ebp, %ebp
	popl	%eax # argc
	movl	%esp, %ecx #argv
	andl	$-16, %esp
	leal	4(%ecx, %eax, 4), %ebx # envp = &argv + 4 * argc + 4
	pushl	%ebx # envp
	pushl	%ecx # argv
	pushl	%eax # argc
	calll	main
	movl	%eax, %ebx
	xorl	%eax, %eax
	incb	%al
	int	$0x80
#endif // __i386__
