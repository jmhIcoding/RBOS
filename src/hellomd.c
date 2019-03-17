/*
 * Sample LSM implementation
 */

//#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
//#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/kd.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for sysctl_local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/unistd.h>

#define SYSCALL_CONNECT		__NR_socketcall
#define SYSCALL_LINK		__NR_link
#define SYSCALL_UNLINK		__NR_unlink
#define SYSCALL_SYMLINK		__NR_symlink
#define SYSCALL_MKDIR		__NR_mkdir
#define SYSCALL_RMDIR		__NR_rmdir


typedef union {
	struct _connect_info {
		struct socket *sock;
		struct sockaddr *address;
		int addrlen;
	}connect_info;
	
	struct _link_info {
		struct dentry *old_dentry;
		struct inode *dir;
		struct dentry *new_dentry;
	}link_info;

	struct _unlink_info {
		struct inode *dir;
		struct dentry *dentry;
	}unlink_info;

	struct _symlink_info {
		struct inode *dir;
		struct dentry *dentry;
		const char *name;
	}symlink_info;

	struct _mkdir_info {
		struct inode *dir;
		struct dentry *dentry;
		int mask;
	}mkdir_info;
	
	struct _rmdir_info {
		struct inode *dir;
		struct dentry *dentry;
	}rmdir_info;
}perm_info_t;

extern struct security_operations *security_ops;

int check_connect_perm(perm_info_t *info)
{
	printk(KERN_WARNING "___Check connect permission___:: %s\n", __FUNCTION__);	
	return 0;
}

int check_link_perm(perm_info_t *info)
{
	printk(KERN_WARNING "___Check link permission___:: %s\n", __FUNCTION__);
	printk(KERN_WARNING "link file: %s\n", info->link_info.old_dentry->d_iname);
	printk(KERN_WARNING "______________________________________\n");
	return 0;
}

int check_unlink_perm(perm_info_t *info)
{
	printk(KERN_WARNING "___Check unlink permission___:: %s\n", __FUNCTION__);
	printk(KERN_WARNING "unlink file: %s\n", info->unlink_info.dentry->d_iname);
	printk(KERN_WARNING "______________________________________\n");
	return 0;
}

int check_symlink_perm(perm_info_t *info)
{
	printk(KERN_WARNING "___Check symlink permission___:: %s\n", __FUNCTION__);
	printk(KERN_WARNING "symlink file: %s\n", info->symlink_info.name);
	printk(KERN_WARNING "______________________________________\n");
	return 0;
}

int check_mkdir_perm(perm_info_t *info)
{
	printk(KERN_WARNING "___Check mkdir permission___:: %s\n", __FUNCTION__);
	printk(KERN_WARNING "mkdir: %s\n", info->mkdir_info.dentry->d_iname);
	printk(KERN_WARNING "______________________________________\n");
	return 0;
}

int check_rmdir_perm(perm_info_t *info)
{
	printk(KERN_WARNING "___Check rmdir permission___:: %s\n", __FUNCTION__);
	printk(KERN_WARNING "rmdir: %s\n", info->rmdir_info.dentry->d_iname);
	printk(KERN_WARNING "______________________________________\n");
	return 0;
}


static int check_perm(int syscall_type, perm_info_t *perm_info)
{
	int ret=0;
	printk(KERN_WARNING "____Check Permission___::%s\n", __FUNCTION__);
	
	switch (syscall_type) {
	case SYSCALL_CONNECT:
		ret = check_connect_perm(perm_info);
		break;
		
	case SYSCALL_LINK:
		ret = check_link_perm(perm_info);
		break;

	case SYSCALL_UNLINK:
		ret = check_unlink_perm(perm_info);
		break;

	case SYSCALL_SYMLINK:
		ret = check_symlink_perm(perm_info);
		break;

	case SYSCALL_MKDIR:
		ret = check_mkdir_perm(perm_info);
		break;

	case SYSCALL_RMDIR:
		ret = check_rmdir_perm(perm_info);
		break;
	}
	
	return ret;  
}

static int sample_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	perm_info_t perm_info;
	perm_info.connect_info.sock = sock;
	perm_info.connect_info.address = address;
	perm_info.connect_info.addrlen = addrlen;
	
	return check_perm(SYSCALL_CONNECT, &perm_info);
}


static int sample_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	perm_info_t perm_info; 

	perm_info.link_info.old_dentry = old_dentry;
	perm_info.link_info.dir = dir;
	perm_info.link_info.new_dentry = new_dentry;
	
	return check_perm(SYSCALL_LINK, &perm_info);

}

static int sample_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	perm_info_t perm_info; 

	perm_info.unlink_info.dir = dir;
	perm_info.unlink_info.dentry = dentry;
	
	return check_perm(SYSCALL_UNLINK, &perm_info);	
}

static int sample_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	perm_info_t perm_info; 

	perm_info.symlink_info.dir = dir;
	perm_info.symlink_info.dentry = dentry;
	perm_info.symlink_info.name = name;
	
	return check_perm(SYSCALL_SYMLINK, &perm_info);

}

static int sample_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
	perm_info_t perm_info; 

	perm_info.mkdir_info.dir = dir;
	perm_info.mkdir_info.dentry = dentry;
	perm_info.mkdir_info.mask = mask;
	
	return check_perm(SYSCALL_MKDIR, &perm_info);
	
}

static int sample_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	perm_info_t perm_info; 

	perm_info.rmdir_info.dir = dir;
	perm_info.rmdir_info.dentry = dentry;
	
	return check_perm(SYSCALL_RMDIR, &perm_info);
}

static struct security_operations sample_ops = {
	//security operations 구조체에 정의된 hooking point에 대해 hook을 정의함
	//sample code의 경우 link, unlink, symlink, mkdir, rmdir system call 이 호출 되는 경우
	//호출 된 system call의 permission을 확인 할 수 있는 sample hook을 등록함
	.socket_connect =		sample_socket_connect,
	.inode_link =			sample_inode_link,
	.inode_unlink =			sample_inode_unlink,
	.inode_symlink =		sample_inode_symlink,
	.inode_mkdir =			sample_inode_mkdir,
	.inode_rmdir =			sample_inode_rmdir

	//system call에 대한 hook을 추가 하고자 할 경우
	//security_operations 구조체에 정의된 member를 참조 하여 hook을 추가 할 수 있음
};

//insmod를 통해 sample kernel module이 Kernel 에 등록되는 경우 sample_init() 함수가 가장 먼저 호출 된다.
static __init int sample_init(void)
{
	// sample_init() 함수는 register_security() 함수를 이용하여
	// 미리 정의된 security_operations 구조체를 kernel에 등록 한다.
	// register_security() 함수는 security/security.c에 정의 되어 있으며
	// hooking point(security.c에 정의 되어 있음)에서 수행된 함수로 sample_ops를 설정한다.
	reset_security_ops();
	if (register_security (&sample_ops)) {
		printk("Sample: Unable to register with kernel.\n");
		return 0;
	}

	printk(KERN_INFO "Sample:  Initializing.\n");

	return 0;
}

static __exit void sample_exit(void)
{
	printk(KERN_INFO "Sample: Exiting.\n");	
}


//insmod를 통해 sample kernel module이 Kernel에 등록 되는 경우 
//module_init() 함수를 통해 sample_init() 함수가 호출 된다
module_init(sample_init);

//rmdod를 통해 sample kernle module이 kernle 에서 삭제되는 경우
//module_exit() 함수를 통해 sample_exit() 함수가 호출 된다.
module_exit(sample_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JMH");
MODULE_DESCRIPTION("A Simple LSM Driver");
