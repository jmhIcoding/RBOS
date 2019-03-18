/*
 * A LSM modules which implements role based access control.
 */
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
#include <linux/uaccess.h>
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
#include <linux/lsm_hooks.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/version.h>
#include <linux/syscalls.h>

//定义将要hook的系统调用
#define SYSCALL_CONNECT		0x01
#define SYSCALL_SOCKET		0x02
#define SYSCALL_MKDIR		0x04
#define SYSCALL_RMDIR		0x08
#define SYSCALL_TASK_CREATE 0x10

//定义四种角色
#define ROLE_RECYCLER_NAME "recycler"
#define ROLE_OPERATOR_NAME "operator"
#define ROLE_NETMANAGER_NAME "netmanager"
#define ROLE_ADMIN_NAME "admin"

#define ROLE_RECYCLER 	1
#define ROLE_OPERATOR 	2
#define ROLE_NETMANAGER 3
#define ROLE_ADMIN 		4

//定义几个配置文件的路径,此处是硬编码的
#define ROLE_CONFIG		"/etc/rbos/role_config"
#define USER_CONFIG		"/etc/rbos/user_config"

//最多支持16种角色,128个用户的分配
#define SAMPLE_MAX_ROLE 	16
#define SAMPLE_MAX_USER		128

#define SAMPLE_MAX_BUF		1024


//角色结构
typedef struct __role__
{
	unsigned int roleid;
	unsigned int right;
}_ROLE_STRUCT;
_ROLE_STRUCT all_roles[SAMPLE_MAX_ROLE]={{0,0},};
unsigned int all_roles_cnt=0;

//用户结构
typedef struct __user__
{
	unsigned int userid;
	unsigned int right;
}_USER_STRUCT;

_USER_STRUCT all_users[SAMPLE_MAX_USER]={{0,SYSCALL_CONNECT | SYSCALL_SOCKET | SYSCALL_MKDIR |SYSCALL_RMDIR | SYSCALL_TASK_CREATE},};
unsigned int all_users_cnt=1;

typedef union {
	struct _socket_info{
		int domain;
		int type;
		int protocol;
	};
	struct _connect_info {
		struct socket *sock;
		struct sockaddr *address;
		int addrlen;
	}connect_info;
	
	struct _mkdir_info {
		struct inode *dir;
		struct dentry *dentry;
		int mask;
	}mkdir_info;
	
	struct _rmdir_info {
		struct inode *dir;
		struct dentry *dentry;
	}rmdir_info;
	struct _taskcreate_info{
		unsigned long clone_flags;
	};
}perm_info_t;


unsigned int sample_asc2int(char * str,int len)
//将整形字符串转换为整数
{
	unsigned int rst =0;
	int i;
	for(i =0;i<len;i++)
	{
		rst=rst * 10 + str[i]-'0';
	}
	printk(KERN_WARNING "asc2int::%d,len:%d  str:%s.\n",rst,len,str);
	return rst;
}
int check_connect_perm(perm_info_t *info,unsigned int right)
{
	printk(KERN_WARNING "___Check connect permission___:: %s\n", __FUNCTION__);
	if(right & SYSCALL_CONNECT) 
	{
		return 0;
	}
	else
	{
		return -EINVAL;
	}
}

int check_socket_perm(perm_info_t *info,unsigned int right)
{
	printk(KERN_WARNING "___Check socket create permission___:: %s\n", __FUNCTION__);
	if(right&SYSCALL_SOCKET)
	{
		return 0;
	}
	else
	{
		return -EINVAL;
	}
}

int check_taskcreate_perm(perm_info_t *info,unsigned int right)
{
	printk(KERN_WARNING "___Check task_create permission___:: %s\n", __FUNCTION__);
	if(right & SYSCALL_TASK_CREATE)
	{
		return 0;
	}
	else
	{
		return -EINVAL;
	}
	
}


int check_mkdir_perm(perm_info_t *info,unsigned int right)
{
	printk(KERN_WARNING "___Check mkdir permission___:: %s\n", __FUNCTION__);
	if(right & SYSCALL_MKDIR)
	{
		return 0;
	}
	else
	{
		return -EINVAL;
	}
}

int check_rmdir_perm(perm_info_t *info,unsigned int right)
{
	printk(KERN_WARNING "___Check rmdir permission___:: %s\n", __FUNCTION__);
	if(right & SYSCALL_RMDIR)
	{
		return 0;
	}
	else
	{
		return -EINVAL;
	}
}


static int check_perm(int syscall_type, perm_info_t *perm_info)
{
	int ret=0;
	struct cred * new;
	unsigned int euid=0;
	unsigned int right=0;
	
	
	//获取用户有效uid,并且得到用户的权限,默认用户都拥有SYSCALL_TASK_CREATE的权限
	new=prepare_creds();
	euid =(unsigned int)(new->euid).val;
	int i;
	for( i=0;i<all_users_cnt;i++)
	{
		if(all_users[i].userid == euid)
		{
			right |= all_users[i].right;
			break;
		}
	}
	if(right==0)
		//非测试用户,打开所有权限
	{
		right=SYSCALL_CONNECT | SYSCALL_SOCKET | SYSCALL_MKDIR |SYSCALL_RMDIR | SYSCALL_TASK_CREATE;
	}
	printk(KERN_WARNING "____Check Permission___::%s, euid :: %d.\n", __FUNCTION__,euid);
	switch (syscall_type) {
	case SYSCALL_CONNECT:
		ret = check_connect_perm(perm_info,right);
		break;
		
	case SYSCALL_SOCKET:
		ret = check_socket_perm(perm_info,right);
		break;

	case SYSCALL_TASK_CREATE:
		ret = check_taskcreate_perm(perm_info,right);
		break;

	case SYSCALL_MKDIR:
		ret = check_mkdir_perm(perm_info,right);
		break;

	case SYSCALL_RMDIR:
		ret = check_rmdir_perm(perm_info,right);
		break;
	}
	
	return ret;  
}

static int sample_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	perm_info_t perm_info;

	
	return check_perm(SYSCALL_CONNECT, &perm_info);
}

static int sample_socket(int domain,int type,int protocol,int kern)
//TODO 完善参数列表
{
	perm_info_t perm_info;

	return check_perm(SYSCALL_SOCKET,&perm_info);
}

static int sample_task_create(unsigned long clone_flags)
{
	perm_info_t perm_info;

	return check_perm(SYSCALL_TASK_CREATE,&perm_info);
}

static int sample_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
	perm_info_t perm_info; 


	
	return check_perm(SYSCALL_MKDIR, &perm_info);
	
}

static int sample_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	perm_info_t perm_info; 


	
	return check_perm(SYSCALL_RMDIR, &perm_info);
}


static void get_role_config(void)
{
	char buf[SAMPLE_MAX_BUF]={0};
	struct file * f=NULL;
	const char * filename =ROLE_CONFIG;
	char * p;
	int i=0;
	char * line_start;
	char * token_start;
	printk(KERN_INFO "get role config from %s.\n",filename);
	mm_segment_t oldfs;

	f =filp_open(filename,O_RDONLY,0);
	if( IS_ERR(f) || (f==NULL))
	{
		printk(KERN_WARNING "get role config error.\n");
		return ;
	}
	p=buf;
	line_start = buf;
	token_start=buf;
	int role_index =0;
	oldfs =get_fs();
	//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
	set_fs(get_ds());
	//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
	while(vfs_read(f,buf+i,1,&f->f_pos)==1)
	{
		//printk(KERN_INFO "%s::%d.THE SRC:%s\n",__FUNCTION__,__LINE__,buf);
		if(i==SAMPLE_MAX_BUF)
			//读满缓存区
		{
			break;
		}
		if(buf[i]==':')
			//读到角色
		{
			//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
			buf[i]=0;//把":"截断
			printk(KERN_INFO "read a role of :%s.\n",line_start);
			
			all_roles_cnt++;
			if(role_index != 0)
			{
				printk(KERN_INFO "last role right:%x.\n",all_roles[role_index].right);
			}
			if(strcmp((const char *)line_start,ROLE_ADMIN_NAME)==0)
			{
				role_index = ROLE_ADMIN;
			}
			//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
			if(strcmp((const char *)line_start,ROLE_NETMANAGER_NAME)==0)
			{
				role_index = ROLE_NETMANAGER;
			}
			//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
			if(strcmp((const char *)line_start,ROLE_OPERATOR_NAME)==0)
			{
				role_index =ROLE_OPERATOR;
			}
			//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
			if(strcmp((const char *)line_start,ROLE_RECYCLER_NAME)==0)
			{
				role_index=ROLE_RECYCLER;
			}
			token_start = buf+i+1;
		}
		if(buf[i]=='\n')
			//遇到换行符了
		{
			line_start = buf +i +1;
		}
		//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
		if(buf[i]==',' || buf[i]==';')
			//到了一个token的终点
		{
			//[token_start,buf+i)是一个token
			buf[i]=0;
			if((buf+i-token_start)<4)
				//明显不是一个token
			{
				;
			}
			else
			{
				
				//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
				if(strcmp((const char *)token_start,"SYSCALL_CONNECT")==0)
					//具有SYSCALL_CONNECT权限
				{
					all_roles[role_index].right |=SYSCALL_CONNECT;
				}
				//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
				if(strcmp((const char *)token_start,"SYSCALL_SOCKET")==0)
				{
					all_roles[role_index].right |= SYSCALL_SOCKET;
				}
				//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
				if(strcmp((const char *)token_start,"SYSCALL_MKDIR")==0)
				{
					all_roles[role_index].right |=SYSCALL_MKDIR;
				}
				//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
				if(strcmp((const char *)token_start,"SYSCALL_RMDIR")==0)
				{
					all_roles[role_index].right |=SYSCALL_RMDIR;
				}
				//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
				if(strcmp((const char *)token_start,"SYSCALL_TASK_CREATE")==0)
				{
					all_roles[role_index].right |= SYSCALL_TASK_CREATE;
				}
			}
			token_start=buf+i+1;
		}
		i++;
	}
	set_fs(oldfs);
	filp_close(f,0);

	printk(KERN_INFO "load %d roles.\n",all_roles_cnt);
}


static void get_user_config(void)
{
	char buf[SAMPLE_MAX_BUF]={0};
	struct file * f=NULL;
	const char * filename =USER_CONFIG;
	char * p;
	int i=0;
	char * line_start;
	char * token_start;
	printk(KERN_INFO "get user config from %s.\n",filename);
	mm_segment_t oldfs;

	f =filp_open(filename,O_RDONLY,0);
	if( IS_ERR(f) || (f==NULL))
	{
		printk(KERN_WARNING "get user config error.\n");
		return ;
	}
	p=buf;
	line_start = buf;
	token_start=buf;
	int user_index =0;
	oldfs =get_fs();
	//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
	set_fs(KERNEL_DS);
	//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
	while(vfs_read(f,buf+i,1,&f->f_pos)==1)
	{
		//printk(KERN_INFO "%s::%d.\n",__FUNCTION__,__LINE__);
		if(i==SAMPLE_MAX_BUF)
			//读满缓存区
		{
			break;
		}
		if(buf[i]==':')
			//读到用户了
		{
			unsigned int userid = sample_asc2int(line_start,buf+i-line_start);
			printk(KERN_INFO "read userid of %d.\n",userid);
			if(all_users_cnt)
			{
				printk(KERN_INFO "last user ::%d,right:%x.\n",all_users[all_users_cnt-1].userid,all_users[all_users_cnt-1].right);
			}
			all_users[all_users_cnt++].userid =userid;
			user_index = all_users_cnt-1;
			token_start = buf+i+1;
		}
		//TODO
		if(buf[i]=='\n')
			//遇到换行符了
		{
			line_start = buf +i +1;
		}
		if(buf[i]==',' || buf[i]==';')
			//到了一个token的终点
		{
			//[token_start,buf+i)是一个token
			buf[i]=0;
			if((buf+i-token_start)<5)
				//明显不是一个token,这有可能为空
			{
				;
			}
			else
			{
				if(strcmp((const char *)token_start,ROLE_ADMIN_NAME)==0)
				{
					all_users[user_index].right |=all_roles[ROLE_ADMIN].right;
				}
				if(strcmp((const char *)token_start,ROLE_OPERATOR_NAME)==0)
				{
					all_users[user_index].right |=all_roles[ROLE_OPERATOR].right;
				}
				if(strcmp((const char *)token_start,ROLE_RECYCLER_NAME)==0)
				{
					all_users[user_index].right |=all_roles[ROLE_RECYCLER].right;
				}
				if(strcmp((const char *)token_start,ROLE_NETMANAGER_NAME)==0)
				{
					all_users[user_index].right |=all_roles[ROLE_NETMANAGER].right;
				}
			}
			token_start=buf+i+1;
		}
		i++;
	}
		set_fs(oldfs);
	filp_close(f,0);

	printk(KERN_INFO "load %d user.\n",all_users_cnt);
}

static struct security_hook_list demo_hooks[]=
{
	LSM_HOOK_INIT(socket_connect,sample_socket_connect),
	LSM_HOOK_INIT(socket_create,sample_socket),
	LSM_HOOK_INIT(task_create,sample_task_create),
	LSM_HOOK_INIT(inode_mkdir,sample_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir,sample_inode_rmdir)
};


static  int sample_init(void)
{

	printk(KERN_INFO "ADD LSM SAMPLE.\n");
	printk(KERN_INFO "LOAD ROLE CONFIG.\n");//载入role config;
	get_role_config();
	printk(KERN_INFO "LOAD USER CONFIG.\n");//载入user config;
	get_user_config();
	security_add_hooks(demo_hooks,ARRAY_SIZE(demo_hooks));
	printk(KERN_INFO "Sample:  Initializing.\n");

	return 0;
}

static  void sample_exit(void)
{
	printk(KERN_INFO "Sample: Exiting.\n");	
}



module_init(sample_init);


module_exit(sample_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JMH");
MODULE_DESCRIPTION("A LSM Driver implements RBAC");
