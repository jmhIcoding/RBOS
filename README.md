# RBOS
为linux内核添加基于角色的访问控制功能.
# 需求
1. 定义好两类角色:

	***recycler***:资源回收角色,可删除文件

	***operator***:普通操作员,不能删除文件
2. 定义权限:

  	***RIGHT_DELETE***:删除文件

3. 角色和权限的管理:可以把权限分配给角色;
4. 用户角色分配:可以给用户分配一定的角色;

# 实现原理
1. 实现LSM模块
2. 对文件删除系统调用进行hook.
首先需要定位出 rm 命令在删除文件时会使用到的系统调用,可以通过strace命令最终rm命令的执行过程。
例如：
```
jmh@ubuntu:~$ strace rm test 
execve("/bin/rm", ["rm", "test"], [/* 59 vars */]) = 0
brk(0)                                  = 0x1267000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f655af12000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=89943, ...}) = 0
mmap(NULL, 89943, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f655aefc000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P \2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1840928, ...}) = 0
mmap(NULL, 3949248, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f655a92d000
mprotect(0x7f655aae7000, 2097152, PROT_NONE) = 0
mmap(0x7f655ace7000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1ba000) = 0x7f655ace7000
mmap(0x7f655aced000, 17088, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f655aced000
close(3)                                = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f655aefb000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f655aef9000
arch_prctl(ARCH_SET_FS, 0x7f655aef9740) = 0
mprotect(0x7f655ace7000, 16384, PROT_READ) = 0
mprotect(0x60d000, 4096, PROT_READ)     = 0
mprotect(0x7f655af14000, 4096, PROT_READ) = 0
munmap(0x7f655aefc000, 89943)           = 0
brk(0)                                  = 0x1267000
brk(0x1288000)                          = 0x1288000
open("/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=7216688, ...}) = 0
mmap(NULL, 7216688, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f655a24b000
close(3)                                = 0
ioctl(0, SNDCTL_TMR_TIMEBASE or SNDRV_TIMER_IOCTL_NEXT_DEVICE or TCGETS, {B38400 opost isig icanon echo ...}) = 0
newfstatat(AT_FDCWD, "test", {st_mode=S_IFREG|0664, st_size=6, ...}, AT_SYMLINK_NOFOLLOW) = 0
geteuid()                               = 1000
newfstatat(AT_FDCWD, "test", {st_mode=S_IFREG|0664, st_size=6, ...}, AT_SYMLINK_NOFOLLOW) = 0
faccessat(AT_FDCWD, "test", W_OK)       = 0
unlinkat(AT_FDCWD, "test", 0)           = 0
lseek(0, 0, SEEK_CUR)                   = -1 ESPIPE (Illegal seek)
close(0)                                = 0
close(1)                                = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++

```
可以很清楚的看出 unlinkat 是删除文件时关键系统调用.通过查看unlinkat的说明,也可以佐证这一点。
```
       The unlinkat() system call operates in exactly the same way  as  either
       unlink(2)  or  rmdir(2) (depending on whether or not flags includes the
       AT_REMOVEDIR flag) except for the differences described in this  manual
       page.
```
同时,unlink也是一个删除文件时常用的系统调用;

因此,我们可以确定要hook的系统调用为：unlink以及unlinkat,通过在这两个函数加入自定义的删除权限判断即可。

如果发现当前进程的current->uid和euid是有相应权限的,那么调用原unlink函数,返回对应unlink执行的结果；否则,返回错误信息即可。

3. 将角色,权限,用户ID之间的关系作为配置文件写入文件系统内,在内核中读配置文件;配置文件的组织形式：

/etc/rbos/role_config :角色拥有的权限
```
operator:NONE
recycler:DELETE
```
/etc/rbos/user_config: 用户所属的角色;默认全部为recycler,只有显式配置为operator的用户才具有相应的角色;root默认配置有recycler角色

```
1000:operator
```
