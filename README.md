## android-native
> Android kernel source analysis 👨‍💻
> Understanding Android Kernel by analyzing the su command procedure

### su Source
- /android-framework/external/toybox/toys/lsb/su.c
```c
#define FOR_su
#include "toys.h"

GLOBALS(
  char *s;
  char *c;
)

static char *snapshot_env(char *name)
{
  char *s = getenv(name);

  if (s) return xmprintf("%s=%s", name, s);

  return 0;
}

void su_main()
{
  char *name, *passhash = 0, **argu, **argv;
  struct passwd *up;
  struct spwd *shp;

  if (*toys.optargs && !strcmp("-", *toys.optargs)) {
    toys.optflags |= FLAG_l;
    toys.optargs++;
  }

  if (*toys.optargs) name = *(toys.optargs++);
  else name = "root";

  if (!(shp = getspnam(name))) perror_exit("no '%s'", name);
  if (getuid()) {
    if (*shp->sp_pwdp != '$') goto deny;
    if (read_password(toybuf, sizeof(toybuf), "Password: ")) goto deny;
    passhash = crypt(toybuf, shp->sp_pwdp);
    memset(toybuf, 0, sizeof(toybuf));
    if (!passhash || strcmp(passhash, shp->sp_pwdp)) goto deny;
  }

  up = xgetpwnam(name);
  xsetuser(up);

  argv = argu = xmalloc(sizeof(char *)*(toys.optc + 4));
  *(argv++) = TT.s ? TT.s : up->pw_shell;

  if (toys.optflags & FLAG_l) {
    int i;
    char *stuff[] = {snapshot_env("TERM"), snapshot_env("DISPLAY"),
      snapshot_env("COLORTERM"), snapshot_env("XAUTHORITY")};

    clearenv();
    for (i=0; i < ARRAY_LEN(stuff); i++) if (stuff[i]) putenv(stuff[i]);
    *(argv++) = "-l";
    xchdir(up->pw_dir);
  } else unsetenv("IFS");
  setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
  if (!(toys.optflags & (FLAG_m|FLAG_p))) {
    setenv("HOME", up->pw_dir, 1);
    setenv("SHELL", up->pw_shell, 1);
    setenv("USER", up->pw_name, 1);
    setenv("LOGNAME", up->pw_name, 1);
  } else unsetenv("IFS");

  if (toys.optflags & FLAG_c) {
    *(argv++) = "-c";
    *(argv++) = TT.c;
  }
  while ((*(argv++) = *(toys.optargs++)));
  xexec(argu);

deny:
  puts("No.");
  toys.exitval = 1;
}
```

### xsetuser Source
- /android-framework/external/toybox/lib/xwrap.c
```c
void xsetuser(struct passwd *pwd)
{
  if (initgroups(pwd->pw_name, pwd->pw_gid) || setgid(pwd->pw_uid)
      || setuid(pwd->pw_uid)) perror_exit("xsetuser '%s'", pwd->pw_name);
}
```

### setuid Source
- /android-framework/bionic/libc/arch-arm64/syscalls/setuid.S
- su > xsetuser > setuid > syscall > svc > Elevation of privilege
- svc: supervisor call
```c
#include <private/bionic_asm.h>

ENTRY(setuid)
    mov     x8, __NR_setuid
    svc     #0

    cmn     x0, #(MAX_ERRNO + 1)
    cneg    x0, x0, hi
    b.hi    __set_errno_internal

    ret
END(setuid)
```

### setuid Kernel Source
- /android-kernel/crosshatch-4.9-pie-qpr2/private/msm-google/kernel/sys.c
```c
SYSCALL_DEFINE1(setuid, uid_t, uid)
{
    struct user_namespace *ns = current_user_ns();
    const struct cred *old;
    struct cred *new;
    int retval;
    kuid_t kuid;

    kuid = make_kuid(ns, uid);
    if (!uid_valid(kuid))
        return -EINVAL;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;
    old = current_cred();

    retval = -EPERM;
    if (ns_capable(old->user_ns, CAP_SETUID)) {
        new->suid = new->uid = kuid;
        if (!uid_eq(kuid, old->uid)) {
            retval = set_user(new);
            if (retval < 0)
                goto error;
        }
    } else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid)) {
        goto error;
    }

    new->fsuid = new->euid = kuid;

    retval = security_task_fix_setuid(new, old, LSM_SETID_ID);
    if (retval < 0)
        goto error;

    return commit_creds(new);

error:
    abort_creds(new);
    return retval;
}
```

### prepare_creds Kernel Source
- /android-kernel/crosshatch-4.9-pie-qpr2/private/msm-google/kernel/cred.c
```c
struct cred *prepare_creds(void)
{
    struct task_struct *task = current;
    const struct cred *old;
    struct cred *new;

    validate_process_creds();

    new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
    if (!new)
        return NULL;

    kdebug("prepare_creds() alloc %p", new);

    old = task->cred;
    memcpy(new, old, sizeof(struct cred));

    atomic_set(&new->usage, 1);
    set_cred_subscribers(new, 0);
    get_group_info(new->group_info);
    get_uid(new->user);
    get_user_ns(new->user_ns);

#ifdef CONFIG_KEYS
    key_get(new->session_keyring);
    key_get(new->process_keyring);
    key_get(new->thread_keyring);
    key_get(new->request_key_auth);
#endif

#ifdef CONFIG_SECURITY
    new->security = NULL;
#endif

    if (security_prepare_creds(new, old, GFP_KERNEL) < 0)
        goto error;
    validate_creds(new);
    return new;

error:
    abort_creds(new);
    return NULL;
}
EXPORT_SYMBOL(prepare_creds);
```

### Process Descirptor & task_struct
> ![image](https://user-images.githubusercontent.com/20378368/129667724-13526fd1-5f09-4827-a769-f06f15c267e4.png)
- /android-kernel/crosshatch-4.9-pie-qpr2/private/msm-google/include/linux/sched.h
- Kernel stores process list in the form of a circular double linked list called the **task-list**.
- In <linux/sched.h>, each item of the task list, task_struct is defined.
- task_struct
    - Large structure reaching 1.7KB
    - File in use, process address space
    - Waiting signal, process status, running program, etc.
- task_struct structure is allocated using stab allocator

### cred Struct Source
- /android-kernel/crosshatch-4.9-pie-qpr2/private/msm-google/include/linux/cred.h
```c
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC  0x43736564
#define CRED_MAGIC_DEAD 0x44656144
#endif
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;  /* caps we're permitted */
    kernel_cap_t    cap_effective;  /* caps we can actually use */
    kernel_cap_t    cap_bset;   /* capability bounding set */
    kernel_cap_t    cap_ambient;    /* Ambient capability set */
#ifdef CONFIG_KEYS
    unsigned char   jit_keyring;    /* default keyring to attach requested
                     * keys to */
    struct key __rcu *session_keyring; /* keyring inherited over fork */
    struct key  *process_keyring; /* keyring private to this process */
    struct key  *thread_keyring; /* keyring private to this thread */
    struct key  *request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
    void        *security;  /* subjective LSM security */
#endif
    struct user_struct *user;   /* real user ID subscription */
    struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
    struct group_info *group_info;  /* supplementary groups for euid/fsgid */
    struct rcu_head rcu;        /* RCU deletion hook */
};
```

#### To recap, su command is the process of putting 0 into the uid of the cred structure ✨
