#ifndef __PIDWATCH_H
#define __PIDWATCH_H

struct event {
    int exit_code;
    __u32 signaled_exit_code;
    bool oom_killed;
};

#endif  // __PIDWATCH_H
