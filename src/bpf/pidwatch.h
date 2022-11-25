#ifndef __PIDWATCH_H
#define __PIDWATCH_H

struct event {
    int exit_code;
    __u32 signaled;
    bool oom;
};

#endif  // __PIDWATCH_H
