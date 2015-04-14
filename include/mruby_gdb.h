#ifndef MRUBY_GDB_H
#define MRUBY_GDB_H

#define RETURN_BUF_SIZE 4096
#define BUF_SIZE 256

MRB_API void mrb_gdb_code_fetch(struct mrb_state* mrb, struct mrb_irep *irep, mrb_code *pc, mrb_value *regs);


#endif
