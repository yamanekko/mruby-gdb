#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "mruby.h"
#include "mruby/compile.h"
#include "mruby/irep.h"
#include "mruby/debug.h"
#include "mruby/opcode.h"
#include "mruby/value.h"
#include "mruby/string.h"
#include "mruby/array.h"
#include "mruby/proc.h"

#include "mruby_gdb.h"

const char *prev_filename = NULL;
const char * filename = NULL;
char ret[RETURN_BUF_SIZE];
int32_t prev_line = -1;
int32_t prev_ciidx = 999;
int32_t line = -1;
int32_t prev_callinfo_size = 0;

static int
local_size(struct mrb_irep *irep){
    return irep->nlocals;
}

volatile int
md_strcmp(const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}

static mrb_int
mrb_gdb_get_callinfosize(mrb_state *mrb)
{
    mrb_int len = 0;
    mrb_callinfo *ci;
    mrb_int ciidx;
    int i;
    int lineno = -1;
    
    ciidx = mrb->c->ci - mrb->c->cibase;
    
    for (i = ciidx; i >= 0; i--) {
        ci = &mrb->c->cibase[i];
        if (MRB_PROC_CFUNC_P(ci->proc)) {
            continue;
        }else {
            mrb_irep *irep = ci->proc->body.irep;
            mrb_code *pc;
            
            if (mrb->c->cibase[i].err) {
                pc = mrb->c->cibase[i].err;
            }else if (i+1 <= ciidx) {
                pc = mrb->c->cibase[i+1].pc - 1;
            }else {
                pc = ci->pc; //continue;
            }
            lineno = mrb_debug_get_line(irep, pc - irep->iseq);
        }
        if (lineno == -1){
            continue;
        }
        len++;
    }
    return len;
}

static mrb_value
mrb_gdb_get_callinfosize_m(mrb_state *mrb, mrb_value self)
{
    mrb_int len = mrb_gdb_get_callinfosize(mrb);
    return mrb_fixnum_value(len);
}

MRB_API void
mrb_gdb_code_fetch(struct mrb_state* mrb, struct mrb_irep *irep, mrb_code *pc, mrb_value *regs)
{
    filename = mrb_debug_get_filename(irep, pc - irep->iseq);
    line = mrb_debug_get_line(irep, pc - irep->iseq);
    if(filename==NULL || line== -1){
        return;
    }
    if (prev_filename && filename && strcmp(prev_filename, filename) == 0 && prev_line == line) {
        return;
    }
    if (filename && line >= 0) {	// breakpoints line number
        int len = (int)mrb_gdb_get_callinfosize(mrb);
        if(prev_ciidx == 999){
            //the first time, save the value
            prev_filename = filename;
            prev_line = line;
            prev_ciidx = len;
            return;
        }
        prev_filename = filename;
        prev_line = line;
        prev_ciidx = len;
    }
}

static char *
mrb_gdb_get_current(struct mrb_state *mrb)
{
    int32_t  ciidx;
    memset(ret, 0, sizeof(ret));
    
    ciidx = (int32_t)mrb_gdb_get_callinfosize(mrb);
    snprintf(ret, sizeof(ret), "result={name=\"%s\",line=\"%d\",ciidx=\"%d\"}", filename, line, ciidx);
    return ret;
}

static mrb_value
mrb_gdb_get_current_m(struct mrb_state *mrb, mrb_value self)
{
    char *str = mrb_gdb_get_current(mrb);
    return mrb_str_new_cstr(mrb, str);
}

static char *
mrb_gdb_get_locals(struct mrb_state* mrb){
    const char *symname;
    char buf[BUF_SIZE];
    int i = 0;
    int flg = 0;	//
    struct mrb_irep *irep;
    int local_len = 0;
    
    if(mrb == NULL){
        return "mrb_null";
    }
    memset(ret, 0, sizeof(ret));
    irep = mrb->c->ci->proc->body.irep;
    local_len = local_size(irep);
    strncpy(ret, "locals=[", sizeof(ret)-1);
    mrb->code_fetch_hook = NULL;
    for (i=0; i+1<local_len; i++) {
        if (irep->lv[i].name == 0){
            continue;
        }
        uint16_t reg = irep->lv[i].r;
        mrb_sym sym = irep->lv[i].name;if (!sym){ continue;}
        symname = mrb_sym2name(mrb, sym);
        mrb_value v2 = mrb->c->stack[reg];
        const char *v2_classname = mrb_obj_classname(mrb, v2);
        mrb_value v2_value = mrb_funcall(mrb, v2, "inspect", 0);
        char * v2_cstr = mrb_str_to_cstr(mrb, v2_value);
        snprintf(buf, sizeof(buf), "{name=\"%s\",value=\"%s\",type=\"%s\"}", symname, v2_cstr, v2_classname);
        if(flg == 1){
            strncat(ret, ",", sizeof(ret)-strlen(ret)-1);
        }
        strncat(ret, buf, sizeof(ret)-strlen(ret)-1);
        flg = 1;
    }
    mrb->code_fetch_hook = mrb_gdb_code_fetch;
    return ret;
}

static mrb_value
mrb_gdb_get_locals_m(struct mrb_state* mrb, mrb_value self)
{
    char *str = mrb_gdb_get_locals(mrb);
    return mrb_str_new_cstr(mrb, str);
}

static char *
mrb_gdb_get_localvalue(struct mrb_state* mrb, char *symname){
    char buf[BUF_SIZE];
    int i = 0;
    struct mrb_irep *irep;
    int local_len = 0;
    
    if(mrb == NULL){
        return "mrb_null";
    }
    if(symname == NULL){
        return "sym_null";
    }
    memset(ret, 0, sizeof(ret));
    mrb_sym sym2 = mrb_intern_cstr(mrb, symname);
    if(sym2 == 0){
        return "bad_sym_null";
    }
    
    irep = mrb->c->ci->proc->body.irep;
    if(irep != NULL){
        local_len = local_size(irep);
    }else{
        return "irep_null";
    }
    strncpy(ret, "result=", sizeof(ret)-1);
    for (i=0; i<local_len; i++) {
        mrb_sym sym = irep->lv[i].name;
        if(sym == sym2){
            uint16_t reg = irep->lv[i].r;
            mrb_value v2 = mrb->c->stack[reg];
            const char *v2_classname = mrb_obj_classname(mrb, v2);
            mrb->code_fetch_hook = NULL;
            mrb_value v2_value = mrb_funcall(mrb, v2, "inspect", 0);
            mrb->code_fetch_hook = mrb_gdb_code_fetch;
            char * v2_cstr = mrb_str_to_cstr(mrb, v2_value);
            snprintf(buf, sizeof(buf), "{name=\"%s\",value=\"%s\",type=\"%s\"}", symname, v2_cstr, v2_classname);
            strncat(ret, buf, sizeof(ret)-strlen(ret)-1);
        }
    }
    return ret;
}

static mrb_value
mrb_gdb_get_localvalue_m(struct mrb_state* mrb, mrb_value self)
{
    mrb_sym sym;
    const char *symname;
    char *localvalue;
    mrb_get_args(mrb, "n", &sym);
    symname = mrb_sym2name(mrb, sym);
    localvalue = mrb_gdb_get_localvalue(mrb, (char *)symname);
    return mrb_str_new_cstr(mrb, localvalue);
}

static mrb_value
mrb_gdb_initialize(mrb_state *mrb, mrb_value self)
{
    return self;
}

void
mrb_mruby_gdb_gem_init(mrb_state* mrb) {
    
    struct RClass *gdb;
    
    gdb = mrb_define_class(mrb, "Gdb", mrb->object_class);
    
    mrb_define_method(mrb, gdb, "initialize", mrb_gdb_initialize, ARGS_REQ(2));
    mrb_define_method(mrb, gdb, "callinfosize", mrb_gdb_get_callinfosize_m, ARGS_REQ(1));
    mrb_define_method(mrb, gdb, "current", mrb_gdb_get_current_m, ARGS_REQ(1));
    mrb_define_method(mrb, gdb, "locals", mrb_gdb_get_locals_m, ARGS_REQ(1));
    mrb_define_method(mrb, gdb, "local_value", mrb_gdb_get_localvalue_m, ARGS_REQ(2));
    
}

void
mrb_mruby_gdb_gem_final(mrb_state* mrb) {
    // finalizer
}
