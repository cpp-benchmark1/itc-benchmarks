AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -pthread
AM_LDFLAGS = -lm -ldl -lnsl -lsocket
bin_PROGRAMS = 01_w_Defects
01_w_Defects_SOURCES = \
HeaderFile.h \
bit_shift.c			       main.c \
buffer_overrun_dynamic.c	       memory_allocation_failure.c \
buffer_underrun_dynamic.c	       memory_leak.c \
cmp_funcadr.c			       not_return.c \
conflicting_cond.c		       null_pointer.c \
data_lost.c			       overrun_st.c \
data_overflow.c			       ow_memcpy.c \
data_underflow.c		       pow_related_errors.c \
dead_code.c			       ptr_subtraction.c \
dead_lock.c			       race_condition.c \
deletion_of_data_structure_sentinel.c  redundant_cond.c \
dl_injection.c			       return_local.c \
double_free.c			       sign_conv.c \
double_lock.c			       sleep_lock.c \
double_release.c		       st_cross_thread_access.c \
endless_loop.c			       st_overflow.c \
free_nondynamic_allocated_memory.c     stubs.c \
free_null_pointer.c		       st_underrun.c \
func_pointer.c			       underrun_st.c \
function_return_value_unchecked.c      uninit_memory_access.c \
improper_termination_of_block.c        uninit_pointer.c \
insign_code.c			       uninit_var.c \
invalid_extern_1.c		       unlock_without_lock.c \
invalid_extern.c		       unused_var.c \
invalid_memory_access.c		       wrong_arguments_func_pointer.c \
littlemem_st.c			       zero_division.c \
livelock.c			       lock_never_unlock.c
