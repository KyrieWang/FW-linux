EXECUTABLE :=firewall#可执行文件名
LIBDIR := /usr/lib/# 静态库目录
LIBS := net netfilter_log# 静态库文件名
INCLUDES := /home/hehe/firewall/ /usr/local/src/libnfnetlink/include/ /usr/local/src/libnetfilter/include/ /usr/local/src/libnet/include/# 头文件目录
SRCDIR :=# 除了当前目录外，其他的源代码文件目录

CC:=gcc
CFLAGS := -Wall -O3
CPPFLAGS := $(CFLAGS)
CPPFLAGS += $(addprefix -I,$(INCLUDES))
CPPFLAGS += -MMD
#CPPFLAGS += -std=c++11

RM-F := rm -f

SRCS := $(wildcard *.c) $(wildcard $(addsuffix /*.c, $(SRCDIR)))
OBJS := $(patsubst %.c,%.o,$(SRCS))
DEPS := $(patsubst %.o,%.d,$(OBJS))
MISSING_DEPS := $(filter-out $(wildcard $(DEPS)),$(DEPS))
MISSING_DEPS_SOURCES := $(wildcard $(patsubst %.d,%.c,$(MISSING_DEPS)))

.PHONY : all deps objs clean veryclean rebuild info

all: $(EXECUTABLE)

deps : $(DEPS)

objs : $(OBJS)

clean :
	@$(RM-F) *.o
	@$(RM-F) *.d
veryclean: clean
	@$(RM-F) $(EXECUTABLE)

rebuild: veryclean all
ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	@$(RM-F) $(patsubst %.d,%.o,$@)
endif
-include $(DEPS)
$(EXECUTABLE) : $(OBJS)
	$(CC) -o $(EXECUTABLE) $(OBJS) $(addprefix -L,$(LIBDIR)) $(addprefix -l,$(LIBS))

info:
	@echo $(SRCS)
	@echo $(OBJS)
	@echo $(DEPS)
	@echo $(MISSING_DEPS)
	@echo $(MISSING_DEPS_SOURCES)