#  This needs to be cleared explicitly, as the libfreeradius-json.mk
#  might not always be available, and the TARGETNAME from the previous
#  target may stick around.
TARGETNAME	:=
-include $(top_builddir)/src/lib/json/all.mk
TARGET		:=

#  Check the targetname defined by libfreeradius-json.mk
#  to verify we have json-c and the libfreeradius-json library.
ifneq "$(TARGETNAME)" ""
  TARGETNAME	:= 

  #  Check the targetname from the local configure script
  ifneq "$(TARGETNAME)" ""
    TARGET		:= $(TARGETNAME)$(L)
  endif
endif

SOURCES		:= $(TARGETNAME).c mod.c couchbase.c

SRC_CFLAGS	:= 
TGT_LDLIBS	:= 
TGT_PREREQS	:= libfreeradius-json.a

# TODO: create man page
#MAN		:= rlm_couchbase.8
LOG_ID_LIB	= 7
