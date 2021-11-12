CC = clang

BUILDDIR = build
SRCDIR = src

LIBBPFSRC = libbpf/src
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/libbpf_errno.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o $(LIBBPFSRC)/staticobjs/netlink.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/nlattr.o $(LIBBPFSRC)/staticobjs/str_error.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/xsk.o

LOADERSRC = loader.c
LOADEROUT = xdpstats
LOADERFLAGS = -lpthread -lelf -lz

RAWXDPSRC = xdp/raw_xdp.c
RAWXDPBC = raw_xdp.bc
RAWXDPOBJ = raw_xdp.o

RAWXDPTXSRC = xdp/raw_xdp_tx.c
RAWXDPTXBC = raw_xdp_tx.bc
RAWXDPTXOBJ = raw_xdp_tx.o

AFXDPSRC = af_xdp/af_xdp.c
AFXDPOBJ = af_xdp.o
AFXDPRAWSRC = af_xdp/raw_xdp.c
AFXDPRAWBC = afxdp_raw.bc
AFXDPRAWOBJ = afxdp_raw.o
AFXDPRAWTXSRC = af_xdp/raw_xdp_tx.c
AFXDPRAWTXBC = afxdp_raw_tx.bc
AFXDPRAWTXOBJ = afxdp_raw_tx.o

INCS = -I $(LIBBPFSRC)

all: rawxdp rawxdptx afxdp loader
rawxdp:
	mkdir -p $(BUILDDIR)
	$(CC) $(INCS) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c $(SRCDIR)/$(RAWXDPSRC) -o $(BUILDDIR)/$(RAWXDPBC)
	llc -march=bpf -filetype=obj $(BUILDDIR)/$(RAWXDPBC) -o $(BUILDDIR)/$(RAWXDPOBJ)
rawxdptx:
	mkdir -p $(BUILDDIR)
	$(CC) $(INCS) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c $(SRCDIR)/$(RAWXDPTXSRC) -o $(BUILDDIR)/$(RAWXDPTXBC)
	llc -march=bpf -filetype=obj $(BUILDDIR)/$(RAWXDPTXBC) -o $(BUILDDIR)/$(RAWXDPTXOBJ)
afxdp: libbpf
	mkdir -p $(BUILDDIR)
	$(CC) $(INCS) -O2 -c -o $(BUILDDIR)/$(AFXDPOBJ) $(SRCDIR)/$(AFXDPSRC)
	$(CC) $(INCS) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c $(SRCDIR)/$(AFXDPRAWSRC) -o $(BUILDDIR)/$(AFXDPRAWBC)
	llc -march=bpf -filetype=obj $(BUILDDIR)/$(AFXDPRAWBC) -o $(BUILDDIR)/$(AFXDPRAWOBJ)
	$(CC) $(INCS) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c $(SRCDIR)/$(AFXDPRAWTXSRC) -o $(BUILDDIR)/$(AFXDPRAWTXBC)
	llc -march=bpf -filetype=obj $(BUILDDIR)/$(AFXDPRAWTXBC) -o $(BUILDDIR)/$(AFXDPRAWTXOBJ)
loader: libbpf
	mkdir -p $(BUILDDIR)
	$(CC) $(INCS) $(LOADERFLAGS) -O3 -o $(BUILDDIR)/$(LOADEROUT) $(LIBBPFOBJS) $(BUILDDIR)/$(AFXDPOBJ) $(SRCDIR)/$(LOADERSRC)
libbpf:
	$(MAKE) -C $(LIBBPFSRC)
install:
	mkdir -p /etc/xdpstats
	cp $(BUILDDIR)/$(RAWXDPOBJ) /etc/xdpstats/$(RAWXDPOBJ)
	cp $(BUILDDIR)/$(RAWXDPTXOBJ) /etc/xdpstats/$(RAWXDPTXOBJ)
	cp $(BUILDDIR)/$(AFXDPRAWOBJ) /etc/xdpstats/$(AFXDPRAWOBJ)
	cp $(BUILDDIR)/$(LOADEROUT) /usr/bin/$(LOADEROUT)
clean:
	$(MAKE) -C $(LIBBPFSRC) clean
	rm -f $(BUILDDIR)/*
.PHONY: libbpf rawxdp rawxdptx afxdp loader
.DEFAULT: all