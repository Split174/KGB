CLANG ?= clang
CFLAGS := -O2 -g -target bpf \
    $(BPF_CFLAGS) \
    -D__KERNEL__ \
    -D__BPF_TRACING__ \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-gnu-variable-sized-type-not-at-end \
    -Wno-address-of-packed-member \
    -Wno-tautological-compare \
    -Wno-unknown-warning-option \
    -fno-stack-protector \
    -fno-jump-tables \
    -fno-unwind-tables \
    -fno-asynchronous-unwind-tables

xdp_filter.o: xdp_filter.c
	$(CLANG) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o
