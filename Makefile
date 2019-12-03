NAME= tinysipproxy
CFLAGS= -Wall -Wextra -O0 -g3

default: $(NAME)

all: $(NAME) openwrt

clean:
	-$(RM) $(NAME)
	-$(RM) $(NAME)_*.ipk
	$(MAKE) -C openwrt $@

$(NAME): $(NAME).c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $?

openwrt:
	$(MAKE) -C $@
	-mv openwrt/*.ipk .

.PHONY: default all clean openwrt
