CC      = gcc
CFLAGS  = -Wall -Wextra -O2
BINS    = frontend backend

.PHONY: all clean setup

all: $(BINS)

frontend: frontend.c common.h
	$(CC) $(CFLAGS) -o frontend frontend.c

backend: backend.c common.h
	$(CC) $(CFLAGS) -o backend backend.c

# Creates a demo protected_users.db (mode 600, root:root) and installs
# backend as a setuid-root binary. Must be run with sudo, e.g.:
#   sudo make setup
setup: all
	@echo "ujjwal:password123" > protected_users.db
	chown root:root protected_users.db
	chmod 600 protected_users.db
	chown root:root backend
	chmod u+s backend
	@echo "Setup complete. protected_users.db and setuid-root backend are in place."
	@echo "Demo credentials -> username: ujjwal  password: password123"

clean:
	rm -f $(BINS)
