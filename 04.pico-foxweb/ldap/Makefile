# Makefile for LDAP provisioning
LDAP_ADMIN_DN = cn=admin,dc=nodomain
LDAP_PASS ?= 

# LDIF files to add
LDIF_FILES = \
    base.ldif \
    add_ou_users.ldif \
    newuser.ldif

.PHONY: all apply clean

all:
	@echo "Use: make apply LDAP_PASS=your_admin_password"

apply:
	@if [ -z "$(LDAP_PASS)" ]; then \
		echo "Error: provide LDAP_PASS (e.g. make apply LDAP_PASS=secret)"; \
		exit 1; \
	fi
	@for file in $(LDIF_FILES); do \
		echo "Applying $$file..."; \
		ldapadd -x -D "$(LDAP_ADMIN_DN)" -w "$(LDAP_PASS)" -f $$file || \
		if [ $$? -eq 68 ]; then echo "  → Entry already exists, skipping."; else exit 1; fi; \
	done

clean:
	rm -f *.rej *.bak

