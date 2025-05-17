#ifndef AUTH_LDAP_H
#define AUTH_LDAP_H

#include "httpd.h" 
#include <stdbool.h>

int authenticate_user(const char *username, const char *password);
bool check_digest_auth(const char *method, const char *uri, header_t *headers);
void send_unauthorized(void);
char *get_header(header_t *headers, const char *name);

#endif

