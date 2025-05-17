#define LDAP_DEPRECATED 1
#include "auth_ldap.h"
#include <ldap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>

#define DIGEST_ATTR "userPassword"
#define REALM "myrealm"
#define LDAP_URI "ldap://localhost"
#define BASE_DN "dc=nodomain"
#define USER_DN_FMT "uid=%s,ou=users," BASE_DN

int authenticate_user(const char *username, const char *password) {
	LDAP *ld;
	int result;
    char user_dn[256];

    snprintf(user_dn, sizeof(user_dn), USER_DN_FMT, username);

    result = ldap_initialize(&ld, LDAP_URI);
    if (result != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_initialize failed: %s\n", ldap_err2string(result));
        return 0;
    }

    int version = LDAP_VERSION3;
ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    // Простой bind
    result = ldap_simple_bind_s(ld, user_dn, password);
    ldap_unbind_ext_s(ld, NULL, NULL);

        printf( "pswd %s\n", password);
    if (result != LDAP_SUCCESS) {
        fprintf(stderr, "LDAP bind failed for %s: %s\n", user_dn, ldap_err2string(result));
        return 0;
    }
    return 1;
}

char *get_ha1_by_username(const char *username) {
    LDAP *ld;
    int result;
    char filter[128];
    char *attrs[] = { DIGEST_ATTR, NULL };
    LDAPMessage *res, *entry;
    char *ha1_value = NULL;

    result = ldap_initialize(&ld, LDAP_URI);
    if (result != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_initialize failed: %s\n", ldap_err2string(result));
        return NULL;
    }

    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    result = ldap_simple_bind_s(ld, "cn=admin,dc=nodomain", "admin");
    if (result != LDAP_SUCCESS) {
        fprintf(stderr, "LDAP bind failed: %s\n", ldap_err2string(result));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }

    snprintf(filter, sizeof(filter), "uid=%s", username);
    result = ldap_search_ext_s(ld, BASE_DN, LDAP_SCOPE_SUBTREE,
                                filter, attrs, 0, NULL, NULL, NULL, 0, &res);
    if (result != LDAP_SUCCESS) {
        fprintf(stderr, "LDAP search failed: %s\n", ldap_err2string(result));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }


    entry = ldap_first_entry(ld, res);
    if (entry) {
        char **values = ldap_get_values(ld, entry, DIGEST_ATTR);
	if (values && values[0]) {
    	   if (strncmp(values[0], "{HA1}", 5) == 0)
               ha1_value = strdup(values[0] + 5);  // Пропустить "{HA1}"
    	   else
               ha1_value = strdup(values[0]);
         ldap_value_free(values);
         }
    }

    ldap_msgfree(res);
    ldap_unbind_ext_s(ld, NULL, NULL);

    return ha1_value;  
}

void md5hex(const char *input, char *output) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input, strlen(input), digest);

    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        sprintf(&output[i * 2], "%02x", digest[i]);

    output[32] = '\0'; // null-terminator
}

bool check_digest_auth(const char *method, const char *uri, header_t *headers) {
    char *auth = get_header(headers, "Authorization");
    if (!auth || strncmp(auth, "Digest ", 7) != 0)
        return false;

    char username[64], realm[64], nonce[128], opaque[128], response[64], digest_uri[128];
    char cnonce[128], nc[64], qop[64];

    int parsed = sscanf(auth,
        "Digest username=\"%63[^\"]\", realm=\"%63[^\"]\", nonce=\"%127[^\"]\", uri=\"%127[^\"]\", "
        "response=\"%63[^\"]\", opaque=\"%127[^\"]\", qop=\"%63[^\"]\", nc=\"%63[^\"]\", cnonce=\"%127[^\"]\"",
        username, realm, nonce, digest_uri, response, opaque, qop, nc, cnonce);

    if (parsed < 6) return false;
    if (strcmp(realm, REALM) != 0) return false;

    // Получаем HA1 вместо plain password
    const char *stored_ha1 = get_ha1_by_username(username);
    if (!stored_ha1) {
	    free((void *)stored_ha1);
	    return false;
    }

    // HA2 = MD5(method:uri)
    char ha2src[256], ha2[33];
    snprintf(ha2src, sizeof(ha2src), "%s:%s", method, digest_uri);
    md5hex(ha2src, ha2);

    // Final response = MD5(HA1:nonce:HA2)
    char finalsrc[512], expected[33];
    snprintf(finalsrc, sizeof(finalsrc), "%s:%s:%s", stored_ha1, nonce, ha2);
    md5hex(finalsrc, expected);

    return strcmp(expected, response) == 0;
}



void send_unauthorized() {
  const char *nonce = "123456";
  const char *opaque = "5ccc069c403dafe9f0171e9517f40e41";

  printf("HTTP/1.1 401 Unauthorized\r\n");
  printf("WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", opaque=\"%s\"\r\n", REALM, nonce, opaque);
  printf("Content-Type: text/plain\r\n");
  printf("Content-Length: 25\r\n");
  printf("\r\n");
  printf("Authorization required.\n");
}
char *get_header(header_t *headers, const char *name) {
  for (header_t *h = headers; h->name; h++) {
    if (strcasecmp(h->name, name) == 0)
      return h->value;
  }
  return NULL;
}

