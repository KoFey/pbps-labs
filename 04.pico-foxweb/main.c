#include "httpd.h"
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <openssl/md5.h>
#include "auth_ldap.h"


#define CHUNK_SIZE 1024 // read 1024 bytes at a time

// Public directory settings
#define PUBLIC_DIR "/var/www/picofoxweb/webroot"
#define INDEX_HTML "/index.html"
#define NOT_FOUND_HTML "/404.html"

int main(int c, char **v) {
  char *port = c == 1 ? "8000" : v[1];
  openlog("picofoxweb", LOG_PID | LOG_CONS, LOG_DAEMON);
  syslog(LOG_INFO, "Сервер запущен. Порт: %s, Рабочий каталог: %s", port, PUBLIC_DIR);
  serve_forever(port);
  return 0;
}

int file_exists(const char *file_name) {
  struct stat buffer;
  int exists;

  exists = (stat(file_name, &buffer) == 0);

  return exists;
}

int read_file(const char *file_name) {
  char buf[CHUNK_SIZE];
  FILE *file;
  size_t nread;
  int err = 1;

  file = fopen(file_name, "r");

  if (file) {
    while ((nread = fread(buf, 1, sizeof buf, file)) > 0)
      fwrite(buf, 1, nread, stdout);

    err = ferror(file);
    fclose(file);
  }
  return err;
}

void log_request(const char *client_ip, const char *user_id, const char *method, const char *res, const char *proto, int resp_code, int ret_size) {
  FILE *log_file = fopen("/var/log/foxweb.log", "a");
  if (!log_file) {
    syslog(LOG_ERR, "Не удалось открыть файл журнала /var/log/foxweb.log");
    return;
  }

  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  char date_str[30];

  strftime(date_str, sizeof(date_str), "%d/%b/%Y:%H:%M:%S %z", tm_info);

  fprintf(log_file, "%s - %s [%s] \"%s %s %s\" %d %d\n",
          client_ip,
          user_id ? user_id : "-",
          date_str,
          method,
          res,
          proto,
          resp_code,
          ret_size);

  fclose(log_file);
}

int get_file_size(const char *file_name) {
  struct stat st;
  if (stat(file_name, &st) == 0)
    return st.st_size;
  return 0;
}

void route() {
  ROUTE_START()

  GET("/") {
    char index_html[20];
    sprintf(index_html, "%s%s", PUBLIC_DIR, INDEX_HTML);

    HTTP_200;
    if (file_exists(index_html)) {
      read_file(index_html);
      log_request(request_header("X-Forwarded-For") ? request_header("X-Forwarded-For") : "127.0.0.1", "-", "GET", "/", "HTTP/1.1", 200, get_file_size(index_html));
    } else {
      printf("Hello! You are using %s\n\n", request_header("User-Agent"));
      log_request(request_header("X-Forwarded-For") ? request_header("X-Forwarded-For") : "127.0.0.1", "-", "GET", "/", "HTTP/1.1", 200, 0);
    }
  }

  GET("/test") {
    HTTP_200;
    char response_buffer[4096];
    int offset = 0;

    printf("List of request headers:\n\n");
    offset += snprintf(response_buffer + offset, sizeof(response_buffer) - offset, "List of request headers:\n\n");

    header_t *h = request_headers();

    while (h->name) {
      printf("%s: %s\n", h->name, h->value);
      offset += snprintf(response_buffer + offset, sizeof(response_buffer) - offset, "%s: %s\n", h->name, h->value);
      h++;
    }
    log_request(request_header("X-Forwarded-For") ? request_header("X-Forwarded-For") : "127.0.0.1","-",  "GET", "/test", "HTTP/1.1" ,200, offset);
  }

  POST("/") {
    HTTP_201;
    printf("Wow, seems that you POSTed %d bytes.\n", payload_size);
    printf("Fetch the data using `payload` variable.\n");
    if (payload_size > 0)
      printf("Request body: %s", payload);
    log_request(request_header("X-Forwarded-For") ? request_header("X-Forwarded-For") : "127.0.0.1", "-", "POST", "/", "HTTP/1.1",  201, payload_size);
  }

  GET(uri) {
    char file_name[255];
    sprintf(file_name, "%s%s", PUBLIC_DIR, uri);

    if (file_exists(file_name)) {
      HTTP_200;
      read_file(file_name);
      log_request(request_header("X-Forwarded-For") ? request_header("X-Forwarded-For") : "127.0.0.1", "-", "GET", uri, "HTTP/1.1",  200, get_file_size(file_name));
    } else {
      HTTP_404;
      sprintf(file_name, "%s%s", PUBLIC_DIR, NOT_FOUND_HTML);
      if (file_exists(file_name))
        read_file(file_name);
      log_request(request_header("X-Forwarded-For") ? request_header("X-Forwarded-For") : "127.0.0.1", "-", "GET", uri, "HTTP/1.1", 404, 0);
    }
  }

  ROUTE_END()
}
