#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + NAME_MAX + 1))
#define LOG_FILE    "file_monitor.log"

typedef struct {
    int fd;
    char *base_path;
    FILE *log;
    char *log_filename;
} ThreadData;

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t watch_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int wd;
    char *path;
} WatchEntry;

WatchEntry *watches = NULL;
int watch_count = 0;

/* Logging functions */
void write_log(FILE *log, const char *message) {
    time_t now = time(NULL);
    char timestr[20];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    pthread_mutex_lock(&log_mutex);
    fprintf(log, "[%s] %s\n", timestr, message);
    fflush(log);
    pthread_mutex_unlock(&log_mutex);
}

/* Watch management functions */
void add_watch_entry(int wd, const char *path) {
    watches = realloc(watches, (watch_count + 1) * sizeof(WatchEntry));
    watches[watch_count].wd = wd;
    watches[watch_count].path = strdup(path);
    watch_count++;
}

void add_watch(int fd, const char *path) {
    pthread_mutex_lock(&watch_mutex);
    
    int wd = inotify_add_watch(fd, path, 
                              IN_CREATE | IN_DELETE | IN_MODIFY |
                              IN_MOVED_FROM | IN_MOVED_TO | IN_ISDIR);
    if (wd == -1) {
        perror("inotify_add_watch");
        pthread_mutex_unlock(&watch_mutex);
        return;
    }

    add_watch_entry(wd, path);
    pthread_mutex_unlock(&watch_mutex);
}

char* get_path_by_wd(int wd) {
    pthread_mutex_lock(&watch_mutex);
    for (int i = 0; i < watch_count; i++) {
        if (watches[i].wd == wd) {
            char *path = strdup(watches[i].path);
            pthread_mutex_unlock(&watch_mutex);
            return path;
        }
    }
    pthread_mutex_unlock(&watch_mutex);
    return NULL;
}

/* File path functions */
int should_ignore(const char *path, const char *ignore_path) {
    char abs_path[PATH_MAX];
    char abs_ignore[PATH_MAX];
    
    if (realpath(path, abs_path) == NULL || realpath(ignore_path, abs_ignore) == NULL) {
        return 0;
    }

    return strcmp(abs_path, abs_ignore) == 0;
}

void build_full_path(char *full_path, size_t size, const char *base_path, const char *name) {
    if (name && *name) {
        snprintf(full_path, size, "%s/%s", base_path, name);
    } else {
        strncpy(full_path, base_path, size);
    }
}

/* Directory traversal functions */
void process_directory_entry(int fd, const char *base_path, const char *entry_name, const char *ignore_path) {
    if (strcmp(entry_name, ".") == 0 || strcmp(entry_name, "..") == 0) {
        return;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", base_path, entry_name);
    
    if (should_ignore(path, ignore_path)) {
        return;
    }

    add_watch(fd, path);
}

void setup_watches_recursive(int fd, const char *base_path, const char *ignore_path) {
    DIR *dir = opendir(base_path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            process_directory_entry(fd, base_path, entry->d_name, ignore_path);
        }
    }
    closedir(dir);
}

void setup_watches(int fd, const char *base_path, const char *ignore_path) {
    add_watch(fd, base_path);
    setup_watches_recursive(fd, base_path, ignore_path);
}

/* Event processing functions */
const char* get_event_type_name(uint32_t mask) {
    if (mask & IN_CREATE) return "CREATED";
    if (mask & IN_DELETE) return "DELETED";
    if (mask & IN_MODIFY) return "MODIFIED";
    if (mask & IN_MOVED_FROM) return "MOVED_FROM";
    if (mask & IN_MOVED_TO) return "MOVED_TO";
    return "UNKNOWN";
}

void handle_create_event(char *message, size_t size, const char *full_path, int is_dir) {
    snprintf(message, size, "%s %s: %s", 
            is_dir ? "DIR" : "FILE", 
            get_event_type_name(IN_CREATE), 
            full_path);
}

void handle_delete_event(char *message, size_t size, const char *full_path, int is_dir) {
    snprintf(message, size, "%s %s: %s", 
            is_dir ? "DIR" : "FILE", 
            get_event_type_name(IN_DELETE), 
            full_path);
}

void handle_modify_event(char *message, size_t size, const char *full_path, int is_dir) {
    snprintf(message, size, "%s %s: %s", 
            is_dir ? "DIR" : "FILE", 
            get_event_type_name(IN_MODIFY), 
            full_path);
}

void handle_move_events(char *message, size_t size, const char *full_path, 
                       struct inotify_event *event, char *buffer, ssize_t len, 
                       int fd, const char *log_filename) {
    if (event->mask & IN_MOVED_FROM) {
        // Check for corresponding MOVED_TO event
        char *next_ptr = (char *)event + EVENT_SIZE + event->len;
        if (next_ptr < buffer + len) {
            struct inotify_event *next_event = (struct inotify_event *)next_ptr;
            if ((next_event->mask & IN_MOVED_TO) && (next_event->cookie == event->cookie)) {
                char *to_base = get_path_by_wd(next_event->wd);
                if (to_base) {
                    char to_path[PATH_MAX];
                    build_full_path(to_path, sizeof(to_path), to_base, next_event->name);
                    free(to_base);
                    
                    if (!should_ignore(to_path, log_filename)) {
                        snprintf(message, size, "FILE MOVED: %s -> %s", full_path, to_path);
                        return;
                    }
                }
            }
        }
        snprintf(message, size, "FILE DELETED (MOVED OUT): %s", full_path);
    } else if (event->mask & IN_MOVED_TO) {
        // Check if this is part of a move pair
        char *prev_ptr = (char *)event - EVENT_SIZE - ((struct inotify_event *)((char *)event - EVENT_SIZE))->len;
        if (prev_ptr >= buffer && ((struct inotify_event *)prev_ptr)->cookie == event->cookie) {
            // Already handled in MOVED_FROM
            return;
        }
        snprintf(message, size, "FILE CREATED (MOVED IN): %s", full_path);
    }
}

void process_single_event(struct inotify_event *event, char *buffer, ssize_t len, 
                         ThreadData *data, char *message, size_t message_size) {
    char *base_path = get_path_by_wd(event->wd);
    if (!base_path) return;

    char full_path[PATH_MAX];
    build_full_path(full_path, sizeof(full_path), base_path, event->name);
    
    if (should_ignore(full_path, data->log_filename)) {
        free(base_path);
        return;
    }

    int is_dir = event->mask & IN_ISDIR;

    if (event->mask & IN_CREATE) {
        handle_create_event(message, message_size, full_path, is_dir);
        if (is_dir) {
            add_watch(data->fd, full_path);
        }
    } 
    else if (event->mask & IN_DELETE) {
        handle_delete_event(message, message_size, full_path, is_dir);
    } 
    else if (event->mask & IN_MODIFY) {
        handle_modify_event(message, message_size, full_path, is_dir);
    } 
    else if (event->mask & IN_MOVED_FROM || event->mask & IN_MOVED_TO) {
        handle_move_events(message, message_size, full_path, event, buffer, len, data->fd, data->log_filename);
    }

    if (*message) {
        printf("%s\n", message);
        write_log(data->log, message);
    }

    free(base_path);
}

void *process_events(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    char buffer[BUF_LEN];
    
    while (1) {
        ssize_t len = read(data->fd, buffer, BUF_LEN);
        if (len == -1) {
            if (errno == EAGAIN) continue;
            perror("read");
            break;
        }

        char *ptr = buffer;
        while (ptr < buffer + len) {
            struct inotify_event *event = (struct inotify_event *)ptr;
            char message[512] = {0};
            
            process_single_event(event, buffer, len, data, message, sizeof(message));
            
            ptr += EVENT_SIZE + event->len;
        }
    }
    
    return NULL;
}

/* Initialization and cleanup functions */
void initialize_logging(FILE **log, const char *log_path) {
    *log = fopen(log_path, "a");
    if (!*log) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    write_log(*log, "Starting file monitoring");
}

int initialize_inotify() {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }
    return fd;
}

void cleanup_resources(int inotify_fd, FILE *log, ThreadData *data) {
    for (int i = 0; i < watch_count; i++) {
        inotify_rm_watch(inotify_fd, watches[i].wd);
        free(watches[i].path);
    }
    free(watches);
    
    close(inotify_fd);
    fclose(log);
    free(data->log_filename);
    pthread_mutex_destroy(&log_mutex);
    pthread_mutex_destroy(&watch_mutex);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char log_path[PATH_MAX];
    if (realpath(LOG_FILE, log_path) == NULL) {
        strncpy(log_path, LOG_FILE, sizeof(log_path));
    }

    FILE *log;
    initialize_logging(&log, log_path);
    
    int inotify_fd = initialize_inotify();
    setup_watches(inotify_fd, argv[1], log_path);

    printf("Monitoring directory: %s (recursive)\n", argv[1]);
    printf("Logging to: %s (ignored in monitoring)\n", log_path);
    printf("Press Ctrl+C to exit\n\n");

    ThreadData data = {
        .fd = inotify_fd,
        .base_path = argv[1],
        .log = log,
        .log_filename = strdup(log_path)
    };

    pthread_t thread;
    if (pthread_create(&thread, NULL, process_events, &data) != 0) {
        perror("pthread_create");
        cleanup_resources(inotify_fd, log, &data);
        exit(EXIT_FAILURE);
    }

    while (1) {
        sleep(1);
    }

    // Cleanup (normally unreachable)
    pthread_cancel(thread);
    pthread_join(thread, NULL);
    cleanup_resources(inotify_fd, log, &data);
    
    return 0;
}