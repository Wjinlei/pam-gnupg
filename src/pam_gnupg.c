#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <wait.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "config.h"

#define KEYGRIP_LENGTH 40

#define READ_END 0
#define WRITE_END 1

#define TRUE 1
#define FALSE 0

#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'A'))

struct userinfo {
    int uid, gid;
    char *home;
};

void free_userinfo(struct userinfo *userinfo) {
    if (userinfo == NULL) {
        return;
    }
    if (userinfo->home != NULL) {
        free((void *) userinfo->home);
    }
    free((void *) userinfo);
}

int get_userinfo(pam_handle_t *pamh, struct userinfo **userinfo) {
    const char *user = NULL;
    struct passwd pwd, *result = NULL;
    char *buf = NULL;
    size_t bufsize;

    *userinfo = NULL;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return FALSE;
    }

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        bufsize = 16384;
    }

    buf = malloc(bufsize);
    if (buf == NULL) {
        return FALSE;
    }

    if (getpwnam_r(user, &pwd, buf, bufsize, &result) != 0 || result == NULL ||
        pwd.pw_dir == NULL || pwd.pw_dir[0] != '/') {
        free(buf);
        return FALSE;
    }

    *userinfo = malloc(sizeof(*userinfo));
    if (*userinfo == NULL) {
        free(buf);
        return FALSE;
    }

    (*userinfo)->uid = pwd.pw_uid;
    (*userinfo)->gid = pwd.pw_gid;
    (*userinfo)->home = strdup(pwd.pw_dir);
    free(buf);

    if ((*userinfo)->home == NULL) {
        free_userinfo(*userinfo);
        *userinfo = NULL;
        return FALSE;
    }

    return TRUE;
}

/* Copied from gnupg */
char *hexify(const char *token) {
    char *result = malloc(2*strlen(token)+1);
    char *r;
    const char *s;
    if (result == NULL) {
        return NULL;
    }
    for (s = token, r = result; *s; s++) {
        *r++ = tohex((*s>>4) & 15);
        *r++ = tohex(*s & 15);
    }
    *r = 0;
    return result;
}

/* Copied from gnome-keyring */
void wipestr(char *data) {
    volatile char *vp;
    size_t len;
    if (!data) {
        return;
    }
    /* Defeats some optimizations */
    len = strlen(data);
    memset(data, 0xAA, len);
    memset(data, 0xBB, len);
    /* Defeats others */
    vp = (volatile char*) data;
    while (*vp) {
        *(vp++) = 0xAA;
    }
    free((void *) data);
}

void cleanup_token(pam_handle_t *pamh, void *data, int error_status) {
    pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "clearing token");
    wipestr(data);
}

void close_safe(int fd)
{
    if (fd != -1) {
        close(fd);
    }
}

void setup_sigs(struct sigaction **old) {
    struct sigaction sigchld, sigpipe;
    if ((*old = malloc(2*sizeof(struct sigaction))) == NULL) {
        return;
    }
    memset(*old, 0, 2*sizeof(struct sigaction));
    memset(&sigchld, 0, sizeof(sigchld));
    memset(&sigpipe, 0, sizeof(sigpipe));
    sigchld.sa_handler = SIG_DFL;
    sigpipe.sa_handler = SIG_IGN;
    sigaction(SIGCHLD, &sigchld, *old+0);
    sigaction(SIGPIPE, &sigpipe, *old+1);
}

void restore_sigs(const struct sigaction *old) {
    if (old == NULL) {
        return;
    }
    sigaction(SIGCHLD, old+0, NULL);
    sigaction(SIGPIPE, old+1, NULL);
    free((void *) old);
}

int run_as_user(const struct userinfo *user, const char * const cmd[], int *input, char **env,
                pam_handle_t *pamh) {
    int inp[2] = {-1, -1};
    int pid;
    int dev_null;

    if (pipe(inp) < 0) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "failed to open pipe");
        *input = -1;
        return 0;
    }
    *input = inp[WRITE_END];

    switch (pid = fork()) {
    case -1:
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "fork() failed (%s)", strerror(errno));
        close_safe(inp[READ_END]);
        close_safe(inp[WRITE_END]);
        *input = -1;
        return FALSE;

    case 0:
        break;

    default:
        close_safe(inp[READ_END]);
        return pid;
    }

    /* We're in the child process now */

    if (dup2(inp[READ_END], STDIN_FILENO) < 0) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "child: dup2() failed (%s)", strerror(errno));
        exit(EXIT_FAILURE);
    }
    close_safe(inp[READ_END]);
    close_safe(inp[WRITE_END]);

    if ((dev_null = open("/dev/null", O_WRONLY)) != -1) {
        dup2(dev_null, STDOUT_FILENO);
        dup2(dev_null, STDERR_FILENO);
        close(dev_null);
    }

    if (seteuid(getuid()) < 0 || setegid(getgid()) < 0 ||
        setgid(user->gid) < 0 || setuid(user->uid) < 0 ||
        setegid(user->gid) < 0 || seteuid(user->uid) < 0) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "child: failed to set uid/gid");
        exit(EXIT_FAILURE);
    }

    if (env != NULL) {
        execve(cmd[0], (char * const *) cmd, env);
    } else {
        execv(cmd[0], (char * const *) cmd);
    }
    pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "child: execve() failed (%s)", strerror(errno));
    exit(EXIT_FAILURE);
}

int preset_passphrase(pam_handle_t *pamh, const char *tok, int autostart) {
    int ret = FALSE;

    struct userinfo *user;
    if (!get_userinfo(pamh, &user)) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "failed to get user info");
        return FALSE;
    }

    char *keygrip_file;
    if (asprintf(&keygrip_file, "%s/.pam-gnupg", user->home) < 0) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "asprintf() failed");
        goto end;
    }
    FILE *file = fopen(keygrip_file, "r");
    free(keygrip_file);
    if (file == NULL) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "failed to open ~/.pam-gnupg (%s)", strerror(errno));
        return FALSE;
    }

    struct sigaction *handlers = NULL;
    setup_sigs(&handlers);
    if (handlers == NULL) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "failed to setup signal handlers");
        goto end;
    }

    /* gpg-connect-agent has an option --no-autostart, which *should* return
     * non-zero when the agent is not running. Unfortunately, the exit code is
     * always 0 in version 2.1. Passing an invalid agent program here is a
     * workaround. See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=797334 */
    const char *cmd[] = {GPG_CONNECT_AGENT, "--agent-program", "/dev/null", NULL};
    if (autostart) {
        cmd[1] = NULL;
    }

    int input;
    char **env = pam_getenvlist(pamh);
    pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "running gpg-preset-passphrase, autostart=%d", autostart);
    const int pid = run_as_user(user, cmd, &input, env, pamh);
    if (env != NULL) {
        free(env);
    }
    if (pid == 0 || input < 0) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "starting gpg-connect-agent failed");
        goto end;
    }

    char *presetcmd;
    const int presetlen = asprintf(&presetcmd, "PRESET_PASSPHRASE xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -1 %s\n", tok);
    if (presetlen < 0) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "asprintf() failed");
        presetcmd = NULL;
        goto end;
    }
    char * const keygrip = presetcmd + 18;

    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, file) != -1) {
        const char *cur = line;
        while (*cur && strchr(" \t\n\r\f\v", *cur)) {
            cur++;
        }
        if (!*cur || *cur == '#') {
            continue;
        }
        strncpy(keygrip, cur, KEYGRIP_LENGTH);
        if (strlen(keygrip) < KEYGRIP_LENGTH) {
            /* We hit eol sooner than expected. */
            continue;
        }
        *(keygrip + KEYGRIP_LENGTH) = '\0';
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "presetting keygrip %s", keygrip);
        *(keygrip + KEYGRIP_LENGTH) = ' ';
        if (write(input, presetcmd, presetlen) < 0) {
            /* If anything goes wrong, we just stop here. No attempt is made to
             * clean passphrases that were set in a previous iteration. */
            pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "write() failed (%s)", strerror(errno));
            close(input);
            goto end;
        }
    }

    int status;
    close(input);
    pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "waiting for subprocess");
    waitpid(pid, &status, 0);
    pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "subprocess finished with exit status %d",
               WEXITSTATUS(status));
    ret = (WIFEXITED(status) && WEXITSTATUS(status) == 0);

end:
    wipestr(presetcmd);
    restore_sigs(handlers);
    free_userinfo(user);
    if (file != NULL) {
        fclose(file);
    }
    if (line != NULL) {
        free(line);
    }
    return ret;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **) &tok) == PAM_SUCCESS && tok != NULL) {
        tok = hexify(tok);
        if (tok != NULL) {
            pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "storing auth token");
            pam_set_data(pamh, "pam-gnupg-token", (void *) tok, cleanup_token);
        }
    } else {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "failed to obtain auth token");
    }
    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    if ((argc > 0 && strcmp(argv[0], "store-only") == 0) ||
        (flags & PAM_DELETE_CRED) ||
        pam_get_data(pamh, "pam-gnupg-token", (const void **) &tok) != PAM_SUCCESS ||
        tok == NULL) {
        return PAM_SUCCESS;
    }
    pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "attempting to unlock");
    if (!preset_passphrase(pamh, tok, FALSE)) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "unlocking failed");
        return PAM_IGNORE;
    }
    pam_set_data(pamh, "pam-gnupg-token", NULL, NULL);
    return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    if (pam_get_data(pamh, "pam-gnupg-token", (const void **) &tok) == PAM_SUCCESS && tok != NULL) {
        pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "attempting to unlock");
        if (!preset_passphrase(pamh, tok, (argc == 0 || strcmp(argv[0], "no-autostart") != 0))) {
            pam_syslog(pamh, LOG_AUTH | LOG_DEBUG, "unlocking failed");
        }
        pam_set_data(pamh, "pam-gnupg-token", NULL, NULL);
    }
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
