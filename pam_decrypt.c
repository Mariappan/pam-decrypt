#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_USERFILE_SIZE 1024
#define USERSFILE "users"

const char *user = "maari";
const char *device = "/dev/nvme0n1p4";
const char *dev_mapper = "/dev/mapper/crypthome";

/**
 * converse -
 * @pamh:   PAM handle
 * @nargs:  number of messages
 * @message:    PAM message array
 * @resp:   user response array
 *
 * Note: Adapted from pam_unix/support.c.
 */
static int converse(pam_handle_t *pamh, int nargs,
    const struct pam_message **message, struct pam_response **resp)
{
    int retval;
    struct pam_conv *conv;

    assert(pamh != NULL);
    assert(nargs >= 0);
    assert(resp != NULL);

    *resp = NULL;
    retval = pam_get_item(pamh, PAM_CONV, (const void **)((void *) &conv));

    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_get_item: %s\n", pam_strerror(pamh, retval));
    } else if (conv == NULL || conv->conv == NULL) {
        fprintf(stderr, "No converse function available\n");
    } else {
        retval = conv->conv(nargs, message, resp, conv->appdata_ptr);
        if (retval != PAM_SUCCESS)
            fprintf(stderr, "conv->conv(...): %s\n", pam_strerror(pamh, retval));
    }

    if (resp == NULL || *resp == NULL || (*resp)->resp == NULL)
        retval = PAM_AUTH_ERR;

    assert(retval != PAM_SUCCESS || (resp != NULL && *resp != NULL &&
           (*resp)->resp != NULL));
    return retval; /* propagate error status */
}

/**
 * read_password -
 * @pamh:   PAM handle
 * @prompt: a prompt message
 * @pass:   space for entered password
 *
 * Returns PAM error code or %PAM_SUCCESS.
 * Note: Adapted from pam_unix/support.c:_unix_read_password().
 */
static int read_password(pam_handle_t *pamh, const char *prompt, char **pass)
{
    int retval;
    struct pam_message msg;
    const struct pam_message *pmsg = &msg;
    struct pam_response *resp = NULL;

    assert(pamh != NULL);
    assert(pass != NULL);

    *pass = NULL;
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg       = (prompt == NULL) ? "Password: " : prompt;
    retval  = converse(pamh, 1, &pmsg, &resp);
    if (retval == PAM_SUCCESS)
        *pass = strdup(resp->resp);

    assert(retval != PAM_SUCCESS || (pass != NULL && *pass != NULL));
    return retval;
}

/**
 * send_message -
 * @pamh:   PAM handle
 * @message: a prompt message
 *
 * Returns None
 * Note: Adapted from pam_unix/support.c:_unix_read_password().
 */
static void send_message(pam_handle_t *pamh, const char *message)
{
    int retval;
    struct pam_message msg;
    const struct pam_message *pmsg = &msg;
    struct pam_response *resp = NULL;

    assert(pamh != NULL);
    if (!message) return;

    msg.msg_style = PAM_ERROR_MSG;
    msg.msg       = message;
    retval  = converse(pamh, 1, &pmsg, &resp);

    assert(retval != PAM_SUCCESS);
    return;
}

static void auth_grab_authtok(pam_handle_t *pamh)
{
    char *authtok = NULL;
    int ret;

    char *ptr = NULL;
    char command[512] = {};

    ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **)((void *) &ptr));

    if (ret == PAM_SUCCESS && ptr != NULL)
        authtok = strdup(ptr);

    if (authtok == NULL) {
        ret = read_password(pamh, "Decryption Password:", &authtok);
    }

    snprintf(command, sizeof(command), "echo %s | tr '\\0' '\\n' | /usr/sbin/cryptsetup open %s crypthome", authtok, device);
    ret = system(command);

    if (0 == WEXITSTATUS(ret)) {
        send_message(pamh, "Decryption Successful");

        memset(command, 0, sizeof(command));
        snprintf(command, sizeof(command), "mount %s /home", dev_mapper);
        ret = system(command);
    } else {
        send_message(pamh, "Decryption failed");
    }

    free(authtok);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
                   const char **argv)
{
    const char *username = NULL;

    if (access(dev_mapper, F_OK) != -1) { // file exists
        return PAM_SUCCESS;
    }

    pam_get_item(handle, PAM_USER, (const void **)((void *) &username));

    if (username == NULL) return PAM_SUCCESS;

    if (username != NULL) {
        if (strncmp(username, user, strlen(user))) {
            return PAM_SUCCESS;
        }
    }

    auth_grab_authtok(handle);

    return PAM_NEW_AUTHTOK_REQD;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                const char **argvPAM_ERROR_MSG)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                  const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                   const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                    const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                const char **argv)
{
    return PAM_SUCCESS;
}

