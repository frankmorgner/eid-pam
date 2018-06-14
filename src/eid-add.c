#include "config.h"
#include "eid.h"
#include <string.h>
#include <unistd.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#include <locale.h>
#define _(string) gettext(string)
#ifndef LOCALEDIR
#define LOCALEDIR "/usr/share/locale"
#endif
#else
#define _(string) string
#endif

#ifndef HAVE_STRNSTR
char *strnstr(const char *haystack, const char *needle, size_t count)
{
    char *found = strstr(haystack, needle);
    if (found && found - haystack <= count) {
        /* for ease of implementation we accept an out of bounds read while
         * searching, but we do not propagate this problem */
        return found;
    }
    return NULL;
}
#endif

struct file_status {
	FILE *file;
	int ok;
};

static void
eid_print(char *contents, size_t count)
{
    struct {
        const char *title;
        const char *pre;
        const char *post;
    } eid[] = {
        {_("Given Name(s):   "), "<GivenNames>","</GivenNames>"},
        {_("Family Name(s):  "), "<FamilyNames>>", "</FamilyNames>"},
        {_("Date Of Birth:   "), "<DateOfBirth>", "</DateOfBirth>"},
    };
    size_t i;

    for (i = 0; i < sizeof eid/sizeof *eid; i++) {
        char *data = strnstr(contents, eid[i].pre, count);
        if (data) {
            char *end = strnstr(data, eid[i].post,
                    count - (data - contents));
            if (end) {
                data += strlen(eid[i].pre);
                printf("%s%.*s\n", eid[i].title, (int) (end - data), data);
                break;
            }
        }
    }
}

static size_t
auth_write(void *contents, size_t size, size_t nmemb, void *userp)
{
    struct file_status *status = (struct file_status *)userp;
    size_t consumed = fwrite(contents, size, nmemb, status->file);

    if (strstr((char *) contents, action_eid_ok)) {
        eid_print(contents, consumed);
        status->ok = 1;
    }

    return consumed;
}

static size_t
name_print(void *contents, size_t size, size_t nmemb, void *userp)
{
    struct {
        const char *pre;
        const char *post;
    } client[] = {
        /* Status response of AusweisApp2 */
        {"Name: ", "\n"},
        /* Status response of Open eCard App */
        {"<ns12:Name>", "</ns12:Name>"},
    };
    struct file_status *status = (struct file_status *)userp;
    char *start = contents;
    size_t consumed = size*nmemb, i;

    for (i = 0; i < sizeof client/sizeof *client; i++) {
        char *name = strnstr(start, client[i].pre, consumed);
        if (name) {
            char *end = strnstr(name, client[i].post,
                    consumed - (name - start));
            if (end) {
                name += strlen(client[i].pre);
                printf(_("Connected to %.*s\n"), (int) (end - name), name);
                status->ok = 1;
                break;
            }
        }
    }


    return consumed;
}

int main(int argc, char **argv)
{
    char user[32];
    struct file_status status = {stdout, -1};
    CURL *curl = NULL;

    curl = curl_easy_init();
    if (NULL == curl)
        goto err;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, name_print);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&status);
    if (!client_action(curl, action_status)) {
        puts(_("Failed to connect to eID Client"));
        goto err;
    }
    if (status.ok != 1) {
        puts(_("Connected to unknown eID Client"));
    }
    status.ok = -1;

    if (0 != getlogin_r(user, sizeof user))
        goto err;

    status.file = auth_fopen(user, "wb");
    if (!status.file) {
        if (0 != auth_mkdir(user))
            goto err;
        status.file = auth_fopen(user, "wb");
        if (!status.file)
            goto err;
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, auth_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&status);
    client_pubkeypinning(curl, user);
    client_action(curl, action_eid);

err:
    if (status.file)
        fclose(status.file);
    if (curl)
        curl_easy_cleanup(curl);

    if (status.ok == 1) {
        puts(_("Configured ~/.eid/authorized_eid"));
        puts(_("To enable certificate pinning, run\n"));
        puts(  "  echo \\\n"
                "    | openssl s_client -connect www.autentapp.de:443 2>/dev/null \\\n"
                "    | openssl x509 -noout -pubkey \\\n"
                "    | openssl asn1parse -noout -inform PEM -out ~/.eid/authorized_pubkey");
        return 0;
    } else {
        /* eID Client will print some error */
        return 1;
    }
}
