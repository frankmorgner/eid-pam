#include <curl/curl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static int auth_dirname(const char *login, char filename[PATH_MAX])
{
    struct passwd *pw = getpwnam(login);
    if (!pw || !pw->pw_dir)
        return 0;

    snprintf(filename, PATH_MAX, "%s/.eid",
            pw->pw_dir);

    return 1;
}

static int auth_filename(const char *login, char filename[PATH_MAX])
{
    if (1 != auth_dirname(login, filename))
        return 0;

    strcat(filename, "/authorized_eid");

    return 1;
}

int auth_mkdir(const char *login)
{
    char dirname[PATH_MAX];

    if (1 != auth_dirname(login, dirname))
        return -1;

    return mkdir(dirname, 0700);
}

FILE *auth_fopen(const char *login, const char *mode)
{
    char filename[PATH_MAX];

    if (1 != auth_filename(login, filename))
        return NULL;

    return fopen(filename, mode);
}

static int pubkey_filename(const char *login, char filename[PATH_MAX])
{
    if (1 != auth_dirname(login, filename))
        return 0;

    strcat(filename, "/authorized_pubkey");

    return 1;
}

void client_pubkeypinning(CURL *curl, const char *login)
{
    char filename[PATH_MAX];
    struct stat sb;

    if (1 == pubkey_filename(login, filename)
            && 0 == stat(filename, &sb)
            && S_ISREG(sb.st_mode)) {
        curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, filename);
    }
}

int client_action(CURL *curl, const char *action)
{
    int ok = 0;
    char url[256];

    snprintf(url, (sizeof url) - 1,
            "http://127.0.0.1:24727/eID-Client?%s",
            action);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (CURLE_OK == curl_easy_perform(curl)) {
        return 1;
    }

    return 0;
}
