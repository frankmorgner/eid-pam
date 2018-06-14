#include <curl/curl.h>
#include <stdio.h>

FILE *auth_fopen(const char *login, const char *mode);
int auth_mkdir(const char *login);

const char action_status[] = "Status";
const char action_settings[] = "ShowUI=Settings";
const char action_pinmanagement[] = "ShowUI=PINManagement";
const char action_eid[] = "tcTokenURL=https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=xml";
const char action_eid_ok[] = "<ns3:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ns3:ResultMajor>";

int client_action(CURL *curl, const char *action);
void client_pubkeypinning(CURL *curl, const char *login);
