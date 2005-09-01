 /**
  * kSpam plugin for Exim Local Scan.
  * Copyright (C) 2005 James Kibblewhite <kibble@aproxity.com>
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of the GNU General Public License
  * as published by the Free Software Foundation; either version 2
  * of the License, or (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
  *
  * -----------------------------------------------------------------------------
  * $Id$
  * -----------------------------------------------------------------------------
  *
  * This local_scan.c file compiles in with exim4.
  * Exim:        http://www.exim.org/
  * MySql:       http://www.mysql.com/
  * ClamAV:      http://www.clamav.org/
  * DSpam:       http://www.nuclearelephant.com/projects/dspam/
  *
  * Changes:
  * Version 0.8: Bug fixes further improved. No crashes can be replicated. Futher testing
  *              required. Removed debugging exim_mainlog output. Will try and get user
  *              rules implemented...
  *
  * Version 0.7: Bugs all fixed, seems to be a fully working system, need to test
  *              all features before full public release can be made...
  *              Will remove all debugging output in 0.9... public release v1.0
  *
  * Version 0.6: Improved email validation. Added `cleanitup` as a cleanup routeen
  *              ClamAV lib updated [now 0.8x & above required as min requirement]
  *              Bleeding Edge CVS of dspam is also required
  *
  * Version 0.5: Started ruleset loading support from database.
  *
  * Version 0.4: Got DSpam working and aliases sorted. First beta release.
  *
  * Version 0.3: Included a config file reader to take variables from the main configuration file.
  *              Also integrated the last of MySQL support and tidy duties on the code done.
  *
  * Version 0.2: Fixes to scan mbox style flatfiles with compressed files...
  *              thanks to ClamAV for: CL_ARCHIVE & CL_MAIL
  *              you've saved me the bother of extracting the mime base64 encoded stuff !! yay
  *
  * Version 0.1: For personal testing.
  *
  * Ideas:       Can block email totally if probability & confidence is very high [like +95% (=>0.95)]
  *
  * Known bugs:  [X] This is no longer a bug, all bugs fixed, testing is required...
  *
  *              If you submit 'many' new emails all at once it has a tendancy to die but tell
  *              you that it has failed... Maybe by controlling the flow of emails will help
  *              [although will slow thru-put]. Will crash at 'mysql_real_connect()' in 'mysql_setup()'
  *              while trying to establish a connection on a second pass... [This is
  *
  * Donations:   To paypal: jelly_bean_junky@hotmail.com 'if' you use this code commercially,
  *              ask your boss for it! And for a pay rise while your at it too... Otherwise I don't
  *              expect anything, unless you wanna send some cool stuff to me...
  *
  * Notes:       This line may need appending to the end of the local_scan.o line:
  *              -I/usr/include/mysql -I/usr/include/dspam -DHAVE_CONFIG_H -DCONFIG_DEFAULT=/etc/sysconf.d/dspam.conf
  */

 /** include required by exim */
 #include        "local_scan.h"

 /** include required by clamav for antivirus checking */
 #include        "clamav.h"

 /** include required by mysql for access to the database */
 #include        "mysql.h"

 /** include required by dspam for spam filtering */
 #include        "libdspam.h"

 /** the usual suspects */
 #include        <stdio.h>
 #include        <stdlib.h>
 #include        <unistd.h>
 #include        <signal.h>
 #include        <string.h>
 #include        <fcntl.h>

 #define         SPAMREPT           2
 #define         FALSEPOS           4
 #define         SPAMFLAG           8
 #define         TOGBLACK          16
 #define         TOGWHITE          32
 #define         SMBYTE            64
 #define         EMBYTE           128
 #define         QMBYTE           256
 #define         HMBYTE           512
 #define         WMBYTE          1024
 #define         BUFFER_SIZE     2048

 /** blocks hosts & ips & emails & headers */
 typedef struct bhosts_s {       /** _lscan._lusers_s.bhosts->next */
         struct bhosts_s         * next;
         char                    * sender_hostname;
         char                    * sender_ipaddr;
         char                    * sender_logics;        /** OR | AND -> hostname - ipaddr */
         char                    * email;
         char                    * email_mtype;          /** contains | exact match */
         char                    * header_field;
         char                    * header_value;
         char                    * header_mtype;         /** contains | exact match -> header_value if header_value == NULL || "" use header_field */
         char                    * logics;               /** OR | AND -> all values */
 } _bhosts_s;

 /** linked list of local users requiring filtering */
 typedef struct lusers_s {       /** _lscan._lusers_s.username */
         struct lusers_s         * next;
         _bhosts_s               * bhosts;
         int                     mailuser_id;            /** refers to database id */
         int                     enabled;                /** is filtering enabled... */
         char                    rcptname[EMBYTE];       /** rcpt name as appears in recipients_list */
         char                    realemail[EMBYTE];      /** if rcptname is an alias, this will be the real email
                                                             for loading dpsma rules with, else set the same as rcptname */
 } _lusers_s;

 typedef struct email_struct {
         char                    localpart[SMBYTE];
         char                    domain[SMBYTE];
 } _email_struct;

 /** varaibles of mass instructions */
 typedef struct lscan_structure {
         MYSQL                   * mysql;
         MYSQL_RES               * result;
         MYSQL_ROW               row;
         _lusers_s               * l_users;
         _email_struct           lpart_domain;
         struct cl_limits        limits;
         struct cl_node          * root;
         header_line             * hl_ptr;
         char                    * virname;
         char                    emailaddy[HMBYTE];
         char                    querystr[BUFFER_SIZE];
         char                    buffer[BUFFER_SIZE];
         char                    scanpath[BUFFER_SIZE];
         int                     i;
         int                     iNo;
         int                     spamflag;
         int                     writefd;
 } _lscan;

 _lscan lscan;

 /**
  *      Remember to set LOCAL_SCAN_HAS_OPTIONS=yes in Local/Makefile
  *      otherwise you get stuck with the compile-time defaults
  */
 /** Al our variables we draw in from the 'exim-localscan.conf' file */
 static uschar   * database              = US"socket_aproxity";
 static uschar   * hostname              = US"localhost";
 static uschar   * password              = US"password";
 static uschar   * poolpath              = US"/home/mail/spool";
 static uschar   * spamflag              = US"X-KD-Spam";
 static uschar   * username              = US"mail";

 optionlist local_scan_options[] = {             /** alphabetical order */
         { "database",         opt_stringptr,  &database },
         { "hostname",         opt_stringptr,  &hostname },
         { "password",         opt_stringptr,  &password },
         { "poolpath",         opt_stringptr,  &poolpath },
         { "spamflag",         opt_stringptr,  &spamflag },
         { "username",         opt_stringptr,  &username }
 };

 int local_scan_options_count = sizeof(local_scan_options) / sizeof(optionlist);

 #ifdef DLOPEN_LOCAL_SCAN
 /** Return the verion of the local_scan ABI, if being compiled as a .so */
 int local_scan_version_major(void) {
         return(LOCAL_SCAN_ABI_VERSION_MAJOR);
 }

 int local_scan_version_minor(void) {
         return(LOCAL_SCAN_ABI_VERSION_MINOR);
 }

 /**
  *      Left over for compatilibility with old patched exims that didn't have
  *      a version number with minor an major. Keep in mind that it will not work
  *      with older exim4s (I think 4.11 and above is required)
  */

 #ifdef DLOPEN_LOCAL_SCAN_OLD_API
 int local_scan_version(void) {
         return(1);
 }
 #endif
 #endif

 /** delete our cached file */
 void del_cachef() {
         if (unlink(lscan.scanpath)) {
                 debug_printf("file [%s] not removed", lscan.scanpath);
         }
         return;
 } /** del_cachef */

 /**
  *      Scan email for virus. Returns 1 if virus
  *      detected or 0 if no virus is detected. Sets
  *      lscan.virname to virua or error output...
  */
 int scan_clamav(char * scanpath) {

         sprintf(lscan.scanpath, "%s", scanpath);
         lscan.iNo = 0;

         /** lets load all our virus defs database's into memory */
         lscan.root = NULL;      /** without this line, the dbload will crash... */
         if((lscan.i = cl_loaddbdir(cl_retdbdir(), &lscan.root, &lscan.iNo))) {
                 sprintf(lscan.virname, "error: [%s]", cl_perror(lscan.i));
         } else {
                 if((lscan.i = cl_build(lscan.root))) {
                         sprintf(lscan.virname, "database initialization error: [%s]", cl_perror(lscan.i));
                         cl_free(lscan.root);
                 }
                 memset(&lscan.limits, 0x0, sizeof(struct cl_limits));
                 lscan.limits.maxfiles = 1000;                   /** max files */
                 lscan.limits.maxfilesize = 10 * 1048576;        /** maximal archived file size == 10 Mb */
                 lscan.limits.maxreclevel = 12;                  /** maximal recursion level */
                 lscan.limits.maxratio = 200;                    /** maximal compression ratio */
                 lscan.limits.archivememlim = 0;                 /** disable memory limit for bzip2 scanner */

                 if ((lscan.i = cl_scanfile(lscan.scanpath, (const char **)&lscan.virname, NULL, lscan.root,
                 &lscan.limits, CL_SCAN_ARCHIVE | CL_SCAN_MAIL | CL_SCAN_OLE2 | CL_SCAN_BLOCKBROKEN | CL_SCAN_HTML | CL_SCAN_PE)) != CL_VIRUS) {
                         if (lscan.i != CL_CLEAN) {
                                 sprintf(lscan.virname, "error: [%s]", cl_perror(lscan.i));
                         } else {
                                 lscan.virname = NULL;
                         }
                 }
                 if (lscan.root != NULL) {
                         cl_free(lscan.root);
                 }
                 memset(&lscan.limits, 0x0, sizeof(struct cl_limits));
         }

         /** lets delete the spool message as we don't need it any more */
         if (lscan.virname != NULL) {            /** remove the file if we have a virus as we are going to reject it */
                 return(1);
         } else {                                /** else keep the file for spam filtering */
                 return(0);
         }

         return(1);

 } /** scan_clamav */

 void cache_mesg(int fd) {

         fd = fd;

         sprintf(lscan.scanpath, "%s/%s", poolpath, message_id);

         /** create the file handler */
         lscan.writefd = creat(lscan.scanpath, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

         /** lets make this thing look like an email mbox structured thing or clamav won't work !! */
         memset(lscan.buffer, 0x0, BUFFER_SIZE);
         sprintf(lscan.buffer, "From %s Mon Jan 00 00:00:00 0000\n", sender_address);
         lscan.i = write(lscan.writefd, lscan.buffer, strlen(lscan.buffer));

         lscan.hl_ptr = header_list;
         while (lscan.hl_ptr != NULL) {
                 /** type '*' means the header is internal, don't print it, or if the variable is NULL, what's the point...? */
                 if ((lscan.hl_ptr->type != '*') || (lscan.hl_ptr->text != NULL))  {
                         lscan.i = write(lscan.writefd, lscan.hl_ptr->text, strlen(lscan.hl_ptr->text));
                 }
                 lscan.hl_ptr = lscan.hl_ptr->next;
         }

         memset(lscan.buffer, 0x0, BUFFER_SIZE);
         sprintf(lscan.buffer, "\n");
         lscan.i = write(lscan.writefd, lscan.buffer, strlen(lscan.buffer));

         /** output all the data, read from orignal and write to spool */
         while ((lscan.i = read(fd, lscan.buffer, BUFFER_SIZE)) > 0) {
                 lscan.i = write(lscan.writefd, lscan.buffer, lscan.i);
         }

         /** close the handle */
         lscan.i = close(lscan.writefd);
         debug_printf("path of cached file [%s]", lscan.scanpath);

         return;

 } /** cache_mesg */

 void remove_headers(char * hfield) {

         lscan.hl_ptr = header_list;
         while (lscan.hl_ptr != NULL) {
                 if ( ((lscan.hl_ptr->type != '*')) && (!strncmp(lscan.hl_ptr->text, hfield, strlen(hfield))) ) {
                         lscan.hl_ptr->type = '*';
                 }
                 lscan.hl_ptr = (struct header_line *)lscan.hl_ptr->next;
         }
 } /** remove_headers */

 /**
  *      If the supplied email address is syntactically valid,
  *      spc_email_isvalid() will return 1; otherwise, it will
  *      return 0. Need to check that there is at least one '@'
  *      symbol and only one in the whole email address, else
  *      `getlocalp_domain` function won't work correctly...
  */
 int spc_email_isvalid(const char *address) {

         int             count = 0;
         const char      *c, *domain;
         static char     *rfc822_specials = "()<>@,;:\\\"[]/";

         /** first we validate the name portion (name@domain) */
         for (c = address;  *c;  c++) {
                 if ((*c == '\"') && (c == address || *(c - 1) == '.' || *(c - 1) == '\"')) {
                         while (*++c) {
                                 if (*c == '\"') {
                                         break;
                                 }
                                 if ((*c == '\\') && (*++c == ' ')) {
                                         continue;
                                 }
                                 if (*c < ' ' || *c >= 127) {
                                         return(0);
                                 }
                         }
                         if (!*c++) {
                                 return(0);
                         }
                         if (*c == '@') {
                                 break;
                         }
                         if (*c != '.') {
                                 return(0);
                         }
                         continue;
                 }
                 if (*c == '@') {
                         break;
                 }
                 if (*c <= ' ' || *c >= 127) {
                         return(0);
                 }
                 if (strchr(rfc822_specials, *c)) {
                         return(0);
                 }
         }
         if (c == address || *(c - 1) == '.') {
                 return(0);
         }

         /** next we validate the domain portion (name@domain) */
         if (!*(domain = ++c)) {
                 return(0);
         }

         do {
                 if (*c == '.') {
                         if (c == domain || *(c - 1) == '.') {
                                 return(0);
                         }
                         count++;
                 }
                 if (*c <= ' ' || *c >= 127) {
                         return(0);
                 }
                 if (strchr(rfc822_specials, *c)) {
                         return(0);
                 }
         } while (*++c);
         return(count >= 1);
 } /** spc_email_isvalid */

 /** this function returns the localpart and the domain section of an email in any given string */
 _email_struct getlocalp_domain(char * emailaddr, _email_struct lpart_domain) {

         memset(lscan.emailaddy, 0x0, HMBYTE);
         memset(lpart_domain.localpart, 0x0, SMBYTE);
         memset(lpart_domain.domain, 0x0, SMBYTE);
         sprintf(lscan.emailaddy, "%s", emailaddr);

         if (spc_email_isvalid(lscan.emailaddy)) {
                 sprintf(lpart_domain.localpart, "%s", strtok(lscan.emailaddy, "@"));
                 sprintf(lpart_domain.domain, "%s", strtok(NULL, "@"));
         }
         return(lpart_domain);
 } /** getlocalp_domain */

 /** mysql results and rows cleanup routine */
 void mysqlrr_cleanup() {

         lscan.row = NULL;

         if (lscan.result != NULL) {
                 mysql_free_result(lscan.result);
                 lscan.result = NULL;
         }

 } /** mysqlrr_cleanup */

 /** mysql results and rows cleanup routine */
 void mysql_cleanup() {

         mysqlrr_cleanup();

         mysql_close(lscan.mysql);
         memset(&lscan.mysql, 0x0, sizeof(lscan.mysql));
         free(lscan.mysql);

 } /** mysql_cleanup */

 int mysql_setup() {

         mysql_cleanup();

         if (!(lscan.mysql = mysql_init(NULL))) {
                 log_write(0, LOG_MAIN, "mysql_init [%s]", mysql_error(lscan.mysql));
                 return(1);
         }

         /** we are always connecting to localhost!! to slow otherwise... */
         if (!mysql_real_connect(lscan.mysql, hostname, username, password, database, 0, NULL, 0)) {
                 log_write(0, LOG_MAIN, "mysql_real_connect [%s]", mysql_error(lscan.mysql));
                 mysql_close(lscan.mysql);
                 return(1);
         }

         if (mysql_select_db(lscan.mysql, database)) {
                 log_write(0, LOG_MAIN, "mysql_select_db [%s]", mysql_error(lscan.mysql));
                 mysql_close(lscan.mysql);
                 return(1);
         }

         return(0);

 } /** mysql_setup */

 /**
  *      Instead of returning a row of data, I've decided to return
  *      the results to obtain the rows, incase I need more than one
  *      set of rows from the results. This basically runs the current
  *      sql query in lscan.querystr.
  */
 MYSQL_RES * get_mysqlres() {

         /** clean up result and row if required */
         mysqlrr_cleanup();

         debug_printf("running query:\n\t[%s]\n", lscan.querystr);

         if (mysql_real_query(lscan.mysql, lscan.querystr, strlen(lscan.querystr))) {
                 log_write(0, LOG_MAIN, "mysql_real_query [%s]", mysql_error(lscan.mysql));
                 return((MYSQL_RES * )NULL);
         }

         if (!(lscan.result = mysql_store_result(lscan.mysql))) {
                 log_write(0, LOG_MAIN, "mysql_store_result [%s]", mysql_error(lscan.mysql));
                 return((MYSQL_RES * )NULL);
         }

         if (mysql_num_rows(lscan.result) != 0) {
                 return(lscan.result);
         }

         return((MYSQL_RES * )NULL);
 } /** get_mysqlres */

 /** add user and rulesets */
 _lusers_s * add_userset(_lusers_s * l_users, int mailuser_id, int enabled, char * rcptname, _email_struct lpart_domain) {

         _lusers_s       * lp = l_users;

         if (enabled == 0) {
                 return(l_users);
         }

         /** remove any duplicates of users in linked list... */

         if (l_users != NULL) {
                 while (l_users->next != NULL) {
                         l_users = (_lusers_s *)l_users->next;
                 }
                 l_users->next = (struct lusers_s *)malloc(sizeof(_lusers_s));
                 l_users = (_lusers_s *)l_users->next;

                 l_users->mailuser_id = mailuser_id;
                 l_users->enabled = enabled;
                 memset(l_users->rcptname, 0x0, EMBYTE);
                 memset(l_users->realemail, 0x0, EMBYTE);
                 sprintf(l_users->rcptname, "%s", rcptname);
                 sprintf(l_users->realemail, "%s@%s", (char *)lpart_domain.localpart, (char *)lpart_domain.domain);

                 l_users->next = NULL;
                 l_users = lp;
         } else {
                 l_users = (_lusers_s *)(struct lusers_s *)malloc(sizeof(_lusers_s));

                 l_users->mailuser_id = mailuser_id;
                 l_users->enabled = enabled;
                 memset(l_users->rcptname, 0x0, EMBYTE);
                 memset(l_users->realemail, 0x0, EMBYTE);
                 sprintf(l_users->rcptname, "%s", rcptname);
                 sprintf(l_users->realemail, "%s@%s", (char *)lpart_domain.localpart, (char *)lpart_domain.domain);

                 l_users->next = NULL;
                 l_users = l_users;
         }

         /** we should now do a look up for the rules and add them to 'l_users->bhosts' */

         return(l_users);
 }

 int load_realuser(char * emailaddr) {

         lscan.lpart_domain = getlocalp_domain(emailaddr, lscan.lpart_domain); /** lscan.lpart_domain.localpart && lscan.lpart_domain.domain */
         memset(lscan.querystr, 0x0, BUFFER_SIZE);
         sprintf(lscan.querystr, "SELECT mailuser_id, enabled FROM mail_mailusers WHERE local_part = '%s' AND domain = '%s'", lscan.lpart_domain.localpart, lscan.lpart_domain.domain);

         if (get_mysqlres()) {   /** sets lscan.result to results returned from db */
                 if (!(lscan.row = mysql_fetch_row(lscan.result))) {     /** lscan.row[0] */
                         log_write(0, LOG_MAIN, "mysql_fetch_row [%s]", mysql_error(lscan.mysql));
                         return(1);
                 }
         } else {
                 return(1);
         }

         /** add user to results & rules... */
         if ((int)atoi(lscan.row[1]) != 0) {
                 log_write(0, LOG_MAIN, "adding user ...");
                 lscan.l_users = add_userset(lscan.l_users, (int)atoi(lscan.row[0]), (int)atoi(lscan.row[1]), (char *)recipients_list[lscan.i].address, lscan.lpart_domain);
         }

         return(0);
 } /** load_realuser */

 int load_aliases(char * emailaddr) {

         lscan.lpart_domain = getlocalp_domain(emailaddr, lscan.lpart_domain);   /** lscan.lpart_domain.localpart && lscan.lpart_domain.domain */
         memset(lscan.querystr, 0x0, BUFFER_SIZE);
         sprintf(lscan.querystr, "SELECT alias FROM mail_aliases WHERE local_part = '%s' AND domain = '%s'", lscan.lpart_domain.localpart, lscan.lpart_domain.domain);

         if (get_mysqlres()) {   /** sets lscan.result to results returned from db */
                 if (!(lscan.row = mysql_fetch_row(lscan.result))) {     /** lscan.row[0] */
                         log_write(0, LOG_MAIN, "mysql_fetch_row [%s]", mysql_error(lscan.mysql));
                         return(1);
                 }
                 if (load_realuser((char *)lscan.row[0])) {              /** failed to load alias as real user */
                         return(1);
                 }
         } else {
                 /** check for wildcard localpart */
                 memset(lscan.querystr, 0x0, BUFFER_SIZE);
                 sprintf(lscan.querystr, "SELECT alias FROM mail_aliases WHERE local_part = '*' AND domain = '%s'", lscan.lpart_domain.domain);

                 if (get_mysqlres()) {   /** sets lscan.result to results returned from db */
                         if (!(lscan.row = mysql_fetch_row(lscan.result))) {     /** lscan.row[0] */
                                 log_write(0, LOG_MAIN, "mysql_fetch_row [%s]", mysql_error(lscan.mysql));
                                 return(1);
                         }
                         if (load_realuser((char *)lscan.row[0])) {      /** failed to load alias as real user */
                                 return(1);
                         }
                 }
         }

         return(0);
 } /** load_aliases */

 /** this loads all users settings into memory */
 int init_users() {

         if (mysql_setup()) {
                 return(1);
         }

         for (lscan.i = 0; lscan.i != recipients_count; lscan.i++) {
                 if (load_realuser(recipients_list[lscan.i].address)) {
                         debug_printf("cound not find user [%s]", recipients_list[lscan.i].address);
                         if (load_aliases(recipients_list[lscan.i].address)) {
                                 debug_printf("alias [%s] not found check your sql schema", recipients_list[lscan.i].address);
                         }
                 }
         }

         mysql_cleanup();

         return(0);
 } /** init_users */

 char * read_emailmem(char * message) {

         long                            len     = 1;
         long                            oCount  = 0;
         int                             fd      = 0;

         memset(lscan.buffer, 0x0, BUFFER_SIZE);
         fd = open(lscan.scanpath, O_RDONLY);
         /* read in the message from stdin */
         message[0] = 0;
         while ((oCount = read(fd, lscan.buffer, sizeof(lscan.buffer))) > 0) {
                 len += strlen(lscan.buffer);
                 message = realloc(message, len);
                 strcat(message, lscan.buffer);
         }
         close(fd);

         return(message);
 } /** read_emailmem */

 /**
  *      Usage:
  *              CTX = attach_ctx_dbaccess(CTX);
  *
  29903: [3/2/2005 22:34:24] bailing on error 22
  29903: [3/2/2005 22:34:24] received invalid result (! DSR_ISSPAM || DSR_INNOCENT || DSR_ISWHITELISTED): 22
         -> happened because read_emailmem() was not returning the message ptr correctly...
  */
 DSPAM_CTX * attach_ctx_dbaccess(DSPAM_CTX * CTX) {

         if (dspam_clearattributes(CTX)) {
                 log_write(0, LOG_MAIN, "dspam_clearattributes failed!");
         }

         dspam_addattribute(CTX, "MySQLServer", (const char *)hostname);
         dspam_addattribute(CTX, "MySQLPort", (const char *)"3306");
         dspam_addattribute(CTX, "MySQLUser", (const char *)username);
         dspam_addattribute(CTX, "MySQLPass", (const char *)password);
         dspam_addattribute(CTX, "MySQLDb", (const char *)database);
         dspam_addattribute(CTX, "IgnoreHeader", (const char *)spamflag);

         if (dspam_attach(CTX, (void *)NULL)) {
                 log_write(0, LOG_MAIN, "dspam_attach failed!");
                 CTX = NULL;
         }

         return(CTX);
 } /** attach_ctx_dbaccess */

 void load_usersrs(_lusers_s * l_users) {

         _lusers_s                       * tmp           = l_users;
         char                            * message       = malloc(1);
         DSPAM_CTX                       * CTX           = NULL; /** DSPAM Context */
         struct _ds_spam_signature       SIG;                    /** Example signature */

         if (tmp == NULL) {
                 memset(message, 0x0, sizeof(message));
                 free(message);
                 return;
         }

         message = read_emailmem(message);

         while (tmp != NULL) {

                 CTX = dspam_create((char *)tmp->realemail, NULL, NULL, DSM_PROCESS, DSF_CHAINED | DSF_SIGNATURE | DSF_NOISE);
                 CTX = attach_ctx_dbaccess(CTX);
                 if (CTX == NULL) {
                         log_write(0, LOG_MAIN, "dspam_create failed!");
                         break;
                 }
                 if (dspam_process(CTX, message) != 0) { /** Call DSPAM's processor with the message text */
                         log_write(0, LOG_MAIN, "dspam_process failed!");
                         dspam_destroy(CTX);
                         break;
                 }
                 if (CTX->result == DSR_ISSPAM) {     /** Print processing results */
                         log_write(0, LOG_MAIN, "spam->[%s]:\n\tProbability:\t[%2.4f]\n\tConfidence:\t[%2.4f]",
                                 (char *)tmp->realemail, CTX->probability, CTX->confidence);
                         header_add(' ', "%s: %s\n", (char *)spamflag, (char *)tmp->realemail);
                         lscan.spamflag = SPAMFLAG;
                 } else {
                         log_write(0, LOG_MAIN, "not spam->[%s]", (char *)tmp->realemail);
                         lscan.spamflag = 0;
                 }

                 if (CTX->signature != NULL) {
                         SIG.data = malloc(CTX->signature->length);
                         if (SIG.data != NULL) {
                                 memcpy(SIG.data, CTX->signature->data, CTX->signature->length);
                         }
                 }
                 SIG.length = CTX->signature->length;

                 if (dspam_destroy(CTX) != 0) {          /** Destroy the context */
                         log_write(0, LOG_MAIN, "dspam_destroy failed!");
                         break;
                 }

                 tmp = (_lusers_s *)tmp->next;                /** Move on to next user */
         }

         memset(message, 0x0, sizeof(message));
         free(message);
         memset(&CTX, 0x0, sizeof(CTX));
         free(CTX);

         return;
 } /** load_usersrs */

 int report_spam(int spamflag) {

         int                             sflag           = 0;
         char                            * message       = malloc(1);
         DSPAM_CTX                       * CTX           = NULL; /** DSPAM Context */
         struct _ds_spam_signature       SIG;                    /** Example signature */

         message = read_emailmem(message);

         switch (spamflag) {
                 case SPAMREPT:  /** set up the context for error correction as spam */
                         CTX = dspam_create((char *)sender_address, NULL, NULL, DSM_PROCESS, DSF_CHAINED);
                         CTX = attach_ctx_dbaccess(CTX);
                         if (CTX == NULL) {
                                 log_write(0, LOG_MAIN, "ERROR: dspam_create failed!\n");
                                 sflag = 1;
                         }
                         CTX->classification  = DSR_ISSPAM;
                         CTX->source          = DSS_ERROR;
                         break;
                 case FALSEPOS:  /** set up the context for error correction as innocent */
                         CTX = dspam_create((char *)sender_address, NULL, NULL, DSM_PROCESS, DSF_CHAINED | DSF_SIGNATURE);
                         CTX = attach_ctx_dbaccess(CTX);
                         if (CTX == NULL) {
                                 log_write(0, LOG_MAIN, "ERROR: dspam_create failed!\n");
                                 sflag = 1;
                         }
                         CTX->classification  = DSR_ISINNOCENT;
                         CTX->source          = DSS_ERROR;
                         CTX->signature               = &SIG; /** Attach the signature to the context */
                         break;
                 default:        /** no reporting required, scan for spam perhaps ? */
                         log_write(0, LOG_MAIN, "report_spam -> no reporting required");
                         break;
         }

         if (dspam_process(CTX, message) != 0) { /** Call DSPAM */
                 log_write(0, LOG_MAIN, "ERROR: dspam_process failed!");
                 sflag = 1;
         }

         if (dspam_destroy(CTX) != 0) {          /** Destroy the context */
                 log_write(0, LOG_MAIN, "ERROR: dspam_destroy failed!");
                 sflag = 1;
         }

         memset(message, 0x0, sizeof(message));
         free(message);
         memset(&CTX, 0x0, sizeof(CTX));
         free(CTX);

         if (sflag == 0) {
                 log_write(0, LOG_MAIN, "<= %s [%s] P=%s A=%s:%s",
                         (char *)sender_address, (char *)sender_host_address, (char *)received_protocol, (char *)sender_host_authenticated, (char *)sender_address);
                 log_write(0, LOG_MAIN, "=> (null) <%s> R=system_localuser T=local_delivery", (char *)recipients_list[0].address);
         }

         /** if we are reporting, which is pretty much so if you reach here, we blackhole the email */
         recipients_count = 0;

         return(sflag);
 } /** report_spam */

 int check_spamflag(char * subspamdom) {

         memset(lscan.emailaddy, 0x0, HMBYTE);
         sprintf(lscan.emailaddy, "%s@%s.%s", lscan.lpart_domain.localpart, subspamdom, lscan.lpart_domain.domain);

         if (strcmp(lscan.emailaddy, recipients_list[0].address)) {
                 return(0);
         }

         return(1);
 } /** check_spamflag */

 int getrept_type() {

         if (check_spamflag("spamrept")) {
                 return(SPAMREPT);
         }

         if (check_spamflag("falsepos")) {
                 return(FALSEPOS);
         }

         return(0);
 } /** getrept_type */

 /**
  *      Providing some sort of clean up routeen...
  */
 int cleanitup(int return_flag) {

         /** log_write(0, LOG_MAIN, "shutting down driver...");
         dspam_shutdown_driver(NULL);
         log_write(0, LOG_MAIN, "dspam has been shut down!"); */

         mysql_cleanup();
         del_cachef();

         return(return_flag);
 } /** cleanitup */

 void inititial_spam_filtering() {

         remove_headers(spamflag);

         if (init_users()) {
                 log_write(0, LOG_MAIN, "Opps!!");
                 return;
         }

         /** lets start dspam filtering... */
         load_usersrs(lscan.l_users);

         return;
 } /** inititial_spam_filtering */

 /**
  *      Note to self: need to provide a cleanup function for '_lusers_s'
  */
 int local_scan(volatile int fd, uschar **return_text) {

         fd = fd;
         return_text = return_text;

         /** log_write(0, LOG_MAIN, "init dspam driver...");
         dspam_init_driver(NULL);
         log_write(0, LOG_MAIN, "dspam driver init completed!"); */

         cache_mesg(fd);
         if (scan_clamav(lscan.scanpath)) {
                 log_write(0, LOG_MAIN, "rejecting email [%s] contains known virus [%s]", message_id, lscan.virname);
                 return(cleanitup(LOCAL_SCAN_REJECT));
         }

         /** check is spam reporting [spamrept.domain.tld|falsepos.domain.tld] */
         lscan.lpart_domain = getlocalp_domain((char *)sender_address, lscan.lpart_domain);
         if ((recipients_count == 1) && (sender_host_authenticated != NULL)) {   /** must be authenticated with only one recipient */

                 switch (getrept_type()) {
                         case SPAMREPT:  /** report spam email */
                                 if (report_spam(SPAMREPT)) {
                                         log_write(0, LOG_MAIN, "it all went wrong... [spamrept]");
                                 }
                                 break;
                         case FALSEPOS:  /** report false positive */
                                 log_write(0, LOG_MAIN, "reporting [falsepos]");
                                 if (report_spam(FALSEPOS)) {
                                         log_write(0, LOG_MAIN, "it all went wrong... [falsepos]");
                                 }
                                 break;
                         default:        /** no reporting required, scan for spam perhaps ? */
                                 log_write(0, LOG_MAIN, "single user rcpt, scanning...");
                                 break;
                 }
         } else if ( (check_spamflag("falsepos")) || (check_spamflag("spamrept")) ) {
                 /** user's can not report spam if they are not authenticated */
                 return(cleanitup(LOCAL_SCAN_REJECT));
         }

         if (sender_host_authenticated == NULL) {
                 inititial_spam_filtering();
                 /**
                  *      some very simple method of slowing spammers down... [teergrube??]
                  *      maybe some indication on 'probability' & 'confidence' we can lenghten time
                  *      perhaps even a record on blacklists... ? Rejection here too ?
                  */
                 /** if (lscan.spamflag == SPAMFLAG) {
                         alarm(0);
                         sleep(30);
                 } */
         }

         return(cleanitup(LOCAL_SCAN_ACCEPT));
 } /** local_scan */

