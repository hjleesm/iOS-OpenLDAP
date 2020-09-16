//
//  LDAPController.m
//  TestLDAP
//
//  Created by hjleesm on 2020/09/15.
//  Copyright © 2020 hjleesm. All rights reserved.
//

#import "LDAPController.h"
#import <ldap.h>
#include <stdlib.h>
#include <string.h>
#import <Foundation/Foundation.h>

@implementation LDAPController

+ (BOOL)search {
    int              i;
    int              err;
    int              ver;
    char           * attribute;
    LDAP           * ld;
    BerValue         cred;
    BerValue       * servercredp;
    BerElement     * ber;
    const char     * dn;
    LDAPMessage    * res;
    LDAPMessage    * entry;
    struct berval ** vals;

    vals            = NULL;
    servercredp     = NULL;
    cred.bv_val     = "drowssap";
    cred.bv_len     = (size_t) strlen("drowssap");
    dn              = "cn=Directory Manager";

    NSLog(@"initialzing LDAP...");
    err = ldap_initialize(&ld, "ldap://10.0.1.3");
    if (err != LDAP_SUCCESS)
    {
       NSLog(@"ldap_initialize(): %s", ldap_err2string(err));
       return(YES);
    };

    ver = LDAP_VERSION3;
    err = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (err != LDAP_SUCCESS)
    {
       NSLog(@"ldap_set_option(): %s", ldap_err2string(err));
       ldap_unbind_ext_s(ld, NULL, NULL);
       return(YES);
    };

    NSLog(@"binding to LDAP server...");
    err = ldap_sasl_bind_s(ld, dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &servercredp);
    if (err != LDAP_SUCCESS)
    {
       NSLog(@"ldap_sasl_bind_s(): %s", ldap_err2string(err));
       ldap_unbind_ext_s(ld, NULL, NULL);
       return(YES);
    };

    NSLog(@"initiating lookup...");
    if ((err = ldap_search_ext_s(ld, "o=test", LDAP_SCOPE_SUB, "(objectclass=*)", NULL, 0, NULL, NULL, NULL, -1, &res)))
    {
       NSLog(@"ldap_search_ext_s(): %s", ldap_err2string(err));
       ldap_unbind_ext_s(ld, NULL, NULL);
       return(YES);
    };

    NSLog(@"checking for results...");
    if (!(ldap_count_entries(ld, res)))
    {
       NSLog(@"no entries found.");
       ldap_msgfree(res);
       ldap_unbind_ext_s(ld, NULL, NULL);
       return(YES);
    };
    NSLog(@"%i entries found.", ldap_count_entries(ld, res));

    NSLog(@"retrieving results...");
    if (!(entry = ldap_first_entry(ld, res)))
    {
       NSLog(@"ldap_first_entry(): %s", ldap_err2string(err));
       ldap_msgfree(res);
       ldap_unbind_ext_s(ld, NULL, NULL);
       return(YES);
    };

    while(entry)
    {
       NSLog(@" ");
       NSLog(@"dn: %s", ldap_get_dn(ld, entry));

       attribute = ldap_first_attribute(ld, entry, &ber);
       while(attribute)
       {
          if ((vals = ldap_get_values_len(ld, entry, attribute)))
          {
             for(i = 0; vals[i]; i++)
                NSLog(@"%s: %s", attribute, vals[i]->bv_val);
             ldap_value_free_len(vals);
          };
          ldap_memfree(attribute);
          attribute = ldap_next_attribute(ld, entry, ber);
       };

       // skip to the next entry
       entry = ldap_next_entry(ld, entry);
    };
    NSLog(@" ");

    NSLog(@"unbinding from LDAP server...");
    ldap_unbind_ext_s(ld, NULL, NULL);
     
     return YES;
}


@end
