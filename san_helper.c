#include <openssl/x509v3.h>
#include <string.h>

void X509V3_add_SAN(X509* x509, char* objectID, char** alternateNames, int alternateNamesLen) {
  GENERAL_NAMES *gens = NULL;
  GENERAL_NAME  *gen  = NULL;
  ASN1_OBJECT   *oid  = NULL;
  int i;

  if(alternateNamesLen) {
      gens = sk_GENERAL_NAME_new_null();
      oid  = OBJ_txt2obj(objectID, 1);

      for(i = 0; i < alternateNamesLen; i++) {
	gen = GENERAL_NAME_new();
	ASN1_TYPE *asn1Type = ASN1_TYPE_new();
	ASN1_PRINTABLESTRING *sudi = ASN1_PRINTABLESTRING_new();

	ASN1_STRING_set(sudi, alternateNames[i], strlen(alternateNames[i]));
	ASN1_TYPE_set(asn1Type, V_ASN1_PRINTABLESTRING, sudi);

	GENERAL_NAME_set0_othername(gen, oid, asn1Type);
	sk_GENERAL_NAME_push(gens, gen);

	if(asn1Type) {
	  ASN1_TYPE_free(asn1Type);
	}
	if(sudi) {
	  ASN1_PRINTABLESTRING_free(sudi);
	}
      }

      X509_add1_ext_i2d(x509, NID_subject_alt_name, gens, 0, 0);

      if(gens) {
	GENERAL_NAMES_free(gens);
      }
    }
}
