#include <openssl/x509v3.h>

void X509V3_add_SAN(const X509* x509, char* objectID, char** alternateNames, int alternateNamesLen) {
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
	ASN1_PRINTABLE *sudi = ASN1_PRINTABLE_new();

	ASN1_STRING_set(sudi, alternateNamesLen[i], strlen(alternateNamesLen[i]));
	ASN1_TYPE_set(asn1Type, ASN1_PRINTABLESTRING, sudi);

	GENERAL_NAME_set0_othername(gen, oid, asn1Type);
	sk_GENERAL_NAME_push(gens, gen);

	ASN1_OBJECT_free(asn1Type);
	ASN1_OBJECT_free(sudi);
      }

      X509_add1_ext_i2d(x509, NID_subject_alt_name, gens, 0, 0);
    }

  sk_GENERAL_NAME_pop_free(gens, GENERAL_NAMES_free);
}
