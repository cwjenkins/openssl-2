#include <openssl/x509v3.h>

X509_EXTENSION* X509V3_subject_to_authority(X509* cert) {
  AUTHORITY_KEYID* akeyid = AUTHORITY_KEYID_new();

  int i               = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1);
  X509_EXTENSION* ext = X509_get_ext(cert, i);
  ASN1_OCTET_STRING* ikeyid = X509V3_EXT_d2i(ext);

  akeyid->keyid = ikeyid;
  
  X509_EXTENSION* akey = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akeyid);

  //free
  //ASN1_OCTET_STRING_free(ikeyid);
  X509_EXTENSION_free(ext);
  //AUTHORITY_KEYID_free(akeyid);

  return akey;
}
