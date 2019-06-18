#include <openssl/x509v3.h>

void X509V3_add_certificate_policies(const X509* x509, char* policyID, char* cpsuri) {
  ASN1_OBJECT* certificatePolicyID   = OBJ_txt2obj(policyID, 1);
  ASN1_OBJECT* policyQualifierInfoID = OBJ_txt2obj("1.3.6.1.5.5.7.2.1", 1);

  ASN1_TYPE* cps = ASN1_generate_v3(cpsuri, NULL);

  POLICYQUALINFO* policyQualifierInfo = POLICYQUALINFO_new();
  policyQualifierInfo->pqualid = policyQualifierInfoID;
  policyQualifierInfo->d.cpsuri = cps->value.ia5string;

  STACK_OF(POLICYQUALINFO) *qualifiers = sk_POLICYQUALINFO_new_null();
  sk_POLICYQUALINFO_push(qualifiers, policyQualifierInfo);

  CERTIFICATEPOLICIES* cpols = CERTIFICATEPOLICIES_new();
  POLICYINFO* cpol = POLICYINFO_new();
  cpol->policyid = certificatePolicyID;
  cpol->qualifiers = qualifiers;
  sk_POLICYINFO_push(cpols, cpol);

  X509_EXTENSION* ext = X509V3_EXT_i2d(NID_certificate_policies, 0, cpols);

  STACK_OF(X509_EXTENSION) *extensions = (STACK_OF(X509_EXTENSION)*)X509_get0_extensions(x509);
  X509v3_add_ext(&extensions, ext, -1);

  ASN1_OBJECT_free(certificatePolicyID);
  ASN1_OBJECT_free(policyQualifierInfoID);

  ASN1_TYPE_free(cps);

  X509_EXTENSION_free(ext);

  /*
  if(qualifiers != NULL) {
    sk_POLICYQUALINFO_pop_free(qualifiers, POLICYQUALINFO_free);
  }
  if(cpols != NULL) {
    sk_POLICYINFO_pop_free(cpols, POLICYINFO_free);
  }
  POLICYINFO_free(cpol);
  CERTIFICATEPOLICIES_free(cpols); */
}
