using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;
using X509ExtensionsGenerator = Org.BouncyCastle.Asn1.X509.X509ExtensionsGenerator;

namespace SharpOCSP
{
	class BasicResponseGenerator
    {
		public enum CrlReason
		{
			unspecified = 0,
			keyCompromise,
			caCompromise,
			affiliationChanged,
			superseded,
			cessationOfOperation,
			certificateHold,
			removeFromCrl = 8
		}
		private X509ExtensionsGenerator _extensions_generator;
		private byte[] _nonce;
		private string _algorithm;
		private IToken _token;
		private BasicOcspRespGenerator _builder;
		public void AddGoodResponse(CertificateID cert_id)
		{
			_builder.AddResponse (cert_id, CertificateStatus.Good, DateTime.UtcNow.AddMinutes (5), null);
		}
		public void AddUnknownResponse(CertificateID cert_id)
		{
			_builder.AddResponse (cert_id, new UnknownStatus (), DateTime.UtcNow.AddMinutes (5), null);
		}
		public void AddRevokedResponse(CertificateID cert_id, X509CrlEntry crl_entry)
		{
			int reason;
			var crl_reason_oid = X509Extensions.ReasonCode;
			var ext_reason = crl_entry.GetExtensionValue (crl_reason_oid);
			if (ext_reason != null) {
				var asn1_reason = new DerEnumerated (ext_reason.GetEncoded ());
				reason = asn1_reason.Value.IntValue;
			} else {
				reason = (int)CrlReason.unspecified;
			}
			CertificateStatus status = new RevokedStatus (crl_entry.RevocationDate, reason);
			_builder.AddResponse (cert_id, status, DateTime.UtcNow.AddMinutes (5), null);
		}
		//requires the extended revocation extension to be included in the basic response
		public void AddExtendedRevocationResponse(CertificateID cert_id)
		{
			var status = new RevokedStatus (new DateTime (1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), (int)CrlReason.certificateHold);
			_builder.AddResponse (cert_id, status, DateTime.UtcNow.AddMinutes (5), null);
			//now add the extended revocation extension
			var extended_revoke_oid = new DerObjectIdentifier ("1.3.6.1.5.5.7.48.1.9");
			_extensions_generator.AddExtension (extended_revoke_oid, false, DerNull.Instance.GetEncoded());
		}
		public void AddCaCompromisedResponse(CertificateID cert_id)
		{
			var status = new RevokedStatus (DateTime.UtcNow, (int)CrlReason.caCompromise);
			_builder.AddResponse (cert_id, status);
		}
		public void AppendNonce(Asn1OctetString nonce)
		{
			if (nonce != null) {
				_nonce = nonce.GetOctets ();
			}else {
				_nonce = null;
			}
		}
		public BasicOcspResp Generate()
		{
			//append nonce if we have it
			_extensions_generator.AddExtension (new DerObjectIdentifier ("1.3.6.1.5.5.7.48.1.2"), false, _nonce);
			//set responseExtensions
			_builder.SetResponseExtensions (_extensions_generator.Generate ());
			var ocsp_resp = _builder.Generate (_algorithm, _token.GetPrivateKey (), new[]{_token.GetOcspSigningCert ()}, DateTime.UtcNow.AddMinutes (5));
			return ocsp_resp;
		}
		public BasicResponseGenerator (IToken token) : this (token, "SHA1withRSA")
		{
		}
		public BasicResponseGenerator(IToken token, string signingAlgorithm)
		{
			_token = token;
			_algorithm = signingAlgorithm;
			_builder = new BasicOcspRespGenerator (new RespID (_token.GetOcspSigningCert ().SubjectDN));
			//_builder = new BasicOcspRespGenerator (issuer.caCertificate.GetPublicKey());
			_extensions_generator = new X509ExtensionsGenerator ();
		}
    }
}
