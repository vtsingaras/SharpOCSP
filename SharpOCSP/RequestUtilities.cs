using System;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Asn1;

namespace SharpOCSP
{
	public static class RequestUtilities
	{
		public static bool IssuersMatch(Req a, Req b)
		{
			if (Utilities.UnsafeCompare (a.GetCertID ().GetIssuerKeyHash(), b.GetCertID ().GetIssuerKeyHash()) 
				&& Utilities.UnsafeCompare (a.GetCertID ().GetIssuerNameHash(), a.GetCertID ().GetIssuerNameHash())) {
				return true;
			} else {
				return false;
			}
		}
		public static Asn1OctetString ExtractNonce(OcspReq req)
		{
			var nonce_oid = new DerObjectIdentifier ("1.3.6.1.5.5.7.48.1.2");
			return req.GetExtensionValue (nonce_oid);
		}
	}
}

