using System;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Asn1;
using System.Net;

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
		public static OcspReq GetRequestFromHttp(HttpListenerRequest http_request)
		{
			OcspReq ocsp_req = null;
			try{
				//check if mime-type is application/ocsp-request
				if ( http_request.Headers["Content-Type"] != "application/ocsp-request"){
					Console.WriteLine("Wrong MIME type.");
					ocsp_req = null;
				}
				switch (http_request.HttpMethod) {
				case "GET":
					var get_request = http_request.Url.PathAndQuery.Remove (0, 1);
					get_request = WebUtility.UrlDecode(get_request);
					ocsp_req = new OcspReq (System.Convert.FromBase64String(get_request));
					break;
				case "POST":
					ocsp_req = new OcspReq (http_request.InputStream);
					break;
				}
			}catch (System.FormatException){
				Console.WriteLine ("Could not parse" + http_request.HttpMethod + " request.");
				ocsp_req = null;
			}
			return ocsp_req;
		}
	}
}

