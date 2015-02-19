using System;
using System.Net;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Ocsp;

namespace SharpOCSP
{
	public static class DataUtilities
	{
		public static bool IsValidUrl(string source)
		{
			Uri uriResult;
			return Uri.TryCreate(source, UriKind.Absolute, out uriResult) && ( uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps );
		}
		public static string ByteArrayToString(byte[] ba)
		{
			string hex = BitConverter.ToString(ba);
			return hex.Replace("-","");
		}
		public static unsafe bool UnsafeCompare(byte[] a1, byte[] a2) {
			if(a1==null || a2==null || a1.Length!=a2.Length)
				return false;
			fixed (byte* p1=a1, p2=a2) {
				byte* x1=p1, x2=p2;
				int l = a1.Length;
				for (int i=0; i < l/8; i++, x1+=8, x2+=8)
					if (*((long*)x1) != *((long*)x2)) return false;
				if ((l & 4)!=0) { if (*((int*)x1)!=*((int*)x2)) return false; x1+=4; x2+=4; }
				if ((l & 2)!=0) { if (*((short*)x1)!=*((short*)x2)) return false; x1+=2; x2+=2; }
				if ((l & 1)!=0) if (*((byte*)x1) != *((byte*)x2)) return false;
				return true;
			}
		}
	}
	public static class RequestUtilities
	{
		public static bool RespondersMatch(Req a, Req b)
		{
			if (DataUtilities.UnsafeCompare (a.GetCertID ().GetIssuerKeyHash(), b.GetCertID ().GetIssuerKeyHash()) 
				&& DataUtilities.UnsafeCompare (a.GetCertID ().GetIssuerNameHash(), a.GetCertID ().GetIssuerNameHash())) {
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
				Console.WriteLine ("Could not parse " + http_request.HttpMethod + " request.");
				ocsp_req = null;
			}
			return ocsp_req;
		}
	}
}