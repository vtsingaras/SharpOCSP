using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Net;
using System.Linq;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Ocsp;

namespace SharpOCSP
{
	public static class PlatformHacks
	{
		[DllImport("libc")] // Linux
		private static extern int prctl(int option, byte[] arg2, IntPtr arg3, IntPtr arg4, IntPtr arg5);

		[DllImport("libc")] // BSD
		private static extern void setproctitle(byte[] fmt, byte[] str_arg);

		public static void SetProcessName(string name)
		{
			try{
				if (prctl(15 /* PR_SET_NAME */, Encoding.ASCII.GetBytes(name + "\0"),
					IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) != 0){
					throw new OcspInternalMalfunctionException("Error setting process name: " +
						Mono.Unix.Native.Stdlib.GetLastError());
				}
			}catch (EntryPointNotFoundException){
				setproctitle(Encoding.ASCII.GetBytes("%s\0"),
					Encoding.ASCII.GetBytes(name + "\0"));
			}
		}
	}
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
	}
	public static class RequestUtilities
	{
		public static bool RespondersMatch(Req a, Req b)
		{
			if ( a.GetCertID ().GetIssuerKeyHash().SequenceEqual(b.GetCertID ().GetIssuerKeyHash() ) 
				&& a.GetCertID ().GetIssuerNameHash().SequenceEqual(b.GetCertID ().GetIssuerNameHash() ) ) {
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
					SharpOCSP.log.Warn ("Wrong MIME type.");
				}
				switch (http_request.HttpMethod) {
				case "GET":
					var get_request = http_request.Url.PathAndQuery.Remove (0, 1);
					get_request = WebUtility.UrlDecode(get_request);
					ocsp_req = new OcspReq (System.Convert.FromBase64String(get_request));
					break;
				case "POST":
					try{
						ocsp_req = new OcspReq (http_request.InputStream);
					}catch{
						ocsp_req = null;
					}
					break;
				default:
					throw new OcspMalformedRequestException();
				}
			}catch (System.FormatException){
				SharpOCSP.log.Warn ("Could not parse " + http_request.HttpMethod + " request.");
			}catch (OcspMalformedRequestException){
				SharpOCSP.log.Warn ("Unsupported Request method: " + http_request.HttpMethod);
			}
			return ocsp_req;
		}
	}
}