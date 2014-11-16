using System;
using System.Net;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;

namespace SharpOCSP
{
    class SharpOCSP
    {
		static CA[] ca_list;
		static Configuration config;
		public static CA GetIssuerForRequest(OcspReq ocsp_req)
		{
			//get first singleRequest
			Req first_single_req = ocsp_req.GetRequestList () [0];
			//check if request contains requests for different issuers(NOT SUPPORTED)
			foreach ( Req single_req in ocsp_req.GetRequestList() )
			{
				if (RequestUtilities.IssuersMatch (single_req, first_single_req) == false)
					throw new OcspMalformedRequestException ("Multiple issuers in request!");
			}
			//select issuer (same for all singleRequests so just use the first one)
			CertificateID cert_id = first_single_req.GetCertID ();
			foreach (CA issuer in ca_list)
			{
				if ( cert_id.MatchesIssuer(issuer.caCertificate))
					return issuer;
			}
			//Issuer not recognized
			throw new OcspUnrecognizedIssuerException("Unrecognized CA in request.");
		}
		public static OcspReq GetRequestFromHttp(HttpListenerRequest http_request)
		{
			OcspReq ocsp_req = null;
			try{
				//check if mime-type is application/ocsp-request
				if ( http_request.Headers["Content-Type"] != "application/ocsp-request"){
					throw new OcspMalformedRequestException("Wrong MIME type.");
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
			}catch (System.FormatException e){
				throw new OcspMalformedRequestException ("Could not parse request.", e);
			}
			return ocsp_req;
		}
		public static OcspResp CreateResponseForRequest (OcspReq ocsp_req)
		{
			try{
				CertificateID cert_id;
				CA issuer;
				issuer = GetIssuerForRequest(ocsp_req);
				BasicResponseGenerator resp_generator = new BasicResponseGenerator (issuer);
				//append nonce
				var nonce = ocsp_req.GetExtensionValue (new DerObjectIdentifier ("1.3.6.1.5.5.7.48.1.2"));
				resp_generator.AppendNonce (nonce);
				foreach (Req single_req in ocsp_req.GetRequestList())
				{
					cert_id = single_req.GetCertID ();
					Console.WriteLine ("Got request for serial: " + cert_id.SerialNumber.ToString() + " for CA: " + issuer.ToString());
					//check for ca compromise flag
					if (issuer.caCompromised == true) {
						//return revoked with reason cacompromised
						resp_generator.AddCaCompromisedResponse (cert_id);
					} else {
						if (issuer.SerialExists (cert_id.SerialNumber) == false) {
							//return unknown, if config.rfc6960 is true the return extended revoke instead
							if (config.getConfigValue ("rfc6960") == "true") {
								//extended revoke, 1 Jan 1970 and certificateHold
								resp_generator.AddExtendedRevocationResponse (cert_id);
								continue;
							} else {
								//unknown
								resp_generator.AddUnknownResponse (cert_id);
								continue;
							}
						}
						//serial exists, check for revocation
						var crl_entry = issuer.GetCrlEntry (cert_id.SerialNumber);
						if ( crl_entry != null) {
							//serial is revoked
							resp_generator.AddRevokedResponse (cert_id, crl_entry);
							continue;
						} else {
							//serial is good
							resp_generator.AddGoodResponse (cert_id);
							continue;
						}
					}
				}
				//Build basic resp
				BasicOcspResp basic_ocsp_resp = resp_generator.Generate ();
				OCSPRespGenerator ocsp_resp_builder = new OCSPRespGenerator ();
				return ocsp_resp_builder.Generate (OcspRespStatus.Successful, basic_ocsp_resp);
			}catch (OcspMalformedRequestException e){
				Console.WriteLine (e.Message);
				return new OCSPRespGenerator ().Generate (OcspRespStatus.MalformedRequest, null);
			}catch (OcspUnrecognizedIssuerException e){
				Console.WriteLine (e.Message);
				return new OCSPRespGenerator ().Generate (OcspRespStatus.Unauthorized, null);
			}
		}
		public static byte[] SendOcspResponse(HttpListenerRequest http_request)
		{
			OcspReq ocsp_req = GetRequestFromHttp(http_request);
			OcspResp ocsp_resp = CreateResponseForRequest(ocsp_req);
			return ocsp_resp.GetEncoded ();
		}
        static void Main(string[] args)
        {
			Console.WriteLine ("SharpOCSP v0.1 OCSP responder by Vyronas Tsingaras firing up!");
			config = new Configuration("config.xml");
			//String ca_name = config.getConfigValue("ca_name");
			ca_list = new CA[1];
			CA testCA = CA.CAFactoryMethod ("TestCA", "/home/vtsingaras/AuthCentralCAR4.pem", 
				new SoftToken ("TestToken", "/home/vtsingaras/ocsp.AuthCentralCAR4.crt.pem", "/home/vtsingaras/ocsp.AuthCentralCAR4.key.pem"),"/home/vtsingaras/AuthCentralCAR4.crl.pem", "/home/vtsingaras/AuthCentralCAR4.index.txt", false);
			ca_list[0] = testCA;
			//Listen for HTTP requests
			HttpHandler http_handler = new HttpHandler (SendOcspResponse, "http://127.0.0.1:8080/");
			http_handler.Run ();
			Console.WriteLine ("Listening for connections...");
			Console.ReadKey ();
			http_handler.Stop ();
        }
    }
}
