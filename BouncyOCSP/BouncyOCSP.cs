using System;
using System.Net;

namespace BouncyOCSP
{
    class BouncyOCSP
    {
		static CA[] ca_list;
		public static CA GetIssuingCaForCertificateId(Org.BouncyCastle.Ocsp.OcspReq ocsp_req)
		{
			cert_id = ocsp_req.GetRequestList () [0].GetCertID ();
			foreach (CA issuing_ca in ca_list)
			{
				if ( cert_id.MatchesIssuer(issuing_ca.caCertificate))
					return issuing_ca;
			}
			throw new Org.BouncyCastle.Ocsp.OcspException("Received request for unknown CA.");
		}
		public static byte[] SendOcspResponse(HttpListenerRequest http_request)
		{
			//TODO check if MIME type is ocsp request
			Console.WriteLine (http_request.Headers["Content-Type"]);
			Org.BouncyCastle.Ocsp.OcspReq ocsp_req = new Org.BouncyCastle.Ocsp.OcspReq (http_request.InputStream);
			Org.BouncyCastle.Ocsp.CertificateID cert_id;
			CA issuer;
			issuer = GetIssuerForRequest(ocsp_req);
			Console.WriteLine ("Got request for serial: " + ocsp_req.GetRequestList () [0].GetCertID ().SerialNumber.ToString()
				+ " for CA: " + issuer.ToString());

			foreach (Org.BouncyCastle.Ocsp.Req single_req in ocsp_req.GetRequestList()) {
				cert_id = single_req.GetCertID ();
				//check for ca compromise
				if(issuer.caCompromised == true)

			}
			//Always return good for now
			Org.BouncyCastle.Ocsp.BasicOcspRespGenerator basic_ocsp_resp_builder = 
				new Org.BouncyCastle.Ocsp.BasicOcspRespGenerator (issuer.caToken.GetPublicKey ());
			basic_ocsp_resp_builder.AddResponse (cert_id, Org.BouncyCastle.Ocsp.CertificateStatus.Good);
			Org.BouncyCastle.Ocsp.BasicOcspResp basic_ocsp_resp = basic_ocsp_resp_builder.Generate ("SHA1withRSA", issuer.caToken.GetPrivateKey (), new[]{issuer.caCertificate, issuer.caToken.GetOcspSigningCert ()}, DateTime.Now);
			Org.BouncyCastle.Ocsp.OCSPRespGenerator ocsp_resp_builder = new Org.BouncyCastle.Ocsp.OCSPRespGenerator ();
			return ocsp_resp_builder.Generate (Org.BouncyCastle.Ocsp.OcscpRespStatus.Successful, basic_ocsp_resp).GetEncoded();
		}
        static void Main(string[] args)
        {
			Configuration config = new Configuration("config.xml");
			//String ca_name = config.getConfigValue("ca_name");
			ca_list = new CA[1];
			CA testCA = new CA ("TestCA", "/home/vtsingaras/AuthCentralCAR4.pem", 
				new SoftToken ("TestToken", "/home/vtsingaras/ocsp.AuthCentralCAR4.crt.pem", "/home/vtsingaras/ocsp.AuthCentralCAR4.key.pem"),"~/crl", "/home/vtsingaras/index.txt", 50, false);
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
