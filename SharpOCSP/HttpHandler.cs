using System;
using System.Net;
using System.Threading;
using System.Text;
using System.IO;

namespace SharpOCSP
{
	public class HttpHandler
	{
		private readonly HttpListener _listener = new HttpListener();
		private readonly Func<HttpListenerRequest, byte[]> _responderMethod;

		public HttpHandler(string[] prefixes, Func<HttpListenerRequest, byte[]> method)
		{
			// URI prefixes are required, for example 
			// "http://localhost:8080/index/".
			if (prefixes == null || prefixes.Length == 0)
				throw new ArgumentException("prefixes");

			// A responder method is required
			if (method == null)
				throw new ArgumentException("method");

			foreach (string s in prefixes)
				_listener.Prefixes.Add(s);

			_responderMethod = method;
			_listener.Start();
		}

		public HttpHandler(Func<HttpListenerRequest, byte[]> method, params string[] prefixes)
			: this(prefixes, method) { }

		public void Run()
		{
			ThreadPool.QueueUserWorkItem((o) =>
				{
					Console.WriteLine("HTTP handler running...");
					try
					{
						while (_listener.IsListening)
						{
							ThreadPool.QueueUserWorkItem((c) =>
								{
									var ctx = c as HttpListenerContext;
									byte[] buf = _responderMethod(ctx.Request);
									ctx.Response.AppendHeader("Content-Type", "application/ocsp-response");
									ctx.Response.ContentLength64 = buf.Length;
									ctx.Response.OutputStream.Write(buf, 0, buf.Length);
									ctx.Response.OutputStream.Close();
								}, _listener.GetContext());
						}
					}
					//TODO: implement proper exception handling
					catch (HttpListenerException e ){
						Console.WriteLine("Error handling http." + e.Message);
					}
					catch (System.ObjectDisposedException e){
						SharpOCSP.log.Warn("Remote endpoint closed the connection.", e);
					}
				});
		}

		public void Stop()
		{
			_listener.Stop();
			_listener.Close();
		}
	}
}