using System;
using System.Net;
using System.Threading;
using System.Text;

namespace BouncyOCSP
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
					Console.WriteLine("Webserver running...");
					try
					{
						while (_listener.IsListening)
						{
							ThreadPool.QueueUserWorkItem((c) =>
								{
									var ctx = c as HttpListenerContext;
									try
									{
										byte[] buf = _responderMethod(ctx.Request);
										ctx.Response.AppendHeader("Content-Type", "application/ocsp-response");
										ctx.Response.ContentLength64 = buf.Length;
										ctx.Response.OutputStream.Write(buf, 0, buf.Length);
									}
									catch { } // suppress any exceptions
									finally
									{
										// always close the stream
										ctx.Response.OutputStream.Close();
									}
								}, _listener.GetContext());
						}
					}
					catch { } // suppress any exceptions
				});
		}

		public void Stop()
		{
			_listener.Stop();
			_listener.Close();
		}
	}
}